//! Open a vault file into a [`Session`](crate::Session).

use aead::BodyAlg;
use container::{ChipWrap, VaultFile, WrapEntry, COMMIT_LEN};
use frame::decode_frames;
use kdf::derive_vault_keys;
use secret::Secret;
use wraps::{
    open_chip, open_device, open_human_password, open_password, open_prf, ChipKeys, DeviceKeys,
    PrfPublics,
};

use crate::create::{body_ad, body_digest, commit_mode, mac_commit, verify_commit, CommitMode, Session};
use crate::error::{Seen, SessionError};

/// Factors a caller can present for one unlock.
///
/// Every field is optional and independent: [`unlock`] picks the first factor
/// that is present both here and in the file, in the order chip → prf →
/// device → master. A factor listed here but absent from the file is an
/// error, not a silent fallback.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnlockCreds<'a> {
    /// The 64-byte master seed (the BIP39 seed of the seed phrase).
    pub master: Option<&'a [u8; 64]>,
    /// This phone's device wrap keys.
    pub device: Option<&'a DeviceKeys>,
    /// This phone's chip keys and the P-256 shared secret the platform
    /// computes as `ECDH(chip_sk, wrap.eph_pub)`.
    pub chip: Option<(&'a ChipKeys, [u8; 32])>,
    /// A hardware key's publics and the 32-byte hmac-secret response the
    /// platform asks it to compute over the wrap's salt.
    pub prf: Option<(&'a PrfPublics, &'a [u8; 32])>,
    /// A human-chosen password (kind `0x0005` wrap).
    pub human: Option<&'a [u8]>,
}

impl<'a> UnlockCreds<'a> {
    /// Master-seed-only credentials.
    #[must_use]
    pub const fn master(master: &'a [u8; 64]) -> Self {
        Self {
            master: Some(master),
            device: None,
            chip: None,
            prf: None,
            human: None,
        }
    }

    /// Present device keys as an additional factor.
    #[must_use]
    pub const fn with_device(mut self, keys: &'a DeviceKeys) -> Self {
        self.device = Some(keys);
        self
    }

    /// Present chip keys with the platform shared secret.
    #[must_use]
    pub const fn with_chip(mut self, keys: &'a ChipKeys, ss_p256: [u8; 32]) -> Self {
        self.chip = Some((keys, ss_p256));
        self
    }

    /// Present a hardware key's publics and its hmac-secret response.
    #[must_use]
    pub const fn with_prf(mut self, publics: &'a PrfPublics, prf_out: &'a [u8; 32]) -> Self {
        self.prf = Some((publics, prf_out));
        self
    }

    /// Present a human-chosen password (kind `0x0005` wrap).
    #[must_use]
    pub const fn with_human(mut self, password: &'a [u8]) -> Self {
        self.human = Some(password);
        self
    }
}

/// Open `file` with the factors in `creds`.
///
/// Attempts go chip → prf → device → human password → master: the first
/// factor present in `creds` is tried against its wrap. The body is decrypted once after the
/// commit matches and its plaintext stays on the session: single frames
/// are opened from it on demand with their per-record key.
///
/// # Errors
///
/// Parse failures surface as `anyhow` errors with stable messages.
/// `no chip wrap for this device` when the chip factor is present but the
/// file has no chip wrap with that id; `wrap not found` for a missing device
/// or master wrap.
/// `wrap authentication failed` when the wrap tag does not match (wrong
/// password included).
/// `commit mismatch` when the HMAC over every byte except the
/// last 32 does not match. This is returned before the body is decrypted.
/// `body authentication failed` when the body tag does not match.
/// `rollback` when `seen` is newer than the file.
/// `conflict` when the generation matches `seen` but the commit tag does not.
/// `no usable wrap` when `creds` carries no factor at all.
pub fn unlock(
    file: &VaultFile,
    creds: &UnlockCreds<'_>,
    seen: Option<Seen>,
) -> anyhow::Result<Session> {
    let parsed = file.parse()?;
    let (vk, wrap_device) = unwrap_vk(&parsed.header, &parsed.entries, creds)?;
    let origin_device = match wrap_device {
        Some(id) => id,
        None => crate::create::fresh_device_id()?,
    };
    let (k_body, k_bmac, k_commit) = derive_vault_keys(vk.expose(), &parsed.header.vault_id)?;
    // A flipped body byte must surface as CommitMismatch, not BodyAuthFailed.
    // For `Frames` bodies the tag covers the fold digest, not the raw bytes,
    // so the check is mode-aware (a raw flip changes the digest, so it still
    // surfaces as CommitMismatch).
    let body_alg = BodyAlg::try_from(parsed.header.body_alg)?;
    let frames_digest = match commit_mode(body_alg) {
        CommitMode::Whole => [0u8; 32],
        CommitMode::Folded => body_digest(parsed.body)?,
    };
    match commit_mode(body_alg) {
        CommitMode::Whole => {
            verify_commit(file.as_bytes(), k_commit.expose(), &parsed.commit)?;
        }
        CommitMode::Folded => {
            let prefix_end = file.as_bytes().len() - parsed.body.len() - COMMIT_LEN;
            let prefix = file
                .as_bytes()
                .get(..prefix_end)
                .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
            let expected = mac_commit(k_commit.expose(), &[prefix, &frames_digest])?;
            if !secret::ct_eq_32(&expected, &parsed.commit) {
                return Err(SessionError::CommitMismatch.into());
            }
        }
    }
    let records = decrypt_body(
        body_alg,
        k_body.expose(),
        k_bmac.expose(),
        &parsed.header,
        parsed.body,
    )?;
    // An older blob is still cryptographically valid. `seen` rejects it after auth.
    accept_seen(seen, parsed.generation, &parsed.commit)?;
    Ok(Session {
        vk,
        k_body,
        k_bmac,
        k_commit,
        body_alg,
        generation: parsed.generation,
        commit_tag: parsed.commit,
        vault_id: parsed.header.vault_id,
        origin_device,
        records,
        frames_digest,
    })
}

/// The vault key plus the device wrap id that produced it.
type UnwrappedKey = (Secret<[u8; 32]>, Option<[u8; 16]>);

fn unwrap_vk(
    header: &container::StaticHeader,
    entries: &[WrapEntry<'_>],
    creds: &UnlockCreds<'_>,
) -> anyhow::Result<UnwrappedKey> {
    if let Some((keys, ss_p256)) = creds.chip {
        let wrap = find_chip(entries, &keys.id)?;
        return open_chip(header, wrap, keys, &ss_p256).map(|vk| (vk, Some(wrap.id)));
    }
    if let Some((publics, prf_out)) = creds.prf {
        let wrap = wraps::find_prf(entries, &publics.id)?;
        return open_prf(header, &wrap, prf_out).map(|vk| (vk, Some(wrap.id)));
    }
    if let Some(keys) = creds.device {
        let wrap = find_device(entries, &keys.id)?;
        return open_device(header, wrap, keys).map(|vk| (vk, Some(keys.id)));
    }
    if let Some(human) = creds.human {
        let wrap = find_human_password(entries)?;
        // The human wrap carries no device id; the origin stays `None`.
        return open_human_password(header, &wrap, human).map(|vk| (vk, None));
    }
    let Some(master) = creds.master else {
        if entries
            .iter()
            .any(|entry| matches!(entry, WrapEntry::Prf(_)))
        {
            return Err(SessionError::PrfFactorRequired.into());
        }
        return Err(SessionError::NoUsableWrap.into());
    };
    let wrap = find_password(entries)?;
    // The recovery wrap does not identify a device.
    open_password(header, &wrap, master).map(|vk| (vk, None))
}

fn find_chip<'a>(
    entries: &'a [WrapEntry<'a>],
    id: &[u8; 16],
) -> anyhow::Result<&'a ChipWrap<'a>> {
    for entry in entries {
        if let WrapEntry::Chip(wrap) = entry {
            if wrap.id == *id {
                return Ok(wrap);
            }
        }
    }
    Err(anyhow::anyhow!("no chip wrap for this device"))
}

fn find_password<'a>(
    entries: &'a [WrapEntry<'a>],
) -> anyhow::Result<container::PasswordWrap<'a>> {
    for entry in entries {
        if let WrapEntry::Password(wrap) = entry {
            return Ok(*wrap);
        }
    }
    Err(anyhow::anyhow!("wrap not found"))
}

fn find_human_password<'a>(
    entries: &'a [WrapEntry<'a>],
) -> anyhow::Result<container::HumanPasswordWrap<'a>> {
    for entry in entries {
        if let WrapEntry::HumanPassword(wrap) = entry {
            return Ok(*wrap);
        }
    }
    Err(anyhow::anyhow!("wrap not found"))
}

fn find_device<'a>(
    entries: &'a [WrapEntry<'a>],
    device_id: &[u8; 16],
) -> anyhow::Result<&'a container::DeviceWrap<'a>> {
    for entry in entries {
        if let WrapEntry::Device(wrap) = entry {
            if wrap.device_id == *device_id {
                return Ok(wrap);
            }
        }
    }
    Err(anyhow::anyhow!("wrap not found"))
}

/// Decrypt the frame body. The plaintext stays on the session; the file's
/// integrity is already established by the commit and the body tag.
///
/// # Errors
///
/// `body authentication failed` when the body tag does not match.
/// `unsupported body algorithm` when the header names a body algorithm
/// this build cannot open.
fn decrypt_body(
    alg: BodyAlg,
    k_body: &[u8; 32],
    k_bmac: &[u8; 32],
    header: &container::StaticHeader,
    body: &[u8],
) -> anyhow::Result<Secret<Vec<u8>>> {
    match alg {
        BodyAlg::Frames => Ok(Secret::new(decode_frames(body)?)),
        alg => {
            let ad = body_ad(header);
            Ok(Secret::new(aead::decrypt_body(
                alg, k_body, k_bmac, body, &ad,
            )?))
        }
    }
}

fn accept_seen(
    seen: Option<Seen>,
    generation: u64,
    commit_tag: &[u8; 32],
) -> anyhow::Result<()> {
    let Some(seen) = seen else {
        return Ok(());
    };
    if generation < seen.generation {
        return Err(SessionError::Rollback.into());
    }
    if generation == seen.generation && !secret::ct_eq_32(commit_tag, &seen.commit_tag) {
        return Err(SessionError::Conflict.into());
    }
    Ok(())
}
