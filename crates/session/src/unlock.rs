//! Open a vault file into a [`Session`](crate::Session).

use aead::BodyAlg;
use container::{ChipWrap, VaultFile, WrapEntry};
use kdf::derive_vault_keys;
use secret::Secret;
use wraps::{open_chip, open_device, open_password, ChipKeys, DeviceKeys};

use crate::create::{body_ad, draw_device_id, verify_commit, Session};
use crate::error::Seen;

/// Factors a caller can present for one unlock.
///
/// Every field is optional and independent: [`unlock`] picks the first factor
/// that is present both here and in the file, in the order chip → device →
/// master. A factor listed here but absent from the file is an error, not
/// a silent fallback.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnlockCreds<'a> {
    /// The 64-byte master seed (the BIP39 seed of the seed phrase).
    pub master: Option<&'a [u8; 64]>,
    /// This phone's device wrap keys.
    pub device: Option<&'a DeviceKeys>,
    /// This phone's chip keys and the P-256 shared secret the platform
    /// computes as `ECDH(chip_sk, wrap.eph_pub)`.
    pub chip: Option<(&'a ChipKeys, [u8; 32])>,
}

impl<'a> UnlockCreds<'a> {
    /// Master-seed-only credentials.
    #[must_use]
    pub const fn master(master: &'a [u8; 64]) -> Self {
        Self {
            master: Some(master),
            device: None,
            chip: None,
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

    // !todo!: PRF factor (YubiKey) removed — restore `pub prf` +
    // `with_prf` together with the `platform::PrfBackend` trait.
}

/// Open `file` with the factors in `creds`.
///
/// Attempts go chip → device → master: the first factor present in
/// `creds` is tried against its wrap. The body is decrypted once after the
/// commit matches and its plaintext stays on the session: single frames
/// are opened from it on demand with their per-record key.
///
/// # Errors
///
/// Parse failures surface as `anyhow` errors with stable messages.
/// `no chip wrap for this device` when the chip factor is present but the
/// file has no chip wrap with that id; `wrap not found` for a missing device
/// or master wrap.
/// `wrap authentication failed` when the wrap tag does not match.
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
    let vk = unwrap_vk(&parsed.header, &parsed.entries, creds)?;
    let (k_body, k_bmac, k_commit) = derive_vault_keys(vk.expose(), &parsed.header.vault_id)?;
    // A flipped body byte must surface as CommitMismatch, not BodyAuthFailed.
    verify_commit(file.as_bytes(), k_commit.expose(), &parsed.commit)?;
    let body_alg = BodyAlg::try_from(parsed.header.body_alg)?;
    let records = decrypt_body(
        body_alg,
        k_body.expose(),
        k_bmac.expose(),
        &parsed.header,
        parsed.body,
    )?;
    // An older blob is still cryptographically valid. `seen` rejects it after auth.
    accept_seen(seen, parsed.generation, &parsed.commit)?;
    let device_id = draw_device_id()?;
    Ok(Session {
        vk,
        k_body,
        k_bmac,
        k_commit,
        body_alg,
        generation: parsed.generation,
        commit_tag: parsed.commit,
        vault_id: parsed.header.vault_id,
        device_id,
        records,
    })
}

fn unwrap_vk(
    header: &container::StaticHeader,
    entries: &[WrapEntry<'_>],
    creds: &UnlockCreds<'_>,
) -> anyhow::Result<Secret<[u8; 32]>> {
    if let Some((keys, ss_p256)) = creds.chip {
        let wrap = find_chip(entries, &keys.id)?;
        return open_chip(header, wrap, keys, &ss_p256);
    }
    // !todo!: PRF factor (YubiKey) removed — restore here between chip and
    // device, together with `UnlockCreds::prf` and `find_prf`.
    if let Some(keys) = creds.device {
        let wrap = find_device(entries, &keys.id)?;
        return open_device(header, wrap, keys);
    }
    let Some(master) = creds.master else {
        return Err(anyhow::anyhow!("no usable wrap"));
    };
    let wrap = find_password(entries)?;
    open_password(header, &wrap, master)
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
    let ad = body_ad(header);
    Ok(Secret::new(aead::decrypt_body(
        alg, k_body, k_bmac, body, &ad,
    )?))
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
        return Err(anyhow::anyhow!("rollback"));
    }
    if generation == seen.generation && !secret::ct_eq_32(commit_tag, &seen.commit_tag) {
        return Err(anyhow::anyhow!("conflict"));
    }
    Ok(())
}
