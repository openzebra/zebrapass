//! Open a vault file into a [`Session`](crate::Session).

use aead::{decrypt_body, BodyAlg};
use container::{ChipWrap, PrfWrap, VaultFile, WrapEntry};
use kdf::derive_vault_keys;
use secret::Secret;
use wraps::{open_chip, open_device, open_password, open_prf, ChipKeys, DeviceKeys};
use zeroize::Zeroize;

use crate::create::{body_ad, verify_commit, Session};
use crate::error::Seen;

/// Factors a caller can present for one unlock.
///
/// Every field is optional and independent: [`unlock`] picks the first factor
/// that is present both here and in the file, in the order chip → PRF →
/// device → password. A factor listed here but absent from the file is an
/// error, not a silent fallback.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnlockCreds<'a> {
    /// The vault password.
    pub password: Option<&'a str>,
    /// This phone's device wrap keys.
    pub device: Option<&'a DeviceKeys>,
    /// This phone's chip keys and the P-256 shared secret the platform
    /// computes as `ECDH(chip_sk, wrap.eph_pub)`.
    pub chip: Option<(&'a ChipKeys, [u8; 32])>,
    /// A PRF grant id and the 32-byte hmac-secret output for it.
    pub prf: Option<([u8; 16], [u8; 32])>,
}

impl<'a> UnlockCreds<'a> {
    /// Password-only credentials.
    #[must_use]
    pub const fn password(pw: &'a str) -> Self {
        Self {
            password: Some(pw),
            device: None,
            chip: None,
            prf: None,
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

    /// Present a PRF output with its grant id.
    #[must_use]
    pub const fn with_prf(mut self, id: [u8; 16], prf_out: [u8; 32]) -> Self {
        self.prf = Some((id, prf_out));
        self
    }
}

/// Open `file` with the factors in `creds`.
///
/// Attempts go chip → PRF → device → password: the first factor present in
/// `creds` is tried against its wrap. The body is decrypted only after the
/// commit matches. The plaintext is wiped and not stored on the session.
///
/// # Errors
///
/// Parse failures surface as `anyhow` errors with stable messages.
/// `no chip wrap for this device` when the chip factor is present but the
/// file has no chip wrap with that id; `no prf wrap for this credential`
/// analogously for the PRF factor; `wrap not found` for a missing device or
/// password wrap.
/// `wrap authentication failed` when the wrap tag does not match.
/// `commit mismatch` when the HMAC over every byte except the
/// last 32 does not match. This is returned before the body is decrypted.
/// `body authentication failed` when the body tag does not match.
/// `rollback` when `seen` is newer than the file.
/// `conflict` when the generation matches `seen` but the commit tag does not.
/// `empty password` when the password factor is chosen and it is empty.
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
    decrypt_and_wipe(
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
    if let Some((id, prf_out)) = creds.prf {
        let wrap = find_prf(entries, &id)?;
        return open_prf(header, wrap, &prf_out);
    }
    if let Some(keys) = creds.device {
        let wrap = find_device(entries, &keys.id)?;
        return open_device(header, wrap, keys);
    }
    let Some(pw) = creds.password else {
        return Err(anyhow::anyhow!("no usable wrap"));
    };
    if pw.is_empty() {
        return Err(anyhow::anyhow!("empty password"));
    }
    let wrap = find_password(entries)?;
    open_password(header, &wrap, pw)
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

fn find_prf<'a>(
    entries: &'a [WrapEntry<'a>],
    id: &[u8; 16],
) -> anyhow::Result<&'a PrfWrap<'a>> {
    for entry in entries {
        if let WrapEntry::Prf(wrap) = entry {
            if wrap.id == *id {
                return Ok(wrap);
            }
        }
    }
    Err(anyhow::anyhow!("no prf wrap for this credential"))
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

fn decrypt_and_wipe(
    alg: BodyAlg,
    k_body: &[u8; 32],
    k_bmac: &[u8; 32],
    header: &container::StaticHeader,
    body: &[u8],
) -> anyhow::Result<()> {
    let ad = body_ad(header);
    // Authenticate the body, then wipe it. The session does not store records.
    #[allow(
        clippy::collection_is_never_read,
        reason = "the plaintext is wiped after the tag check and is not returned"
    )]
    let mut plaintext = decrypt_body(alg, k_body, k_bmac, body, &ad)?;
    plaintext.zeroize();
    Ok(())
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
