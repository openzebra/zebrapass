//! Open a vault file into a [`Session`](crate::Session).

use aead::{decrypt_body, BodyAlg};
use container::{VaultFile, WrapEntry};
use kdf::derive_vault_keys;
use secret::Secret;
use wraps::{open_device, open_password, DeviceKeys};
use zeroize::Zeroize;

use crate::create::{body_ad, verify_commit, Session};
use crate::error::{Seen, VaultV2Error};

/// Open `file` with a password or with device keys.
///
/// Device keys, when present, select that device wrap. Otherwise the single
/// password wrap is opened. The body is decrypted only after the commit matches.
/// The plaintext is wiped and not stored on the session.
///
/// # Errors
///
/// Parse errors use the same names as [`container::FormatError`].
/// [`VaultV2Error::WrapNotFound`] when the device id or the password wrap is missing.
/// [`VaultV2Error::WrapAuthFailed`] when the wrap tag does not match.
/// [`VaultV2Error::CommitMismatch`] when the HMAC over every byte except the
/// last 32 does not match. This is returned before the body is decrypted.
/// [`VaultV2Error::BodyAuthFailed`] when the body tag does not match.
/// [`VaultV2Error::Rollback`] when `seen` is newer than the file.
/// [`VaultV2Error::Conflict`] when the generation matches `seen` but the commit tag does not.
/// [`VaultV2Error::EmptyPassword`] when no device is given and `pw` is empty.
pub fn unlock(
    file: &VaultFile,
    pw: &str,
    dev: Option<&DeviceKeys>,
    seen: Option<Seen>,
) -> Result<Session, VaultV2Error> {
    let parsed = file.parse()?;
    let vk = unwrap_vk(&parsed.header, &parsed.entries, pw, dev)?;
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
    pw: &str,
    dev: Option<&DeviceKeys>,
) -> Result<Secret<[u8; 32]>, VaultV2Error> {
    if let Some(keys) = dev {
        let wrap = find_device(entries, &keys.id)?;
        return open_device(header, wrap, keys).map_err(Into::into);
    }
    let wrap = find_password(entries)?;
    open_password(header, &wrap, pw).map_err(Into::into)
}

fn find_password<'a>(
    entries: &'a [WrapEntry<'a>],
) -> Result<container::PasswordWrap<'a>, VaultV2Error> {
    for entry in entries {
        if let WrapEntry::Password(wrap) = entry {
            return Ok(*wrap);
        }
    }
    Err(VaultV2Error::WrapNotFound)
}

fn find_device<'a>(
    entries: &'a [WrapEntry<'a>],
    device_id: &[u8; 16],
) -> Result<&'a container::DeviceWrap<'a>, VaultV2Error> {
    for entry in entries {
        if let WrapEntry::Device(wrap) = entry {
            if wrap.device_id == *device_id {
                return Ok(wrap);
            }
        }
    }
    Err(VaultV2Error::WrapNotFound)
}

fn decrypt_and_wipe(
    alg: BodyAlg,
    k_body: &[u8; 32],
    k_bmac: &[u8; 32],
    header: &container::StaticHeader,
    body: &[u8],
) -> Result<(), VaultV2Error> {
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
) -> Result<(), VaultV2Error> {
    let Some(seen) = seen else {
        return Ok(());
    };
    if generation < seen.generation {
        return Err(VaultV2Error::Rollback);
    }
    if generation == seen.generation && !secret::ct_eq_32(commit_tag, &seen.commit_tag) {
        return Err(VaultV2Error::Conflict);
    }
    Ok(())
}
