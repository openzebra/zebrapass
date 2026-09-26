//! Master change, record rewrite, and vault-key rotation.

use aead::BodyAlg;
use container::{KIND_CHIP, KIND_DEVICE, KIND_PRF, VaultFile, WrapEntry};
use frame::encode_frames;
use secret::Secret;
use wraps::{seal_prf, ChipPublics, DevicePublics, PrfPublics};

use crate::create::{
    encrypt_records, fold_log, fold_new_spans, next_generation, publish, Session,
};
use crate::error::SessionError;
use crate::wraps_rot::{replace_password, rotate_all};
use crate::rewrap::rewrap;

/// Replace the master wrap: re-seal the same vault key under a new master
/// seed.
///
/// The new record has a new kid and nonce and seals the same vault key.
/// Header and body bytes stay as they are. Generation increases by one.
/// On error, `file` and `session` are left as they were.
///
/// # Errors
///
/// `wrap not found` when the file has no master wrap.
pub fn change_master(
    session: &mut Session,
    file: &mut VaultFile,
    new_master: &[u8; 64],
    prfs: &[(PrfPublics, [u8; 32])],
) -> anyhow::Result<()> {
    rewrap(session, file, |parsed, vk| {
        for entry in &parsed.entries {
            if let WrapEntry::Prf(wrap) = entry {
                if !prfs.iter().any(|(item, _)| item.id == wrap.id) {
                    return Err(SessionError::PrfFactorRequired.into());
                }
            }
        }
        let kept: Vec<WrapEntry<'_>> = parsed
            .entries
            .iter()
            .copied()
            .filter(|entry| entry.kind() != KIND_PRF)
            .collect();
        let mut records = replace_password(&kept, &parsed.header, new_master, vk)?;
        for entry in &parsed.entries {
            if let WrapEntry::Prf(wrap) = entry {
                if let Some((publics, prf_out)) =
                    prfs.iter().find(|(item, _)| item.id == wrap.id)
                {
                    let (record, _grant) = seal_prf(&parsed.header, publics, prf_out, vk)?;
                    records.push(record);
                }
            }
        }
        Ok((records, ()))
    })
}

/// Append `records` to the vault log and republish the file.
///
/// `records` holds new sealed frames (`Frames`) or new plaintext record
/// bytes (whole-body modes); the previous log always survives. Wrap
/// records are copied unchanged. Generation increases by one. On error,
/// `file` and `session` are left as they were.
///
/// # Errors
///
/// `unsupported body algorithm` when the session body algorithm is
/// Kuznyechik-MGM. `corrupted length` when the log does not parse as
/// whole frames or the OS RNG fails.
pub fn write_records(
    session: &mut Session,
    file: &mut VaultFile,
    records: &[u8],
) -> anyhow::Result<()> {
    let (header, generation, kept, body, raw) = {
        let parsed = file.parse()?;
        let kept = crate::create::owned_entries(&parsed.entries)?;
        let existing_len = session.records.expose().len();
        let mut raw = Vec::with_capacity(existing_len + records.len());
        raw.extend_from_slice(session.records.expose());
        raw.extend_from_slice(records);
        let body = match session.body_alg {
            BodyAlg::Frames => {
                session.frames_digest =
                    fold_new_spans(session.frames_digest, existing_len, &raw)?;
                encode_frames(&raw)?
            }
            alg => encrypt_records(
                alg,
                &parsed.header,
                session.k_body.expose(),
                session.k_bmac.expose(),
                &raw,
            )?,
        };
        let generation = next_generation(parsed.generation)?;
        (parsed.header, generation, kept, body, raw)
    };
    publish(session, file, &header, &kept, &body, generation)?;
    session.records = Secret::new(raw);
    Ok(())
}

/// Replace the raw frame log wholesale (history compaction).
///
/// `Frames` bodies keep the sealed frames as-is — only the folded commit
/// changes, so no re-encryption happens. Whole-body modes re-encrypt through
/// the existing pipeline. On success the session's raw log is `records`.
///
/// # Errors
///
/// `corrupted length` when `records` is not a whole number of frames;
/// publish errors as in [`write_records`].
pub fn rewrite_body(
    session: &mut Session,
    file: &mut VaultFile,
    records: &[u8],
) -> anyhow::Result<()> {
    let body = match session.body_alg {
        BodyAlg::Frames => {
            session.frames_digest = fold_log(records)?;
            encode_frames(records)?
        }
        alg => encrypt_records(
            alg,
            &file.parse()?.header,
            session.k_body.expose(),
            session.k_bmac.expose(),
            records,
        )?,
    };
    let (header, generation, kept) = {
        let parsed = file.parse()?;
        let kept = crate::create::owned_entries(&parsed.entries)?;
        let generation = next_generation(parsed.generation)?;
        (parsed.header, generation, kept)
    };
    publish(session, file, &header, &kept, &body, generation)?;
    session.records = Secret::new(records.to_vec());
    Ok(())
}

/// Rotate the vault key, keeping the record log as it is.
///
/// Old wrap ciphertexts are not reused: they seal the previous vault key.
/// A file wrap id with no matching entry in `creds.devices` or `creds.chips`
/// is `wrap not found` and does not modify `file` or `session`. A PRF wrap
/// without a matching output in `creds.prfs` is `prf factor required`, and a
/// human password wrap without `creds.human_password` is
/// `human factor required`. Sealing a chip
/// wrap draws a fresh ephemeral P-256 key in this process, so the platform
/// must re-derive its shared secret against the new ephemeral public key
/// after the call. On success every record survives the rotation. The log
/// rewrite and the key rotation are two publishes; each is fail-atomic.
///
/// # Errors
///
/// `corrupted length` when the stored log does not parse as whole frames;
/// `wrap not found` when a device or chip wrap has no matching public id.
/// `prf factor required` when a PRF wrap has no matching output.
/// `human factor required` when a human wrap has no password.
/// `zero shared secret` when a device X25519 public key is zero.
pub fn reencrypt_body(
    session: &mut Session,
    file: &mut VaultFile,
    master: &[u8; 64],
    devices: &[DevicePublics],
    chips: &[(ChipPublics, [u8; 32])],
    prfs: &[(PrfPublics, [u8; 32])],
) -> anyhow::Result<()> {
    let log = session.records.expose().clone();
    rewrite_body(session, file, &log)?;
    rotate_all(
        session,
        file,
        &RotateCreds {
            master,
            human_password: None,
            devices,
            chips,
            prfs,
        },
        None,
    )
}

/// Secret material the remaining wraps are re-sealed from: the recovery
/// passphrase and the live outputs of every kept human factor.
///
/// Device and chip wraps are sealed to public keys, so revoking one of them
/// needs no secret from the revoked device.
#[derive(Clone, Copy, Debug)]
pub struct RotateCreds<'a> {
    /// Seals the password (recovery) wrap.
    pub master: &'a [u8; 64],
    /// Public keys of every kept device wrap.
    pub devices: &'a [DevicePublics],
    /// Platform public key plus its P-256 shared secret, per kept chip wrap.
    pub chips: &'a [(ChipPublics, [u8; 32])],
    /// hmac-secret output, per kept PRF wrap.
    pub prfs: &'a [(PrfPublics, [u8; 32])],
    /// The human password, needed only when a human password wrap must be
    /// re-sealed. `None` is fine for vaults without one.
    pub human_password: Option<&'a [u8]>,
}

/// The wrap a revocation removes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Revoke<'a> {
    /// The device wrap with this id.
    Device(&'a [u8; 16]),
    /// The chip wrap with this id.
    Chip(&'a [u8; 16]),
    /// The PRF wrap with this id.
    Prf(&'a [u8; 16]),
}

/// Revoke an unlock factor: drop its wrap and rotate the vault key under
/// every remaining one.
///
/// A revoked device keeps its wrap ciphertext and everything it ever
/// decrypted, so dropping the wrap alone proves nothing. The vault key is
/// drawn fresh and the body is re-encrypted, so old key material cannot read
/// records written after this call. Every remaining wrap needs matching
/// material in `creds`; device and chip wraps need only their public keys.
/// The session's decrypted frame body becomes empty. On error, `file` and
/// `session` are left as they were.
///
/// # Errors
///
/// `wrap not found` when no wrap of the target kind has the id, or a
/// remaining device or chip wrap has no matching public id in `creds`.
/// `prf factor required` when a remaining PRF wrap has no matching output.
/// `human factor required` when a remaining human wrap has no password in
/// `creds`.
/// `zero shared secret` when a remaining device public key is zero.
pub fn revoke(
    session: &mut Session,
    file: &mut VaultFile,
    target: &Revoke<'_>,
    creds: &RotateCreds<'_>,
) -> anyhow::Result<()> {
    match target {
        Revoke::Device(id) => rotate_all(session, file, creds, Some((KIND_DEVICE, **id))),
        Revoke::Chip(id) => rotate_all(session, file, creds, Some((KIND_CHIP, **id))),
        Revoke::Prf(id) => rotate_all(session, file, creds, Some((KIND_PRF, **id))),
    }
}

