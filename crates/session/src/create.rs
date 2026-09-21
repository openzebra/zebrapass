//! Create a vault and the shared commit/body helpers.

use aead::{encrypt_body, BodyAlg};
use container::{
    assemble, encode_device_entry, encode_password_entry, encode_wrap_dir, StaticHeader, VaultFile,
    WrapEntry, BODY_AEGIS256, BODY_KUZ_CTR_HMAC, BODY_KUZ_MGM, COMMIT_LEN, DOMAIN_BODY,
    KDF_ARGON2ID, WRAP_AEGIS256,
};
use hmac::{Hmac, KeyInit, Mac};
use kdf::{derive_vault_keys, KdfProfile};
use secret::Secret;
use sha2::Sha256;
use wraps::seal_password;
use zeroize::Zeroize;

use crate::error::VaultV2Error;

type HmacSha256 = Hmac<Sha256>;

/// Open vault. The vault key and the three derived keys are wiped on drop.
///
/// `generation` and `commit_tag` track the file this session last wrote or opened.
#[derive(Debug)]
pub struct Session {
    pub(crate) vk: Secret<[u8; 32]>,
    pub(crate) k_body: Secret<[u8; 32]>,
    pub(crate) k_bmac: Secret<[u8; 32]>,
    pub(crate) k_commit: Secret<[u8; 32]>,
    pub(crate) body_alg: BodyAlg,
    pub(crate) generation: u64,
    pub(crate) commit_tag: [u8; 32],
}

impl Session {
    /// Directory generation of the file this session last wrote or opened.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Commit tag of that file.
    #[must_use]
    pub const fn commit_tag(&self) -> &[u8; 32] {
        &self.commit_tag
    }
}

/// Create a vault and the session that holds its keys.
///
/// Generation starts at 1. The file has one password wrap and a body that is
/// the AEAD of an empty record list. The commit is HMAC-SHA256 over
/// `header ‖ wrap directory ‖ body`.
///
/// # Errors
///
/// [`VaultV2Error::EmptyPassword`] when `pw` is empty, before any KDF.
/// [`VaultV2Error::UnsupportedBodyAlg`] for [`BodyAlg::KuzMgm`], before Argon2.
/// [`VaultV2Error::KdfParamsRejected`] when the profile parameters are rejected.
/// [`VaultV2Error::CorruptedLength`] when the OS RNG or HMAC constructor fails.
pub fn create(
    pw: &str,
    profile: KdfProfile,
    body_alg: BodyAlg,
) -> Result<(VaultFile, Session), VaultV2Error> {
    if pw.is_empty() {
        return Err(VaultV2Error::EmptyPassword);
    }
    // KuzMgm is a recognized id this build cannot seal. Reject it before Argon2.
    let body_id = body_alg_id(body_alg)?;
    let vk = draw_secret()?;
    let header = new_header(profile, body_id)?;
    let password = seal_password(&header, pw, vk.expose())?;
    let (k_body, k_bmac, k_commit) = derive_vault_keys(vk.expose(), &header.vault_id)?;
    let body = encrypt_records(body_alg, &header, k_body.expose(), k_bmac.expose(), &[])?;
    let records = [password];
    let wrap_dir = dir_bytes(1, &records)?;
    let (file, commit_tag) = assemble_committed(k_commit.expose(), &header, &wrap_dir, &body)?;
    Ok((
        file,
        Session {
            vk,
            k_body,
            k_bmac,
            k_commit,
            body_alg,
            generation: 1,
            commit_tag,
        },
    ))
}

const fn body_alg_id(alg: BodyAlg) -> Result<u16, VaultV2Error> {
    match alg {
        BodyAlg::Aegis256 => Ok(BODY_AEGIS256),
        BodyAlg::KuzCtrHmac => Ok(BODY_KUZ_CTR_HMAC),
        BodyAlg::KuzMgm => Err(VaultV2Error::UnsupportedBodyAlg(BODY_KUZ_MGM)),
    }
}

/// A wrapping generation would look like a rollback to a client that stored `Seen`.
pub const fn next_generation(generation: u64) -> Result<u64, VaultV2Error> {
    match generation.checked_add(1) {
        Some(next) => Ok(next),
        None => Err(VaultV2Error::CorruptedLength),
    }
}

pub fn encode_entry(entry: &WrapEntry<'_>) -> Vec<u8> {
    match entry {
        WrapEntry::Password(wrap) => {
            encode_password_entry(wrap.kid, wrap.nonce, wrap.ct, wrap.tag).to_vec()
        }
        WrapEntry::Device(wrap) => encode_device_entry(
            wrap.device_id,
            wrap.kem_alg,
            wrap.dev_x_pk,
            wrap.eph_x_pk,
            wrap.sntrup_ct,
            wrap.nonce,
            wrap.ct,
            wrap.tag,
        ),
    }
}

pub fn owned_entries(entries: &[WrapEntry<'_>]) -> Vec<Vec<u8>> {
    let mut records = Vec::with_capacity(entries.len());
    for entry in entries {
        records.push(encode_entry(entry));
    }
    records
}

pub fn dir_bytes(generation: u64, records: &[Vec<u8>]) -> Result<Vec<u8>, VaultV2Error> {
    let refs = records.iter().map(Vec::as_slice).collect::<Vec<_>>();
    encode_wrap_dir(generation, &refs).map_err(Into::into)
}

pub fn body_ad(header: &StaticHeader) -> Vec<u8> {
    let header_bytes = header.to_bytes();
    let mut ad = Vec::with_capacity(header_bytes.len() + DOMAIN_BODY.len());
    ad.extend_from_slice(&header_bytes);
    ad.extend_from_slice(DOMAIN_BODY);
    ad
}

pub fn encrypt_records(
    alg: BodyAlg,
    header: &StaticHeader,
    k_body: &[u8; 32],
    k_bmac: &[u8; 32],
    records: &[u8],
) -> Result<Vec<u8>, VaultV2Error> {
    let ad = body_ad(header);
    let nonce = fresh_nonce(alg)?;
    encrypt_body(alg, k_body, k_bmac, nonce.as_slice(), &ad, records).map_err(Into::into)
}

pub fn assemble_committed(
    k_commit: &[u8; 32],
    header: &StaticHeader,
    wrap_dir: &[u8],
    body: &[u8],
) -> Result<(VaultFile, [u8; 32]), VaultV2Error> {
    let header_bytes = header.to_bytes();
    let tag = mac_commit(k_commit, &[&header_bytes, wrap_dir, body])?;
    Ok((assemble(header, wrap_dir, body, &tag), tag))
}

/// Replace `file` and the session's generation only after the new bytes exist.
pub fn publish(
    session: &mut Session,
    file: &mut VaultFile,
    header: &StaticHeader,
    records: &[Vec<u8>],
    body: &[u8],
    generation: u64,
) -> Result<(), VaultV2Error> {
    let wrap_dir = dir_bytes(generation, records)?;
    let (updated, tag) = assemble_committed(session.k_commit.expose(), header, &wrap_dir, body)?;
    *file = updated;
    session.generation = generation;
    session.commit_tag = tag;
    Ok(())
}

fn mac_commit(key: &[u8; 32], parts: &[&[u8]]) -> Result<[u8; 32], VaultV2Error> {
    // A 32-byte key is a legal HMAC key. The constructor still returns `Result`.
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return Err(VaultV2Error::CorruptedLength);
    };
    for part in parts {
        mac.update(part);
    }
    let digest = mac.finalize().into_bytes();
    <[u8; 32]>::try_from(digest.as_slice()).map_err(|_| VaultV2Error::CorruptedLength)
}

pub fn verify_commit(
    bytes: &[u8],
    key: &[u8; 32],
    expected: &[u8; 32],
) -> Result<(), VaultV2Error> {
    let end = bytes
        .len()
        .checked_sub(COMMIT_LEN)
        .ok_or(VaultV2Error::CorruptedLength)?;
    let prefix = bytes.get(..end).ok_or(VaultV2Error::CorruptedLength)?;
    let actual = mac_commit(key, &[prefix])?;
    if secret::ct_eq_32(&actual, expected) {
        Ok(())
    } else {
        Err(VaultV2Error::CommitMismatch)
    }
}

pub fn draw_secret() -> Result<Secret<[u8; 32]>, VaultV2Error> {
    let mut raw = [0u8; 32];
    fill_random(&mut raw)?;
    let secret = Secret::new(raw);
    raw.zeroize();
    Ok(secret)
}

fn new_header(profile: KdfProfile, body_alg: u16) -> Result<StaticHeader, VaultV2Error> {
    let mut kdf_salt = [0u8; 32];
    let mut vault_id = [0u8; 16];
    fill_random(&mut kdf_salt)?;
    fill_random(&mut vault_id)?;
    Ok(StaticHeader {
        kdf_alg: KDF_ARGON2ID,
        kdf_m_kib: profile.m_kib(),
        kdf_t: profile.t(),
        kdf_p: profile.p(),
        kdf_salt,
        vault_id,
        body_alg,
        wrap_alg: WRAP_AEGIS256,
    })
}

fn fresh_nonce(alg: BodyAlg) -> Result<Nonce, VaultV2Error> {
    match alg {
        BodyAlg::Aegis256 => {
            let mut nonce = [0u8; 32];
            fill_random(&mut nonce)?;
            Ok(Nonce::Aegis(nonce))
        }
        BodyAlg::KuzCtrHmac => {
            let mut nonce = [0u8; 8];
            fill_random(&mut nonce)?;
            Ok(Nonce::Kuz(nonce))
        }
        BodyAlg::KuzMgm => Err(VaultV2Error::UnsupportedBodyAlg(BODY_KUZ_MGM)),
    }
}

fn fill_random(dest: &mut [u8]) -> Result<(), VaultV2Error> {
    // The session error set has no RNG variant. Wipe whatever was written and
    // report a structural failure; the caller cannot repair an OS entropy error.
    if getrandom::fill(dest).is_err() {
        dest.zeroize();
        return Err(VaultV2Error::CorruptedLength);
    }
    Ok(())
}

enum Nonce {
    Aegis([u8; 32]),
    Kuz([u8; 8]),
}

impl Nonce {
    const fn as_slice(&self) -> &[u8] {
        match self {
            Self::Aegis(nonce) => nonce,
            Self::Kuz(nonce) => nonce,
        }
    }
}
