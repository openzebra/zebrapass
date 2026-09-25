//! Create a vault and the shared commit/body helpers.

use aead::{encrypt_body, BodyAlg};
use container::{
    assemble, encode_chip_entry, encode_device_entry, encode_password_entry, encode_prf_entry,
    encode_wrap_dir, StaticHeader, VaultFile, WrapEntry, BODY_AEGIS256, BODY_KUZ_CTR_HMAC,
    BODY_KUZ_MGM, COMMIT_LEN, DOMAIN_BODY, KDF_ARGON2ID, WRAP_AEGIS256,
};
use hmac::{Hmac, KeyInit, Mac};
use kdf::{derive_vault_keys, local_meta_key, KdfProfile};
use secret::Secret;
use sha2::Sha256;
use wraps::seal_password;
use zeroize::Zeroize;


type HmacSha256 = Hmac<Sha256>;

/// Open vault. The vault key and the three derived keys are wiped on drop.
///
/// `generation` and `commit_tag` track the file this session last wrote or opened.
/// `records` holds the decrypted frame body: it is materialized once at
/// [`unlock`](crate::unlock) and kept for on-demand record access; it is
/// wiped when the session drops.
#[derive(Debug)]
pub struct Session {
    pub(crate) vk: Secret<[u8; 32]>,
    pub(crate) k_body: Secret<[u8; 32]>,
    pub(crate) k_bmac: Secret<[u8; 32]>,
    pub(crate) k_commit: Secret<[u8; 32]>,
    pub(crate) body_alg: BodyAlg,
    pub(crate) generation: u64,
    pub(crate) commit_tag: [u8; 32],
    /// Public vault id: the HKDF salt for frame keys.
    pub(crate) vault_id: [u8; 16],
    /// Device identity this session stamps into new frames.
    pub(crate) device_id: [u8; 16],
    /// Decrypted frame body. A per-record key opens single frames from it.
    pub(crate) records: Secret<Vec<u8>>,
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

    /// Public vault id of the opened file.
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }

    /// Device identity this session stamps into new frames.
    #[must_use]
    pub const fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }

    /// Key for this vault's on-device local-metadata file.
    ///
    /// # Errors
    ///
    /// `kdf parameters rejected` when HKDF-Expand rejects the output length.
    pub fn local_meta_key(&self) -> anyhow::Result<Secret<[u8; 32]>> {
        local_meta_key(self.vk.expose(), &self.vault_id)
    }
}

/// Create a vault and the session that holds its keys.
///
/// `master` is the 64-byte master seed (the BIP39 seed of the seed
/// phrase); a `&[u8; 64]` can never be empty. Generation starts at 1. The
/// file has one password wrap and a body that is the AEAD of an empty
/// frame list. The commit is HMAC-SHA256 over
/// `header ‖ wrap directory ‖ body`.
///
/// # Errors
///
/// `unsupported body algorithm` for [`BodyAlg::KuzMgm`], before Argon2.
/// `kdf parameters rejected` when the profile parameters are rejected.
/// `corrupted length` when the OS RNG or HMAC constructor fails.
pub fn create(
    master: &[u8; 64],
    profile: KdfProfile,
    body_alg: BodyAlg,
) -> anyhow::Result<(VaultFile, Session)> {
    // KuzMgm is a recognized id this build cannot seal. Reject it before Argon2.
    let body_id = body_alg_id(body_alg)?;
    let vk = draw_secret()?;
    let header = new_header(profile, body_id)?;
    let password = seal_password(&header, master, vk.expose())?;
    let (k_body, k_bmac, k_commit) = derive_vault_keys(vk.expose(), &header.vault_id)?;
    let body = encrypt_records(body_alg, &header, k_body.expose(), k_bmac.expose(), &[])?;
    let records = [password];
    let wrap_dir = dir_bytes(1, &records)?;
    let (file, commit_tag) = assemble_committed(k_commit.expose(), &header, &wrap_dir, &body)?;
    let device_id = draw_device_id()?;
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
            vault_id: header.vault_id,
            device_id,
            records: Secret::new(Vec::new()),
        },
    ))
}

/// Draw a device id that is never all-zero.
pub(super) fn draw_device_id() -> anyhow::Result<[u8; 16]> {
    for _ in 0..8 {
        let mut id = [0u8; 16];
        fill_random(&mut id)?;
        if id != [0u8; 16] {
            return Ok(id);
        }
    }
    Err(anyhow::anyhow!("os entropy failed"))
}

fn body_alg_id(alg: BodyAlg) -> anyhow::Result<u16> {
    match alg {
        BodyAlg::Aegis256 => Ok(BODY_AEGIS256),
        BodyAlg::KuzCtrHmac => Ok(BODY_KUZ_CTR_HMAC),
        BodyAlg::KuzMgm => Err(anyhow::anyhow!("unsupported body algorithm 0xa002")),
    }
}

/// A wrapping generation would look like a rollback to a client that stored `Seen`.
pub fn next_generation(generation: u64) -> anyhow::Result<u64> {
    generation
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("generation overflow"))
}

pub fn encode_entry(entry: &WrapEntry<'_>) -> anyhow::Result<Vec<u8>> {
    match entry {
        WrapEntry::Password(wrap) => {
            Ok(encode_password_entry(wrap.kid, wrap.nonce, wrap.ct, wrap.tag).to_vec())
        }
        WrapEntry::Device(wrap) => Ok(encode_device_entry(
            wrap.device_id,
            wrap.kem_alg,
            wrap.dev_x_pk,
            wrap.eph_x_pk,
            wrap.kem_ct,
            wrap.nonce,
            wrap.ct,
            wrap.tag,
        )?),
        WrapEntry::Chip(wrap) => Ok(encode_chip_entry(
            wrap.id,
            wrap.chip_pub,
            wrap.eph_pub,
            wrap.pq_pk,
            wrap.kem_ct,
            wrap.nonce,
            wrap.ct,
            wrap.tag,
        )?),
        WrapEntry::Prf(wrap) => Ok(encode_prf_entry(
            wrap.id,
            wrap.cred_id,
            wrap.salt,
            wrap.nonce,
            wrap.ct,
            wrap.tag,
        )?),
    }
}

pub fn owned_entries(entries: &[WrapEntry<'_>]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut records = Vec::with_capacity(entries.len());
    for entry in entries {
        records.push(encode_entry(entry)?);
    }
    Ok(records)
}

pub fn dir_bytes(generation: u64, records: &[Vec<u8>]) -> anyhow::Result<Vec<u8>> {
    let refs = records.iter().map(Vec::as_slice).collect::<Vec<_>>();
    encode_wrap_dir(generation, &refs)
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
) -> anyhow::Result<Vec<u8>> {
    let ad = body_ad(header);
    let mut nonce = [0u8; 32];
    let nonce_len = match alg {
        BodyAlg::Aegis256 => 32,
        BodyAlg::KuzCtrHmac => 8,
        BodyAlg::KuzMgm => return Err(anyhow::anyhow!("unsupported body algorithm {BODY_KUZ_MGM:#06x}")),
    };
    let slot = nonce
        .get_mut(..nonce_len)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    fill_random(slot)?;
    let used = nonce
        .get(..nonce_len)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    encrypt_body(alg, k_body, k_bmac, used, &ad, records)
}

pub fn assemble_committed(
    k_commit: &[u8; 32],
    header: &StaticHeader,
    wrap_dir: &[u8],
    body: &[u8],
) -> anyhow::Result<(VaultFile, [u8; 32])> {
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
) -> anyhow::Result<()> {
    let wrap_dir = dir_bytes(generation, records)?;
    let (updated, tag) = assemble_committed(session.k_commit.expose(), header, &wrap_dir, body)?;
    *file = updated;
    session.generation = generation;
    session.commit_tag = tag;
    Ok(())
}

fn mac_commit(key: &[u8; 32], parts: &[&[u8]]) -> anyhow::Result<[u8; 32]> {
    // A 32-byte key is a legal HMAC key. The constructor still returns `Result`.
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return Err(anyhow::anyhow!("corrupted length"));
    };
    for part in parts {
        mac.update(part);
    }
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    for (dst, src) in out.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    Ok(out)
}

pub fn verify_commit(
    bytes: &[u8],
    key: &[u8; 32],
    expected: &[u8; 32],
) -> anyhow::Result<()> {
    let end = bytes
        .len()
        .checked_sub(COMMIT_LEN)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let prefix = bytes.get(..end).ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let actual = mac_commit(key, &[prefix])?;
    if secret::ct_eq_32(&actual, expected) {
        Ok(())
    } else {
        Err(anyhow::anyhow!("commit mismatch"))
    }
}

pub fn draw_secret() -> anyhow::Result<Secret<[u8; 32]>> {
    let mut raw = [0u8; 32];
    fill_random(&mut raw)?;
    let secret = Secret::new(raw);
    raw.zeroize();
    Ok(secret)
}

fn new_header(profile: KdfProfile, body_alg: u16) -> anyhow::Result<StaticHeader> {
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

fn fill_random(dest: &mut [u8]) -> anyhow::Result<()> {
    // The session error set has no RNG variant. Wipe whatever was written and
    // report a structural failure; the caller cannot repair an OS entropy error.
    if getrandom::fill(dest).is_err() {
        dest.zeroize();
        return Err(anyhow::anyhow!("corrupted length"));
    }
    Ok(())
}
