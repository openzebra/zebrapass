//! Create a vault and the shared commit/body helpers.

use aead::{encrypt_body, BodyAlg};
use container::{
    assemble, encode_chip_entry, encode_human_password_entry, encode_password_entry,
    encode_prf_entry, encode_wrap_dir, StaticHeader, VaultFile, WrapEntry, BODY_AEGIS256,
    BODY_FRAMES, BODY_KUZ_CTR_HMAC, BODY_KUZ_MGM, COMMIT_LEN, DOMAIN_BODY, KDF_ARGON2ID,
    WRAP_AEGIS256,
};
use frame::encode_frames;
use hmac::{Hmac, KeyInit, Mac};
use kdf::{derive_vault_keys, local_meta_key, KdfProfile};
use secret::Secret;
use sha2::{Digest, Sha256};
use wraps::seal_password;
use zeroize::Zeroize;

use crate::error::SessionError;

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
    /// Device identity this session stamps into new frames: the wrap id of
    /// the device wrap that opened the session, a fresh random id when the
    /// vault was just created, or a per-unlock random id for seed, human
    /// password, and recovery unlocks (an unregistered origin).
    pub(crate) origin_device: [u8; 16],
    /// Decrypted frame body. A per-record key opens single frames from it.
    pub(crate) records: Secret<Vec<u8>>,
    /// Running `Frames` body commitment. Zero for whole-body modes.
    pub(crate) frames_digest: [u8; 32],
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

    /// The running `Frames` body commitment; zero for whole-body modes.
    #[must_use]
    pub const fn frames_digest(&self) -> [u8; 32] {
        self.frames_digest
    }

    /// The device wrap id this session unlocked with, if any.
    #[must_use]
    pub const fn origin_device(&self) -> [u8; 16] {
        self.origin_device
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
    let origin_device = fresh_device_id()?;
    let header = new_header(profile, body_id)?;
    let password = seal_password(&header, master, vk.expose())?;
    let (k_body, k_bmac, k_commit) = derive_vault_keys(vk.expose(), &header.vault_id)?;
    let body = encrypt_records(body_alg, &header, k_body.expose(), k_bmac.expose(), &[])?;
    let mode = commit_mode(body_alg);
    let records = [password];
    let wrap_dir = dir_bytes(1, &records)?;
    let (file, commit_tag) =
        assemble_committed(k_commit.expose(), &header, &wrap_dir, &body, mode)?;
    let frames_digest = match mode {
        CommitMode::Folded => body_digest(&body)?,
        CommitMode::Whole => [0u8; 32],
    };
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
            origin_device,
            frames_digest,
            records: Secret::new(Vec::new()),
        },
    ))
}

fn body_alg_id(alg: BodyAlg) -> anyhow::Result<u16> {
    match alg {
        BodyAlg::Aegis256 => Ok(BODY_AEGIS256),
        BodyAlg::Frames => Ok(BODY_FRAMES),
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
        WrapEntry::HumanPassword(wrap) => Ok(encode_human_password_entry(
            wrap.kid, wrap.salt, wrap.kdf, wrap.nonce, wrap.ct, wrap.tag,
        )
        .to_vec()),
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
    let nonce_len = match alg {
        BodyAlg::Frames => return encode_frames(records),
        BodyAlg::KuzMgm => {
            return Err(anyhow::anyhow!(
                "unsupported body algorithm {BODY_KUZ_MGM:#06x}"
            ))
        }
        BodyAlg::Aegis256 => 32,
        BodyAlg::KuzCtrHmac => 16,
    };
    let ad = body_ad(header);
    let mut nonce = [0u8; 32];
    let slot = nonce
        .get_mut(..nonce_len)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    fill_random(slot)?;
    encrypt_body(alg, k_body, k_bmac, slot, &ad, records)
}

/// How the commit tag covers the body.
///
/// Whole-body algorithms re-encrypt on every write, so the tag must cover the
/// whole ciphertext. `Frames` appends sealed frames without touching the old
/// bytes; the tag covers a fold (chained SHA-256) of the per-frame digests,
/// so appending updates the commitment in O(1) instead of O(body size) and a
/// server can check which frame belongs to which vault version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitMode {
    /// HMAC over the whole body ciphertext.
    Whole,
    /// HMAC over `SHA256(body)` — the body commitment fold.
    Folded,
}

/// The commit mode a body algorithm dictates.
#[must_use]
pub const fn commit_mode(alg: BodyAlg) -> CommitMode {
    match alg {
        BodyAlg::Frames => CommitMode::Folded,
        BodyAlg::Aegis256 | BodyAlg::KuzCtrHmac | BodyAlg::KuzMgm => CommitMode::Whole,
    }
}

/// SHA-256 over `bytes`. The fold's per-step compression.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Fold one frame into the running body commitment:
/// `SHA256(running || SHA256(frame))`. Chaining the running value makes the
/// commitment order-sensitive, so frames cannot be reordered without a
/// different final digest.
#[must_use]
pub fn fold_tag(running: [u8; 32], frame: &[u8]) -> [u8; 32] {
    let step = sha256(frame);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&running);
    input[32..].copy_from_slice(&step);
    sha256(&input)
}

/// The body commitment for a `Frames` body: `fold` over every frame.
///
/// # Errors
///
/// `frame index rejected` when the body does not parse as a frame log.
pub fn body_digest(body: &[u8]) -> anyhow::Result<[u8; 32]> {
    fold_log(&frame::decode_frames(body)?)
}

/// Fold a whole raw frame log into one commitment.
///
/// # Errors
///
/// `corrupted length` when the log does not parse as whole frames or a
/// span overflows the buffer.
#[allow(
    clippy::redundant_pub_crate,
    reason = "shared by sibling rotation modules; the module itself is private"
)]
pub(crate) fn fold_log(log: &[u8]) -> anyhow::Result<[u8; 32]> {
    fold_new_spans([0u8; 32], 0, log)
}

/// Fold only the frames past `existing_len` into `digest` (the O(1)-append
/// counterpart of [`fold_log`]).
///
/// # Errors
///
/// `corrupted length` when the log does not parse as whole frames or a
/// span overflows the buffer.
#[allow(
    clippy::redundant_pub_crate,
    reason = "shared by sibling rotation modules; the module itself is private"
)]
pub(crate) fn fold_new_spans(
    digest: [u8; 32],
    existing_len: usize,
    log: &[u8],
) -> anyhow::Result<[u8; 32]> {
    frame::spans(log)?
        .into_iter()
        .try_fold(digest, |digest, (start, len)| {
            let Some(end) = start.checked_add(len) else {
                anyhow::bail!("corrupted length");
            };
            if end <= existing_len {
                return Ok(digest);
            }
            let span = log
                .get(start..end)
                .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
            Ok(fold_tag(digest, span))
        })
}

pub fn assemble_committed(
    k_commit: &[u8; 32],
    header: &StaticHeader,
    wrap_dir: &[u8],
    body: &[u8],
    mode: CommitMode,
) -> anyhow::Result<(VaultFile, [u8; 32])> {
    let header_bytes = header.to_bytes();
    let tag = match mode {
        CommitMode::Whole => mac_commit(k_commit, &[&header_bytes, wrap_dir, body])?,
        // Only the commitment rides into the MAC: appending a frame changes
        // the digest, not the whole body, so the O(1) append is possible.
        CommitMode::Folded => {
            let commitment = body_digest(body)?;
            mac_commit(k_commit, &[&header_bytes, wrap_dir, &commitment])?
        }
    };
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
    let mode = commit_mode(session.body_alg);
    let (updated, tag) =
        assemble_committed(session.k_commit.expose(), header, &wrap_dir, body, mode)?;
    *file = updated;
    session.generation = generation;
    session.commit_tag = tag;
    Ok(())
}

pub fn mac_commit(key: &[u8; 32], parts: &[&[u8]]) -> anyhow::Result<[u8; 32]> {
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

pub fn verify_commit(bytes: &[u8], key: &[u8; 32], expected: &[u8; 32]) -> anyhow::Result<()> {
    let end = bytes
        .len()
        .checked_sub(COMMIT_LEN)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let prefix = bytes
        .get(..end)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let actual = mac_commit(key, &[prefix])?;
    if secret::ct_eq_32(&actual, expected) {
        Ok(())
    } else {
        Err(SessionError::CommitMismatch.into())
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
    // An OS entropy failure is environmental, not structural: report it as
    // its own error so the UI never shows a corruption message.
    if getrandom::fill(dest).is_err() {
        dest.zeroize();
        return Err(SessionError::Entropy.into());
    }
    Ok(())
}

/// Random per-device frame origin. The all-zero id is never handed out: it
/// would make an unidentified origin look like a registered device.
///
/// # Errors
///
/// `os entropy failed` when the OS RNG is unavailable.
pub fn fresh_device_id() -> anyhow::Result<[u8; 16]> {
    let mut id = [0u8; 16];
    fill_random(&mut id)?;
    Ok(id)
}
