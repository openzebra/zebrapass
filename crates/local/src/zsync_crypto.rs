//! Self-certifying personal and shared sync repository anchors, recovery-phrase
//! vault-key grants (`zsync.grant`), and hybrid P-256 + ML-KEM-768 shared-vault
//! rotation grants.

use frame::{ALG_CASCADE, FrameMeta, KIND_REVISION, open, seal};
use pq::{
    KEM_CT_LEN, PERSONAL_REPO_CTX, SHARED_REPO_CTX, SYNC_SIG_LEN, SYNC_VK_LEN, sync_sign,
    sync_verify, sync_verifying_key,
};
use secret::{Secret, ct_eq};
use session::frame_parts;
use sha2::{Digest, Sha256};
use syncwire::reader::Reader;

use crate::share_keys::{ShareKeys, SharePublics};
use crate::{Paths, write_atomic};

/// Encoded byte length of a [`PersonalRepoAnchor`].
pub const PERSONAL_ANCHOR_LEN: usize = SYNC_VK_LEN + SYNC_SIG_LEN;

/// Encoded byte length of a [`SharedRepoProof`].
pub const SHARED_PROOF_LEN: usize = SYNC_VK_LEN + 16 + 32 + SYNC_SIG_LEN;

const DOMAIN_PERSONAL_ANCHOR: &[u8] = b"brby/v3/personal-repo-anchor";
const DOMAIN_SHARED_PROOF: &[u8] = b"brby/v3/shared-repo-proof";
const DOMAIN_SHARED_REKEY: &[u8] = b"brby/v3/shared-rekey";
const SHARED_REKEY_MAGIC: [u8; 6] = *b"ZSRK\x00\x01";
const MASTER_GRANT_RECORD_ID: u32 = 0x8000_0022;
const SHARED_REKEY_RECORD_ID: u32 = 0x8000_0023;
const MAX_MASTER_GRANT_BYTES: usize = 512;
const MAX_SHARED_REKEY_SEALED: usize = 512;

fn corrupted() -> anyhow::Error {
    anyhow::anyhow!("corrupted length")
}

/// Self-certifying ML-DSA-65 proof binding a personal sync repository's
/// `storage_id` (`personal_storage_id_from_vk(&anchor_vk)`) to `(client_id, root_vk)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalRepoAnchor {
    /// Dedicated personal sync anchor verifying key.
    pub anchor_vk: Box<[u8; SYNC_VK_LEN]>,
    /// ML-DSA-65 signature authorizing `(storage_id, client_id, root_vk)`.
    pub signature: Vec<u8>,
}

impl PersonalRepoAnchor {
    fn signed_message(
        storage_id: &[u8; 64],
        client_id: &[u8; 64],
        root_vk: &[u8; SYNC_VK_LEN],
    ) -> anyhow::Result<Vec<u8>> {
        frame_parts(&[DOMAIN_PERSONAL_ANCHOR, storage_id, client_id, root_vk])
    }

    /// Issue a self-certifying anchor from `master_seed` for `(client_id, root_vk)`.
    ///
    /// # Errors
    ///
    /// Key derivation or ML-DSA signing failure.
    pub fn issue(
        master_seed: &[u8; 64],
        client_id: &[u8; 64],
        root_vk: &[u8; SYNC_VK_LEN],
    ) -> anyhow::Result<Self> {
        let seed = kdf::zsync_personal_root_seed(master_seed)?;
        let raw_vk = sync_verifying_key(seed.expose())?;
        let anchor_vk = Box::new(<[u8; SYNC_VK_LEN]>::try_from(raw_vk).map_err(|_| corrupted())?);
        let sid = kdf::personal_storage_id_from_vk(anchor_vk.as_slice())?;
        let msg = Self::signed_message(&sid, client_id, root_vk)?;
        let signature = sync_sign(seed.expose(), PERSONAL_REPO_CTX, &msg)?;
        Ok(Self {
            anchor_vk,
            signature,
        })
    }

    /// Canonical 512-bit personal sync `storage_id` derived from `anchor_vk`.
    ///
    /// # Errors
    ///
    /// KDF rejection.
    pub fn storage_id(&self) -> anyhow::Result<[u8; 64]> {
        kdf::personal_storage_id_from_vk(self.anchor_vk.as_slice())
    }

    /// Verify that `anchor_vk` hashes to `storage_id` and authorizes `(client_id, root_vk)`.
    ///
    /// # Errors
    ///
    /// Self-certifying `storage_id` mismatch or invalid ML-DSA signature.
    pub fn verify(
        &self,
        storage_id: &[u8; 64],
        client_id: &[u8; 64],
        root_vk: &[u8; SYNC_VK_LEN],
    ) -> anyhow::Result<()> {
        let derived = self.storage_id()?;
        if !ct_eq(&derived, storage_id) {
            anyhow::bail!("personal repo anchor rejected");
        }
        let msg = Self::signed_message(storage_id, client_id, root_vk)?;
        sync_verify(
            self.anchor_vk.as_slice(),
            PERSONAL_REPO_CTX,
            &msg,
            &self.signature,
        )
        .map_err(|_| anyhow::anyhow!("personal repo anchor rejected"))
    }

    /// Encode to fixed [`PERSONAL_ANCHOR_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Signature has unexpected length.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        if self.signature.len() != SYNC_SIG_LEN {
            return Err(corrupted());
        }
        let mut out = Vec::with_capacity(PERSONAL_ANCHOR_LEN);
        out.extend_from_slice(self.anchor_vk.as_slice());
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Decode from fixed [`PERSONAL_ANCHOR_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Slice length is not [`PERSONAL_ANCHOR_LEN`].
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut r = Reader::new(bytes);
        let anchor_vk = Box::new(r.array::<SYNC_VK_LEN>()?);
        let sig = r.array::<SYNC_SIG_LEN>()?;
        r.finish()?;
        Ok(Self {
            anchor_vk,
            signature: sig.to_vec(),
        })
    }
}

/// Compute the self-certifying 512-bit shared `zsync` storage identifier from
/// `shared_seed` and `vault_id`.
///
/// # Errors
///
/// Key derivation or ML-DSA key encoding failure.
pub fn shared_zsync_storage_id(
    shared_seed: &[u8; 64],
    vault_id: &[u8; 16],
) -> anyhow::Result<[u8; 64]> {
    let seed = kdf::shared_repo_sign_seed(shared_seed, vault_id)?;
    let vk = sync_verifying_key(seed.expose())?;
    kdf::shared_storage_id_from_vk(&vk, vault_id)
}

/// Self-certifying ML-DSA-65 proof binding a shared sync repository's
/// `storage_id` to `(vault_id, anchor)` so outsiders cannot squat it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedRepoProof {
    /// Repository verifying key derived from `shared_seed`.
    pub repo_vk: Box<[u8; SYNC_VK_LEN]>,
    /// Shared vault identifier.
    pub vault_id: [u8; 16],
    /// Genesis `MemberLog` entry hash.
    pub anchor: [u8; 32],
    /// ML-DSA-65 signature over `(storage_id, vault_id, anchor)`.
    pub signature: Vec<u8>,
}

impl SharedRepoProof {
    fn signed_message(
        storage_id: &[u8; 64],
        vault_id: &[u8; 16],
        anchor: &[u8; 32],
    ) -> anyhow::Result<Vec<u8>> {
        frame_parts(&[DOMAIN_SHARED_PROOF, storage_id, vault_id, anchor])
    }

    /// Issue a [`SharedRepoProof`] and return `(proof, storage_id)`.
    ///
    /// # Errors
    ///
    /// Key derivation or ML-DSA signing failure.
    pub fn issue(
        shared_seed: &[u8; 64],
        vault_id: [u8; 16],
        anchor: [u8; 32],
    ) -> anyhow::Result<(Self, [u8; 64])> {
        let seed = kdf::shared_repo_sign_seed(shared_seed, &vault_id)?;
        let raw_vk = sync_verifying_key(seed.expose())?;
        let repo_vk = Box::new(<[u8; SYNC_VK_LEN]>::try_from(raw_vk).map_err(|_| corrupted())?);
        let sid = kdf::shared_storage_id_from_vk(repo_vk.as_slice(), &vault_id)?;
        let msg = Self::signed_message(&sid, &vault_id, &anchor)?;
        let signature = sync_sign(seed.expose(), SHARED_REPO_CTX, &msg)?;
        Ok((
            Self {
                repo_vk,
                vault_id,
                anchor,
                signature,
            },
            sid,
        ))
    }

    /// Verify that `repo_vk` hashes to `storage_id` and authorizes `(vault_id, anchor)`.
    ///
    /// # Errors
    ///
    /// Self-certifying `storage_id` mismatch or invalid ML-DSA signature.
    pub fn verify(&self, storage_id: &[u8; 64]) -> anyhow::Result<()> {
        let derived = kdf::shared_storage_id_from_vk(self.repo_vk.as_slice(), &self.vault_id)?;
        if !ct_eq(&derived, storage_id) {
            anyhow::bail!("shared repo proof rejected");
        }
        let msg = Self::signed_message(storage_id, &self.vault_id, &self.anchor)?;
        sync_verify(
            self.repo_vk.as_slice(),
            SHARED_REPO_CTX,
            &msg,
            &self.signature,
        )
        .map_err(|_| anyhow::anyhow!("shared repo proof rejected"))
    }

    /// Encode to [`SHARED_PROOF_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Signature has unexpected length.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        if self.signature.len() != SYNC_SIG_LEN {
            return Err(corrupted());
        }
        let mut out = Vec::with_capacity(SHARED_PROOF_LEN);
        out.extend_from_slice(self.repo_vk.as_slice());
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.anchor);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Decode from [`SHARED_PROOF_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Slice length is not [`SHARED_PROOF_LEN`].
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut r = Reader::new(bytes);
        let repo_vk = Box::new(r.array::<SYNC_VK_LEN>()?);
        let vault_id = r.array::<16>()?;
        let anchor = r.array::<32>()?;
        let sig = r.array::<SYNC_SIG_LEN>()?;
        r.finish()?;
        Ok(Self {
            repo_vk,
            vault_id,
            anchor,
            signature: sig.to_vec(),
        })
    }
}

/// Seal the personal vault key `vk` under `master_seed` and `storage_id` so a
/// BIP39 phrase restore can open `SignedHead` without any peer device.
///
/// # Errors
///
/// Key derivation or Cascade sealing failure.
pub fn seal_master_grant(
    master_seed: &[u8; 64],
    storage_id: &[u8; 64],
    vault_id: &[u8; 16],
    vk: &Secret<[u8; 32]>,
) -> anyhow::Result<Vec<u8>> {
    let key = kdf::zsync_master_grant_key(master_seed, storage_id)?;
    let meta = FrameMeta {
        kind: KIND_REVISION,
        record_id: MASTER_GRANT_RECORD_ID,
        revision: 1,
        origin_device: *vault_id,
        timestamp_ms: 0,
        alg: ALG_CASCADE,
    };
    seal(&key, &meta, vk.expose())
}

/// Open a `master_grant` blob using `master_seed` and `storage_id`, returning
/// `(vault_id, vk)`.
///
/// # Errors
///
/// Oversized/malformed frame or Cascade authentication failure.
pub fn open_master_grant(
    master_seed: &[u8; 64],
    storage_id: &[u8; 64],
    blob: &[u8],
) -> anyhow::Result<([u8; 16], Secret<[u8; 32]>)> {
    if blob.len() > MAX_MASTER_GRANT_BYTES {
        return Err(corrupted());
    }
    let meta = frame::parse(blob)?;
    if meta.alg != ALG_CASCADE || meta.record_id != MASTER_GRANT_RECORD_ID || meta.revision != 1 {
        anyhow::bail!("master grant rejected");
    }
    let key = kdf::zsync_master_grant_key(master_seed, storage_id)?;
    let plain = open(&key, blob)?;
    if plain.expose().len() != 32 {
        return Err(corrupted());
    }
    let mut vk = Secret::new([0u8; 32]);
    vk.expose_mut().copy_from_slice(plain.expose());
    Ok((meta.origin_device, vk))
}

/// Persist the current `master_grant` blob atomically (`0600`) next to the vault.
///
/// # Errors
///
/// Atomic write failure.
pub fn save_master_grant(paths: &Paths, grant: &[u8]) -> anyhow::Result<()> {
    if grant.len() > MAX_MASTER_GRANT_BYTES {
        return Err(corrupted());
    }
    write_atomic(&paths.zsync_grant(), grant)
}

/// Read the persisted `master_grant` blob if present and within size bounds.
#[must_use]
pub fn load_master_grant(paths: &Paths) -> Option<Vec<u8>> {
    let bytes = std::fs::read(paths.zsync_grant()).ok()?;
    (bytes.len() <= MAX_MASTER_GRANT_BYTES && !bytes.is_empty()).then_some(bytes)
}

/// Remove any persisted `master_grant` blob when dropping the recovery wrap.
pub fn clear_master_grant(paths: &Paths) {
    let _ = std::fs::remove_file(paths.zsync_grant());
}

fn shared_rekey_transcript(
    vault_id: &[u8; 16],
    anchor: &[u8; 32],
    target_device: &[u8; 16],
    new_epoch: u32,
    eph_ec: &[u8; 65],
    kem_ct: &[u8; KEM_CT_LEN],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN_SHARED_REKEY)
        .chain_update(vault_id)
        .chain_update(anchor)
        .chain_update(target_device)
        .chain_update(new_epoch.to_be_bytes())
        .chain_update(eph_ec)
        .chain_update(kem_ct)
        .finalize()
        .into()
}

/// Seal a rotated 64-byte `new_seed` at `new_epoch` to one remaining member
/// device (`recipient`, `target_device`) using hybrid P-256 + ML-KEM-768 and
/// Cascade (`0xA005`).
///
/// # Errors
///
/// Invalid recipient key, RNG failure, key-derivation or sealing failure.
pub fn seal_shared_rekey(
    recipient: &SharePublics,
    target_device: &[u8; 16],
    vault_id: &[u8; 16],
    anchor: &[u8; 32],
    new_epoch: u32,
    new_seed: &Secret<[u8; 64]>,
) -> anyhow::Result<Vec<u8>> {
    let (eph_secret, eph_public) = ec::fresh_pair()?;
    let eph_ec = ec::encode_pub(&eph_public)?;
    let peer_ec = ec::decode_pub(&recipient.ec_pub)?;
    let ss_ec = Secret::new(ec::shared(&eph_secret, &peer_ec));
    let (ss_kem, kem_ct_vec) = pq::encrypt_shared(recipient.kem_ek.as_slice())?;
    let kem_ct: [u8; KEM_CT_LEN] = kem_ct_vec.try_into().map_err(|_| corrupted())?;
    let th = shared_rekey_transcript(vault_id, anchor, target_device, new_epoch, &eph_ec, &kem_ct);
    let key = kdf::shared_rekey_key(&ss_kem, &ss_ec, vault_id, &th)?;
    let meta = FrameMeta {
        kind: KIND_REVISION,
        record_id: SHARED_REKEY_RECORD_ID,
        revision: u64::from(new_epoch),
        origin_device: *target_device,
        timestamp_ms: 0,
        alg: ALG_CASCADE,
    };
    let sealed = seal(&key, &meta, new_seed.expose())?;
    let sealed_len = u16::try_from(sealed.len())?;
    let mut out = Vec::with_capacity(SHARED_REKEY_MAGIC.len() + 65 + KEM_CT_LEN + 2 + sealed.len());
    out.extend_from_slice(&SHARED_REKEY_MAGIC);
    out.extend_from_slice(&eph_ec);
    out.extend_from_slice(&kem_ct);
    out.extend_from_slice(&sealed_len.to_be_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Decapsulate a hybrid P-256 + ML-KEM-768 shared-vault rotation grant for
/// `my_device` at `expected_epoch`.
///
/// # Errors
///
/// Malformed grant, epoch/device mismatch, or AEAD authentication failure.
pub fn open_shared_rekey(
    keys: &ShareKeys,
    my_device: &[u8; 16],
    vault_id: &[u8; 16],
    anchor: &[u8; 32],
    expected_epoch: u32,
    blob: &[u8],
) -> anyhow::Result<Secret<[u8; 64]>> {
    let mut r = Reader::new(blob);
    let magic = r.array::<6>()?;
    if !ct_eq(&magic, &SHARED_REKEY_MAGIC) {
        return Err(corrupted());
    }
    let eph_ec = r.array::<65>()?;
    let kem_ct = r.array::<KEM_CT_LEN>()?;
    let sealed = r.bytes_u16(MAX_SHARED_REKEY_SEALED)?;
    r.finish()?;

    let ec_sk = keys.ec_secret()?;
    let peer_ec = ec::decode_pub(&eph_ec)?;
    let ss_ec = Secret::new(ec::shared(&ec_sk, &peer_ec));
    let ss_kem = pq::decrypt_shared(keys.kem_seed().expose(), &kem_ct)?;
    let th = shared_rekey_transcript(
        vault_id,
        anchor,
        my_device,
        expected_epoch,
        &eph_ec,
        &kem_ct,
    );
    let key = kdf::shared_rekey_key(&ss_kem, &ss_ec, vault_id, &th)?;
    let meta = frame::parse(sealed)?;
    if meta.alg != ALG_CASCADE
        || meta.record_id != SHARED_REKEY_RECORD_ID
        || meta.revision != u64::from(expected_epoch)
        || !ct_eq(&meta.origin_device, my_device)
    {
        anyhow::bail!("shared rekey grant rejected");
    }
    let plain = open(&key, sealed)?;
    if plain.expose().len() != 64 {
        return Err(corrupted());
    }
    let mut seed = Secret::new([0u8; 64]);
    seed.expose_mut().copy_from_slice(plain.expose());
    Ok(seed)
}
