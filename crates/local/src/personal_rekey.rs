//! Personal vault head metadata, authenticated device-key announcements, and
//! hybrid P-256 + ML-KEM-768 personal vault-key rotation grants.

use frame::{ALG_CASCADE, FrameMeta, KIND_REVISION, open, seal};
use pq::{KEM_CT_LEN, PEER_CTX, PQ_PK_LEN, SYNC_SIG_LEN, SYNC_VK_LEN, sync_sign, sync_verify};
use secret::{Secret, ct_eq};
use session::{DeviceCert, frame_parts};
use sha2::{Digest, Sha256};
use syncwire::reader::Reader;
use syncwire::{CERT_WIRE_LEN, decode_cert, encode_cert};

use crate::share_keys::{ShareKeys, SharePublics};
use crate::sync_identity::SyncIdentity;

/// Encoded length of the compact personal snapshot head metadata.
pub const PERSONAL_HEAD_LEN: usize = 56;

/// Magic header for signed per-device announcements uploaded as personal frames.
pub const PERSONAL_DEVICE_MAGIC: [u8; 6] = *b"ZPDV\x00\x01";

/// Magic header for hybrid P-256 + ML-KEM-768 personal vault-key rekey grants.
const REKEY_MAGIC: [u8; 6] = *b"ZPRK\x00\x01";

const DOMAIN_DEVICE_ENTRY: &[u8] = b"brby/v1/personal-device-entry";
const DOMAIN_REKEY: &[u8] = b"brby/v1/personal-rekey";
const REKEY_RECORD_ID: u32 = 0x8000_0021;
const MAX_REKEY_SEALED: usize = 512;

fn corrupted() -> anyhow::Error {
    anyhow::anyhow!("corrupted length")
}

/// Encode `(vault_id, commit_tag, generation)` into the compact 56-byte head
/// metadata stored alongside a personal snapshot on sync servers.
#[must_use]
pub const fn encode_personal_head(
    vault_id: &[u8; 16],
    commit_tag: &[u8; 32],
    generation: u64,
) -> [u8; PERSONAL_HEAD_LEN] {
    let mut out = [0u8; PERSONAL_HEAD_LEN];
    if let Some((head, tail)) = out.split_at_mut_checked(16) {
        head.copy_from_slice(vault_id);
        if let Some((tag, gen_bytes)) = tail.split_at_mut_checked(32) {
            tag.copy_from_slice(commit_tag);
            gen_bytes.copy_from_slice(&generation.to_be_bytes());
        }
    }
    out
}

/// Decode the compact 56-byte personal snapshot head metadata into
/// `(vault_id, commit_tag, generation)`.
///
/// # Errors
///
/// `corrupted length` when the byte slice is not 56 bytes.
pub fn decode_personal_head(bytes: &[u8]) -> anyhow::Result<([u8; 16], [u8; 32], u64)> {
    let mut reader = Reader::new(bytes);
    let vault_id = reader.array::<16>()?;
    let commit_tag = reader.array::<32>()?;
    let generation = reader.u64()?;
    reader.finish()?;
    Ok((vault_id, commit_tag, generation))
}

/// Signed announcement of one device's certificate, optional `device.key` wrap id,
/// and hybrid P-256 + ML-KEM-768 public keys for personal VK rekeying.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalDeviceEntry {
    /// Device wrap identifier in the container directory (`device.key` id), if enrolled.
    pub wrap_id: Option<[u8; 16]>,
    /// Public P-256 + ML-KEM-768 keys of this device.
    pub publics: SharePublics,
    /// Account-certified ML-DSA-65 device certificate.
    pub cert: DeviceCert,
}

impl PersonalDeviceEntry {
    fn signed_message(
        vault_id: &[u8; 16],
        wrap_id: Option<[u8; 16]>,
        publics: &SharePublics,
        cert: &DeviceCert,
        cert_wire: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let has_wrap = [u8::from(wrap_id.is_some())];
        let wrap_bytes = wrap_id.unwrap_or([0u8; 16]);
        frame_parts(&[
            DOMAIN_DEVICE_ENTRY,
            vault_id,
            &cert.client_id,
            &has_wrap,
            &wrap_bytes,
            &publics.ec_pub,
            publics.kem_ek.as_slice(),
            cert_wire,
        ])
    }

    /// Issue and sign an announcement for this device under `vault_id`.
    ///
    /// # Errors
    ///
    /// Missing local certificate, invalid share keys, or signing failure.
    pub fn issue(
        identity: &SyncIdentity,
        vault_id: &[u8; 16],
        wrap_id: Option<[u8; 16]>,
    ) -> anyhow::Result<Vec<u8>> {
        let cert = identity
            .devices()
            .first()
            .ok_or_else(|| anyhow::anyhow!("missing local device certificate"))?;
        let publics = identity.share_publics()?;
        let cert_wire = encode_cert(cert)?;
        let msg = Self::signed_message(vault_id, wrap_id, &publics, cert, &cert_wire)?;
        let sig = sync_sign(identity.sign_key().seed(), PEER_CTX, &msg)?;
        let mut out = Vec::with_capacity(
            PERSONAL_DEVICE_MAGIC.len()
                + 16
                + 1
                + 16
                + 65
                + PQ_PK_LEN
                + CERT_WIRE_LEN
                + SYNC_SIG_LEN,
        );
        out.extend_from_slice(&PERSONAL_DEVICE_MAGIC);
        out.extend_from_slice(vault_id);
        out.push(u8::from(wrap_id.is_some()));
        out.extend_from_slice(&wrap_id.unwrap_or([0u8; 16]));
        out.extend_from_slice(&publics.ec_pub);
        out.extend_from_slice(publics.kem_ek.as_slice());
        out.extend_from_slice(&cert_wire);
        out.extend_from_slice(&sig);
        Ok(out)
    }

    /// Decode and cryptographically verify a signed peer device announcement
    /// against `root_vk`, `vault_id`, and wall time `now_ms`.
    ///
    /// # Errors
    ///
    /// Malformed payload, wrong vault, invalid/expired cert, or bad signature.
    pub fn verify_decode(
        bytes: &[u8],
        root_vk: &[u8; SYNC_VK_LEN],
        vault_id: &[u8; 16],
        now_ms: u64,
    ) -> anyhow::Result<Self> {
        let mut reader = Reader::new(bytes);
        let magic = reader.array::<6>()?;
        if !ct_eq(&magic, &PERSONAL_DEVICE_MAGIC) {
            return Err(corrupted());
        }
        let msg_vault = reader.array::<16>()?;
        if !ct_eq(&msg_vault, vault_id) {
            anyhow::bail!("device entry rejected");
        }
        let has_wrap = reader.array::<1>()?[0];
        let raw_wrap = reader.array::<16>()?;
        let wrap_id = match has_wrap {
            0 => None,
            1 => Some(raw_wrap),
            _ => return Err(corrupted()),
        };
        let ec_pub = reader.array::<65>()?;
        let kem_ek = Box::new(reader.array::<PQ_PK_LEN>()?);
        let cert_wire = reader.array::<CERT_WIRE_LEN>()?;
        let sig = reader.array::<SYNC_SIG_LEN>()?;
        reader.finish()?;

        let cert = decode_cert(&cert_wire)?;
        cert.verify(root_vk, now_ms)?;
        let publics = SharePublics { ec_pub, kem_ek };
        let msg = Self::signed_message(vault_id, wrap_id, &publics, &cert, &cert_wire)?;
        sync_verify(&cert.device_vk, PEER_CTX, &msg, &sig)?;
        Ok(Self {
            wrap_id,
            publics,
            cert,
        })
    }
}

fn rekey_transcript(
    vault_id: &[u8; 16],
    target_device: &[u8; 16],
    generation: u64,
    eph_ec: &[u8; 65],
    kem_ct: &[u8; KEM_CT_LEN],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN_REKEY)
        .chain_update(vault_id)
        .chain_update(target_device)
        .chain_update(generation.to_be_bytes())
        .chain_update(eph_ec)
        .chain_update(kem_ct)
        .finalize()
        .into()
}

/// Seal a newly rotated 32-byte personal vault key `vk` to one non-revoked
/// peer device using hybrid P-256 + ML-KEM-768 and Cascade (`0xA005`).
///
/// # Errors
///
/// Invalid recipient key, RNG failure, key-derivation or sealing failure.
pub fn seal_personal_rekey(
    recipient: &SharePublics,
    target_device: &[u8; 16],
    vault_id: &[u8; 16],
    generation: u64,
    vk: &Secret<[u8; 32]>,
) -> anyhow::Result<Vec<u8>> {
    let (eph_secret, eph_public) = ec::fresh_pair()?;
    let eph_ec = ec::encode_pub(&eph_public)?;
    let peer_ec = ec::decode_pub(&recipient.ec_pub)?;
    let ss_ec = Secret::new(ec::shared(&eph_secret, &peer_ec));
    let (ss_kem, kem_ct_vec) = pq::encrypt_shared(recipient.kem_ek.as_slice())?;
    let kem_ct: [u8; KEM_CT_LEN] = kem_ct_vec.try_into().map_err(|_| corrupted())?;
    let transcript = rekey_transcript(vault_id, target_device, generation, &eph_ec, &kem_ct);
    let key = kdf::personal_rekey_key(&ss_kem, &ss_ec, vault_id, &transcript)?;
    let meta = FrameMeta {
        kind: KIND_REVISION,
        record_id: REKEY_RECORD_ID,
        revision: generation,
        origin_device: *target_device,
        timestamp_ms: 0,
        alg: ALG_CASCADE,
    };
    let sealed = seal(&key, &meta, vk.expose())?;
    let sealed_len = u16::try_from(sealed.len())?;
    let mut out = Vec::with_capacity(REKEY_MAGIC.len() + 65 + KEM_CT_LEN + 2 + sealed.len());
    out.extend_from_slice(&REKEY_MAGIC);
    out.extend_from_slice(&eph_ec);
    out.extend_from_slice(&kem_ct);
    out.extend_from_slice(&sealed_len.to_be_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Decapsulate a hybrid P-256 + ML-KEM-768 personal vault-key rekey grant for
/// this device (`my_device`) at `generation`.
///
/// # Errors
///
/// Malformed grant, invalid key material, or AEAD authentication failure.
pub fn open_personal_rekey(
    keys: &ShareKeys,
    my_device: &[u8; 16],
    vault_id: &[u8; 16],
    generation: u64,
    blob: &[u8],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let mut reader = Reader::new(blob);
    let magic = reader.array::<6>()?;
    if !ct_eq(&magic, &REKEY_MAGIC) {
        return Err(corrupted());
    }
    let eph_ec = reader.array::<65>()?;
    let kem_ct = reader.array::<KEM_CT_LEN>()?;
    let sealed = reader.bytes_u16(MAX_REKEY_SEALED)?;
    reader.finish()?;

    let ec_sk = keys.ec_secret()?;
    let peer_ec = ec::decode_pub(&eph_ec)?;
    let ss_ec = Secret::new(ec::shared(&ec_sk, &peer_ec));
    let ss_kem = pq::decrypt_shared(keys.kem_seed().expose(), &kem_ct)?;
    let transcript = rekey_transcript(vault_id, my_device, generation, &eph_ec, &kem_ct);
    let key = kdf::personal_rekey_key(&ss_kem, &ss_ec, vault_id, &transcript)?;
    let meta = frame::parse(sealed)?;
    if meta.alg != ALG_CASCADE
        || meta.record_id != REKEY_RECORD_ID
        || meta.revision != generation
        || !ct_eq(&meta.origin_device, my_device)
    {
        anyhow::bail!("rekey grant rejected");
    }
    let plain = open(&key, sealed)?;
    if plain.expose().len() != 32 {
        return Err(corrupted());
    }
    let mut vk = Secret::new([0u8; 32]);
    vk.expose_mut().copy_from_slice(plain.expose());
    Ok(vk)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use secret::Secret;

    use super::{
        PERSONAL_HEAD_LEN, PersonalDeviceEntry, decode_personal_head, encode_personal_head,
        open_personal_rekey, seal_personal_rekey,
    };
    use crate::SyncIdentity;

    #[test]
    fn head_device_entry_and_hybrid_rekey_roundtrip() {
        let seed = [0x42u8; 64];
        let vault_id = [0x11u8; 16];
        let commit = [0x22u8; 32];
        let encoded_head = encode_personal_head(&vault_id, &commit, 7);
        assert_eq!(encoded_head.len(), PERSONAL_HEAD_LEN);
        assert_eq!(
            decode_personal_head(&encoded_head).unwrap(),
            (vault_id, commit, 7)
        );

        let client_id = kdf::client_id(&seed).unwrap();
        let dev_b = [0xBBu8; 16];
        let id_b = SyncIdentity::enroll(&seed, &client_id, dev_b, u64::MAX).unwrap();
        let wrap_id = [0xCCu8; 16];
        let wire = PersonalDeviceEntry::issue(&id_b, &vault_id, Some(wrap_id)).unwrap();
        let parsed =
            PersonalDeviceEntry::verify_decode(&wire, id_b.root_vk(), &vault_id, 1000).unwrap();
        assert_eq!(parsed.wrap_id, Some(wrap_id));
        assert_eq!(parsed.cert.device_id, dev_b);

        let new_vk = Secret::new([0x99u8; 32]);
        let grant = seal_personal_rekey(&parsed.publics, &dev_b, &vault_id, 8, &new_vk).unwrap();
        let opened = open_personal_rekey(id_b.share_keys(), &dev_b, &vault_id, 8, &grant).unwrap();
        assert_eq!(opened.expose(), new_vk.expose());
        assert!(open_personal_rekey(id_b.share_keys(), &dev_b, &vault_id, 9, &grant).is_err());
    }
}
