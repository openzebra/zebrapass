//! The PIN-sealed device key file: this device's P-256 scalar and ML-KEM
//! seed for the vault's device wrap (a chip-kind wrap on the wire).
//!
//! Layout: `"ZPDK" ‖ version u16 BE ‖ profile u8 ‖ wrap id[16] ‖ salt[32] ‖
//! cascade frame(p256 scalar ‖ ML-KEM seed)`. The frame key is
//! `HKDF(Argon2id(PIN, salt, profile), vault_id, INFO_DEVICE_KEY_FILE ‖
//! u16 len ‖ file header)`, so every header byte is bound into the key. The
//! wrap id and profile are public (the id is in the vault file too) and can
//! be read without the PIN. The file lives next to the vault and never
//! syncs: opening the vault this way takes both this disk and the PIN.

use std::fmt;
use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use ec::{decode_pub, pair_from_scalar, shared};
use frame::{FrameMeta, ALG_CASCADE, CASCADE_OVERHEAD, HEADER_LEN, KIND_REVISION, TAG_LEN};
use kdf::{argon2id, device_key_file_key, KdfProfile};
use pq::{keypair_from_seed, PQ_PK_LEN, PQ_SK_LEN};
use secret::Secret;
use session::{ChipKeys, ChipPublics};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::limits::DEVICE_PIN_LEN;
use crate::write_atomic;

const MAGIC: [u8; 4] = *b"ZPDK";
const VERSION: u16 = 1;
const FILE_HEADER_LEN: usize = MAGIC.len() + 2 + 1 + 16 + 32;
const PLAIN_LEN: usize = 32 + PQ_SK_LEN;

/// Exact size of a device key file; any other length is rejected unread.
pub const DEVICE_KEY_FILE_LEN: usize =
    FILE_HEADER_LEN + HEADER_LEN + PLAIN_LEN + CASCADE_OVERHEAD + TAG_LEN;

const FRAME_META: FrameMeta = FrameMeta {
    kind: KIND_REVISION,
    record_id: 0,
    revision: 1,
    origin_device: [0; 16],
    timestamp_ms: 0,
    alg: ALG_CASCADE,
};

/// The public header of a device key file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceKeyInfo {
    /// The device wrap this file opens.
    pub id: [u8; 16],
    /// Argon2id preset the PIN is stretched with.
    pub profile: KdfProfile,
}

/// This device's private half of its device wrap.
pub struct DeviceKey {
    p256_sk: Secret<[u8; 32]>,
    chip: ChipKeys,
}

impl ZeroizeOnDrop for DeviceKey {}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceKey([REDACTED])")
    }
}

impl DeviceKey {
    /// Draw a fresh wrap id, P-256 scalar and ML-KEM seed from the OS RNG.
    ///
    /// # Errors
    ///
    /// `os entropy failed` when the OS RNG fails.
    pub fn generate() -> anyhow::Result<Self> {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|_| entropy_failed())?;
        let mut pq_sk = Secret::new([0u8; PQ_SK_LEN]);
        getrandom::fill(pq_sk.expose_mut()).map_err(|_| entropy_failed())?;
        Ok(Self {
            p256_sk: random_scalar()?,
            chip: ChipKeys { id, pq_sk },
        })
    }

    /// The wrap id this key opens.
    #[must_use]
    pub const fn id(&self) -> &[u8; 16] {
        &self.chip.id
    }

    /// The ML-KEM half, as [`session::UnlockCreds::with_chip`] takes it.
    #[must_use]
    pub const fn chip_keys(&self) -> &ChipKeys {
        &self.chip
    }

    /// Public keys for [`session::add_chip_unlock`].
    ///
    /// # Errors
    ///
    /// `kem length` when a derived public key has an unexpected length.
    pub fn publics(&self) -> anyhow::Result<ChipPublics> {
        let (_, point) = pair_from_scalar(&self.p256_sk)?;
        let mut chip_pub = [0x04u8; 65];
        let (_, body) = chip_pub
            .split_first_mut()
            .ok_or_else(|| anyhow::anyhow!("kem length"))?;
        body.copy_from_slice(&point);
        let (pq_public, _) = keypair_from_seed(self.chip.pq_sk.expose());
        let pq_pk: [u8; PQ_PK_LEN] = pq_public
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("kem length"))?;
        Ok(ChipPublics {
            id: self.chip.id,
            chip_pub,
            pq_pk,
        })
    }

    /// `ECDH(p256_sk, peer)`: the P-256 half of opening the device wrap.
    ///
    /// # Errors
    ///
    /// `kem length` when `peer` is not an uncompressed P-256 point.
    pub fn ecdh(&self, peer: &[u8; 65]) -> anyhow::Result<Secret<[u8; 32]>> {
        let (sk, _) = pair_from_scalar(&self.p256_sk)?;
        Ok(Secret::new(shared(&sk, &decode_pub(peer)?)))
    }
}

/// Seal `key` under `pin` into `path`, bound to `vault_id`.
///
/// # Errors
///
/// `device PIN length` when `pin` is outside [`DEVICE_PIN_LEN`]; entropy,
/// KDF, frame and atomic-write errors.
pub fn seal_device_key(
    path: &Path,
    vault_id: &[u8; 16],
    key: &DeviceKey,
    pin: &[u8],
    profile: KdfProfile,
) -> anyhow::Result<()> {
    check_pin(pin)?;
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).map_err(|_| entropy_failed())?;
    let info = DeviceKeyInfo {
        id: key.chip.id,
        profile,
    };
    let header = encode_header(&info, &salt);
    let file_key = file_key(pin, vault_id, &header, profile, &salt)?;
    let mut plain = Zeroizing::new([0u8; PLAIN_LEN]);
    let (scalar, seed) = plain
        .split_first_chunk_mut::<32>()
        .ok_or_else(auth_failed)?;
    scalar.copy_from_slice(key.p256_sk.expose());
    seed.copy_from_slice(key.chip.pq_sk.expose());
    let sealed = frame::seal(&file_key, &FRAME_META, plain.as_slice())?;
    let mut out = Vec::with_capacity(DEVICE_KEY_FILE_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&sealed);
    write_atomic(path, &out)
}

/// Open the device key file at `path` with `pin`.
///
/// # Errors
///
/// `device PIN length` when `pin` is outside [`DEVICE_PIN_LEN`];
/// `device key unreadable` when the file cannot be read; one uniform
/// `device key authentication failed` for a wrong PIN, another vault, an
/// unknown profile or version, truncation, or any modified byte.
pub fn open_device_key(path: &Path, vault_id: &[u8; 16], pin: &[u8]) -> anyhow::Result<DeviceKey> {
    check_pin(pin)?;
    let bytes = read_bounded(path)?;
    if bytes.len() != DEVICE_KEY_FILE_LEN {
        return Err(auth_failed());
    }
    let (header, sealed) = bytes
        .split_first_chunk::<FILE_HEADER_LEN>()
        .ok_or_else(auth_failed)?;
    let (info, salt) = parse_header(header)?;
    if frame::parse(sealed).map_err(|_| auth_failed())?.alg != ALG_CASCADE {
        return Err(auth_failed());
    }
    let file_key = file_key(pin, vault_id, header, info.profile, &salt)?;
    let plain = frame::open(&file_key, sealed).map_err(|_| auth_failed())?;
    decode_plain(info.id, plain.expose())
}

/// Read the public header of the device key file at `path` without the PIN.
///
/// Unauthenticated until [`open_device_key`] succeeds: use it to pick the
/// wrap to try, never to decide trust.
///
/// # Errors
///
/// `device key unreadable` when the file cannot be read;
/// `device key authentication failed` when it is not a device key file.
pub fn device_key_info(path: &Path) -> anyhow::Result<DeviceKeyInfo> {
    let bytes = read_bounded(path)?;
    if bytes.len() != DEVICE_KEY_FILE_LEN {
        return Err(auth_failed());
    }
    let header = bytes
        .first_chunk::<FILE_HEADER_LEN>()
        .ok_or_else(auth_failed)?;
    parse_header(header).map(|(info, _)| info)
}

fn check_pin(pin: &[u8]) -> anyhow::Result<()> {
    if DEVICE_PIN_LEN.contains(&pin.len()) {
        Ok(())
    } else {
        Err(anyhow::anyhow!("device PIN length"))
    }
}

fn read_bounded(path: &Path) -> anyhow::Result<Vec<u8>> {
    let unreadable = || anyhow::anyhow!("device key unreadable");
    let limit = u64::try_from(DEVICE_KEY_FILE_LEN + 1).map_err(|_| unreadable())?;
    let mut bytes = Vec::with_capacity(DEVICE_KEY_FILE_LEN + 1);
    File::open(path)
        .map_err(|_| unreadable())?
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable())?;
    Ok(bytes)
}

fn encode_header(info: &DeviceKeyInfo, salt: &[u8; 32]) -> [u8; FILE_HEADER_LEN] {
    let mut header = [0u8; FILE_HEADER_LEN];
    MAGIC
        .iter()
        .chain(&VERSION.to_be_bytes())
        .chain(&[u8::from(info.profile)])
        .chain(&info.id)
        .chain(salt)
        .zip(header.iter_mut())
        .for_each(|(src, dst)| *dst = *src);
    header
}

fn parse_header(header: &[u8; FILE_HEADER_LEN]) -> anyhow::Result<(DeviceKeyInfo, [u8; 32])> {
    let (magic, rest) = header.split_first_chunk::<4>().ok_or_else(auth_failed)?;
    let (version, rest) = rest.split_first_chunk::<2>().ok_or_else(auth_failed)?;
    let (profile, rest) = rest.split_first().ok_or_else(auth_failed)?;
    let (id, salt) = rest.split_first_chunk::<16>().ok_or_else(auth_failed)?;
    if *magic != MAGIC || u16::from_be_bytes(*version) != VERSION {
        return Err(auth_failed());
    }
    // The profile is checked against the allow-list before Argon2 runs.
    let profile = KdfProfile::try_from(*profile).map_err(|_| auth_failed())?;
    let salt = <[u8; 32]>::try_from(salt).map_err(|_| auth_failed())?;
    Ok((DeviceKeyInfo { id: *id, profile }, salt))
}

fn file_key(
    pin: &[u8],
    vault_id: &[u8; 16],
    header: &[u8],
    profile: KdfProfile,
    salt: &[u8; 32],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let stretched = argon2id(pin, salt, profile.m_kib(), profile.t(), profile.p())?;
    device_key_file_key(stretched.expose(), vault_id, header)
}

fn decode_plain(id: [u8; 16], plain: &[u8]) -> anyhow::Result<DeviceKey> {
    let (scalar, seed) = plain.split_first_chunk::<32>().ok_or_else(auth_failed)?;
    if seed.len() != PQ_SK_LEN {
        return Err(auth_failed());
    }
    let mut p256_sk = Secret::new([0u8; 32]);
    p256_sk.expose_mut().copy_from_slice(scalar);
    let mut pq_sk = Secret::new([0u8; PQ_SK_LEN]);
    pq_sk.expose_mut().copy_from_slice(seed);
    Ok(DeviceKey {
        p256_sk,
        chip: ChipKeys { id, pq_sk },
    })
}

fn random_scalar() -> anyhow::Result<Secret<[u8; 32]>> {
    let mut scalar = Secret::new([0u8; 32]);
    // Rejection sampling: almost every 32-byte draw is a valid scalar.
    for _ in 0..8 {
        getrandom::fill(scalar.expose_mut()).map_err(|_| entropy_failed())?;
        if pair_from_scalar(&scalar).is_ok() {
            return Ok(scalar);
        }
    }
    Err(entropy_failed())
}

fn entropy_failed() -> anyhow::Error {
    anyhow::anyhow!("os entropy failed")
}

fn auth_failed() -> anyhow::Error {
    anyhow::anyhow!("device key authentication failed")
}
