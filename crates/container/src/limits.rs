//! Wire constants, Argon2 bounds, and bounds-checked reads.
//!
//! Reads go through `get` so a short or hostile file yields an error, not a panic.


/// File magic `BRBY`.
pub const MAGIC: [u8; 4] = *b"BRBY";

/// Container version written by this format.
pub const VERSION: u16 = 2;

/// Argon2id `kdf_alg`.
pub const KDF_ARGON2ID: u16 = 0x0001;

/// AEGIS-256 body, tag 32 (`0xA001`).
pub const BODY_AEGIS256: u16 = 0xA001;

/// Kuznyechik-MGM body (`0xA002`). Recognized here; decryption is elsewhere.
pub const BODY_KUZ_MGM: u16 = 0xA002;

/// Kuznyechik-CTR + HMAC-SHA256 body (`0xA003`).
pub const BODY_KUZ_CTR_HMAC: u16 = 0xA003;

/// AEGIS-256 wrap (`0xB001`).
pub const WRAP_AEGIS256: u16 = 0xB001;

/// Password wrap kind.
pub const KIND_PASSWORD: u16 = 0x0001;

/// Device wrap kind.
pub const KIND_DEVICE: u16 = 0x0002;

/// `ntrulp` device KEM (`ntrup761`).
pub const KEM_NTRULP: u16 = 0xC001;

/// Body associated-data domain.
pub const DOMAIN_BODY: &[u8] = b"brby/v2/body";

/// Password-wrap associated-data domain.
pub const DOMAIN_WRAP_PASSWORD: &[u8] = b"brby/v2/wrap-password";

/// Device-wrap associated-data domain.
pub const DOMAIN_WRAP_DEVICE: &[u8] = b"brby/v2/wrap-device";

/// Static header size in bytes.
pub const HEADER_LEN: usize = 72;

/// Trailing commit tag size in bytes.
pub const COMMIT_LEN: usize = 32;

/// Minimum file size: header plus commit, with nothing between them.
pub const MIN_FILE_LEN: usize = HEADER_LEN + COMMIT_LEN;

/// `wrap_count` (u16) + `generation` (u64).
pub const WRAP_DIR_HEADER_LEN: usize = 2 + 8;

/// `kind` (u16) + `entry_len` (u32).
pub const ENTRY_HEADER_LEN: usize = 2 + 4;

/// Password payload after `entry_len`: kid, nonce, ct, tag.
pub const PASSWORD_PAYLOAD_LEN: usize = 104;

/// Password record on the wire, including kind and `entry_len`.
pub const PASSWORD_RECORD_LEN: usize = ENTRY_HEADER_LEN + PASSWORD_PAYLOAD_LEN;

/// Device fields before the `ntrulp` ciphertext: id, kem, two X25519 keys.
pub const DEVICE_PREFIX_LEN: usize = 82;

/// Device fields after the `ntrulp` ciphertext: nonce, AEGIS ct, AEGIS tag.
pub const DEVICE_SUFFIX_LEN: usize = 96;

/// Shortest device payload: prefix, one ciphertext byte, suffix.
pub const DEVICE_PAYLOAD_MIN: usize = DEVICE_PREFIX_LEN + 1 + DEVICE_SUFFIX_LEN;

const BODY_MIN_AEGIS: usize = 64;
const BODY_MIN_KUZ_MGM: usize = 32;
const BODY_MIN_KUZ_CTR: usize = 40;

/// Inclusive Argon2id memory floor, in KiB (19 MiB).
pub const KDF_M_KIB_MIN: u32 = 19_456;

/// Inclusive Argon2id memory ceiling, in KiB (1 GiB).
pub const KDF_M_KIB_MAX: u32 = 1_048_576;

/// Inclusive Argon2id time floor.
pub const KDF_T_MIN: u32 = 2;

/// Inclusive Argon2id time ceiling.
pub const KDF_T_MAX: u32 = 16;

/// Inclusive Argon2id parallelism floor.
pub const KDF_P_MIN: u32 = 1;

/// Inclusive Argon2id parallelism ceiling.
pub const KDF_P_MAX: u32 = 16;

const _: () = {
    assert!(MIN_FILE_LEN == 104);
    assert!(PASSWORD_RECORD_LEN == 110);
    assert!(DEVICE_PREFIX_LEN == 16 + 2 + 32 + 32);
    assert!(DEVICE_SUFFIX_LEN == 32 + 32 + 32);
    assert!(8 + 32 + 32 + 32 == PASSWORD_PAYLOAD_LEN);
    assert!(BODY_MIN_AEGIS == 32 + 32);
    assert!(BODY_MIN_KUZ_MGM == 16 + 16);
    assert!(BODY_MIN_KUZ_CTR == 8 + 32);
};

/// `true` when memory, time, and parallelism are inside the floor and ceiling.
pub const fn kdf_params_ok(m_kib: u32, t: u32, p: u32) -> bool {
    m_kib >= KDF_M_KIB_MIN
        && m_kib <= KDF_M_KIB_MAX
        && t >= KDF_T_MIN
        && t <= KDF_T_MAX
        && p >= KDF_P_MIN
        && p <= KDF_P_MAX
}

pub const fn known_body_alg(alg: u16) -> bool {
    matches!(alg, BODY_AEGIS256 | BODY_KUZ_MGM | BODY_KUZ_CTR_HMAC)
}

/// Minimum body length: nonce plus tag, allowing an empty ciphertext.
pub const fn min_body_len(alg: u16) -> Option<usize> {
    match alg {
        BODY_AEGIS256 => Some(BODY_MIN_AEGIS),
        BODY_KUZ_MGM => Some(BODY_MIN_KUZ_MGM),
        BODY_KUZ_CTR_HMAC => Some(BODY_MIN_KUZ_CTR),
        _ => None,
    }
}

pub fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> anyhow::Result<[u8; N]> {
    Ok(*read_ref(bytes, offset)?)
}

pub fn read_ref<const N: usize>(bytes: &[u8], offset: usize) -> anyhow::Result<&[u8; N]> {
    let end = offset.checked_add(N).ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let slice = bytes.get(offset..end).ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    slice.first_chunk::<N>().ok_or_else(|| anyhow::anyhow!("corrupted length"))
}

pub fn read_u16(bytes: &[u8], offset: usize) -> anyhow::Result<u16> {
    Ok(u16::from_le_bytes(read_array(bytes, offset)?))
}

pub fn read_u32(bytes: &[u8], offset: usize) -> anyhow::Result<u32> {
    Ok(u32::from_le_bytes(read_array(bytes, offset)?))
}

pub fn read_u64(bytes: &[u8], offset: usize) -> anyhow::Result<u64> {
    Ok(u64::from_le_bytes(read_array(bytes, offset)?))
}

/// Little-endian `u32` length. A value that does not fit becomes four zero bytes,
/// which later fails the fixed-size check instead of truncating.
pub fn wire_len(len: usize) -> [u8; 4] {
    u32::try_from(len).map_or([0; 4], u32::to_le_bytes)
}

/// Copy `parts` into a fixed array when their lengths sum to `N`.
pub fn concat_array<const N: usize>(parts: &[&[u8]]) -> [u8; N] {
    let mut out = [0u8; N];
    let Some(total) = parts
        .iter()
        .try_fold(0usize, |acc, part| acc.checked_add(part.len()))
    else {
        return out;
    };
    if total != N {
        return out;
    }
    let mut offset = 0usize;
    for part in parts {
        let end = offset.saturating_add(part.len());
        if let Some(slot) = out.get_mut(offset..end) {
            slot.copy_from_slice(part);
        }
        offset = end;
    }
    out
}

pub fn shift(base: usize, rel: usize) -> anyhow::Result<usize> {
    base.checked_add(rel).ok_or_else(|| anyhow::anyhow!("corrupted length"))
}
