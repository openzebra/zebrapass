//! The unencrypted outer header of a `KeePass` database, read only to learn
//! and bound the key-derivation cost before anything runs it.

use crate::limits::{
    MAX_KDBX_AES_ROUNDS, MAX_KDBX_ARGON2_ITERATIONS, MAX_KDBX_ARGON2_LANES, MAX_KDBX_ARGON2_MEMORY,
    MAX_KDBX_ARGON2_WORK_MIB,
};

const SIGNATURE: [u8; 4] = [0x03, 0xD9, 0xA2, 0x9A];
/// `KeePass` 1.x (`.kdb`).
const KDB_ID: u32 = 0xB54B_FB65;
/// `KeePass` 2.x pre-release and 2.x (`.kdbx`).
const KDBX_IDS: [u32; 2] = [0xB54B_FB66, 0xB54B_FB67];
/// Offset of the transform rounds in a `.kdb` header.
const KDB_ROUNDS_AT: usize = 120;

const END: u8 = 0;
const KDBX3_TRANSFORM_ROUNDS: u8 = 6;
const KDBX4_KDF_PARAMS: u8 = 11;
/// Most header fields read before giving up.
const MAX_FIELDS: usize = 64;
/// Most variant-dictionary entries read before giving up.
const MAX_ENTRIES: usize = 32;

const ARGON2D: [u8; 16] = [
    0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C,
];
const ARGON2ID: [u8; 16] = [
    0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6,
];
const AES_KDF: [u8; 16] = [
    0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA,
];
const AES_KDF_KDBX3: [u8; 16] = [
    0x7C, 0x02, 0xBB, 0x82, 0x79, 0xA7, 0x4A, 0xC0, 0x92, 0x7D, 0x11, 0x4A, 0x00, 0x64, 0x82, 0x38,
];

/// Key-derivation cost announced by an untrusted header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfCost {
    /// Argon2d or Argon2id.
    Argon2 {
        /// Memory in bytes.
        memory: u64,
        /// Passes.
        iterations: u64,
        /// Lanes.
        lanes: u32,
    },
    /// Repeated AES.
    Aes {
        /// Rounds.
        rounds: u64,
    },
}

/// The KDF cost of the database in `bytes`.
///
/// # Errors
///
/// `not a KeePass database` for a missing signature or a truncated or
/// malformed header; `unsupported KeePass version`; `unknown key derivation`.
pub fn kdf_cost(bytes: &[u8]) -> anyhow::Result<KdfCost> {
    if bytes.get(..4) != Some(SIGNATURE.as_slice()) {
        anyhow::bail!("not a KeePass database");
    }
    let id = u32_at(bytes, 4)?;
    if id == KDB_ID {
        let rounds = u32_at(bytes, KDB_ROUNDS_AT)?;
        return Ok(KdfCost::Aes {
            rounds: u64::from(rounds),
        });
    }
    if !KDBX_IDS.contains(&id) {
        anyhow::bail!("unsupported KeePass version");
    }
    match u16_at(bytes, 10)? {
        0..=3 => kdbx3(bytes),
        4 => kdbx4(bytes),
        _ => anyhow::bail!("unsupported KeePass version"),
    }
}

/// Refuse a cost this application will not pay.
///
/// # Errors
///
/// `unlock cost too high` with the setting to lower.
pub fn check(cost: KdfCost) -> anyhow::Result<()> {
    let fits = match cost {
        KdfCost::Argon2 {
            memory,
            iterations,
            lanes,
        } => {
            let work = (memory / (1024 * 1024)).saturating_mul(iterations);
            memory <= MAX_KDBX_ARGON2_MEMORY
                && iterations <= MAX_KDBX_ARGON2_ITERATIONS
                && lanes <= MAX_KDBX_ARGON2_LANES
                && work <= MAX_KDBX_ARGON2_WORK_MIB
        }
        KdfCost::Aes { rounds } => rounds <= MAX_KDBX_AES_ROUNDS,
    };
    if fits {
        Ok(())
    } else {
        anyhow::bail!(
            "unlock cost too high: lower it in KeePassXC (Database → Security → Encryption settings) and export again"
        )
    }
}

/// `KeePass` 2.x up to 3.1: `u8 id ‖ u16 len ‖ data` fields.
fn kdbx3(bytes: &[u8]) -> anyhow::Result<KdfCost> {
    let mut pos = 12usize;
    for _ in 0..MAX_FIELDS {
        let id = u8_at(bytes, pos)?;
        let len = usize::from(u16_at(bytes, pos + 1)?);
        let data = slice(bytes, pos + 3, len)?;
        match id {
            END => break,
            KDBX3_TRANSFORM_ROUNDS => {
                return Ok(KdfCost::Aes {
                    rounds: u64_at(data, 0)?,
                })
            }
            _ => pos = pos + 3 + len,
        }
    }
    anyhow::bail!("not a KeePass database")
}

/// `KeePass` 4.x: `u8 id ‖ u32 len ‖ data` fields; KDF parameters are a
/// variant dictionary.
fn kdbx4(bytes: &[u8]) -> anyhow::Result<KdfCost> {
    let mut pos = 12usize;
    for _ in 0..MAX_FIELDS {
        let id = u8_at(bytes, pos)?;
        let len = usize::try_from(u32_at(bytes, pos + 1)?)
            .map_err(|_| anyhow::anyhow!("not a KeePass database"))?;
        let data = slice(bytes, pos + 5, len)?;
        match id {
            END => break,
            KDBX4_KDF_PARAMS => return kdf_params(data),
            _ => pos = pos + 5 + len,
        }
    }
    anyhow::bail!("not a KeePass database")
}

/// `u16 version ‖ (u8 type ‖ u32 key_len ‖ key ‖ u32 len ‖ value)* ‖ 0`.
fn kdf_params(dict: &[u8]) -> anyhow::Result<KdfCost> {
    if u16_at(dict, 0)? >> 8 > 1 {
        anyhow::bail!("unsupported KeePass version");
    }
    let (mut uuid, mut memory, mut iterations, mut lanes, mut rounds) =
        (None, None, None, None, None);
    let mut pos = 2usize;
    for _ in 0..MAX_ENTRIES {
        if u8_at(dict, pos)? == END {
            break;
        }
        let key_len = usize::try_from(u32_at(dict, pos + 1)?)
            .map_err(|_| anyhow::anyhow!("not a KeePass database"))?;
        let key = slice(dict, pos + 5, key_len)?;
        let value_at = pos + 5 + key_len;
        let value_len = usize::try_from(u32_at(dict, value_at)?)
            .map_err(|_| anyhow::anyhow!("not a KeePass database"))?;
        let value = slice(dict, value_at + 4, value_len)?;
        match key {
            b"$UUID" => uuid = <[u8; 16]>::try_from(value).ok(),
            b"M" => memory = Some(u64_at(value, 0)?),
            b"I" => iterations = Some(u64_at(value, 0)?),
            b"P" => lanes = Some(u32_at(value, 0)?),
            b"R" => rounds = Some(u64_at(value, 0)?),
            _ => {}
        }
        pos = value_at + 4 + value_len;
    }
    match uuid {
        Some(ARGON2D | ARGON2ID) => Ok(KdfCost::Argon2 {
            memory: memory.ok_or_else(|| anyhow::anyhow!("not a KeePass database"))?,
            iterations: iterations.ok_or_else(|| anyhow::anyhow!("not a KeePass database"))?,
            lanes: lanes.ok_or_else(|| anyhow::anyhow!("not a KeePass database"))?,
        }),
        Some(AES_KDF | AES_KDF_KDBX3) => Ok(KdfCost::Aes {
            rounds: rounds.ok_or_else(|| anyhow::anyhow!("not a KeePass database"))?,
        }),
        Some(_) | None => anyhow::bail!("unknown key derivation"),
    }
}

fn slice(bytes: &[u8], at: usize, len: usize) -> anyhow::Result<&[u8]> {
    at.checked_add(len)
        .and_then(|end| bytes.get(at..end))
        .ok_or_else(|| anyhow::anyhow!("not a KeePass database"))
}

fn u8_at(bytes: &[u8], at: usize) -> anyhow::Result<u8> {
    bytes
        .get(at)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("not a KeePass database"))
}

fn u16_at(bytes: &[u8], at: usize) -> anyhow::Result<u16> {
    let raw = slice(bytes, at, 2)?;
    Ok(u16::from_le_bytes(raw.try_into()?))
}

fn u32_at(bytes: &[u8], at: usize) -> anyhow::Result<u32> {
    let raw = slice(bytes, at, 4)?;
    Ok(u32::from_le_bytes(raw.try_into()?))
}

fn u64_at(bytes: &[u8], at: usize) -> anyhow::Result<u64> {
    let raw = slice(bytes, at, 8)?;
    Ok(u64::from_le_bytes(raw.try_into()?))
}
