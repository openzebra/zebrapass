//! Public wrap-directory metadata, readable without unlocking.
//!
//! Everything here comes from the unauthenticated wrap directory through the
//! bounded container parse. None of it opens the vault: it tells a UI which
//! kinds of factor exist so it can ask for the right one, and it carries the
//! chip publics a rotation re-seals to.

use container::{VaultFile, WrapEntry};
use wraps::ChipPublics;

/// A chip wrap's public half.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChipFactor {
    /// Publics a rotation re-seals the vault key to.
    pub publics: ChipPublics,
    /// Ephemeral P-256 key the platform runs `ECDH(chip_sk, eph_pub)` against.
    pub eph_pub: [u8; 65],
}

/// One unlock factor listed in the wrap directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Factor {
    /// The recovery wrap sealed under the seed phrase (kind `0x0001`).
    Recovery,
    /// A human-chosen password wrap (kind `0x0005`) and its Argon2id cost.
    Password {
        /// Memory in KiB.
        m_kib: u32,
        /// Passes.
        t: u32,
        /// Lanes.
        p: u32,
    },
    /// A device wrap (kind `0x0002`).
    Device {
        /// Device id.
        id: [u8; 16],
    },
    /// A chip wrap (kind `0x0003`).
    Chip(Box<ChipFactor>),
    /// A hardware-key PRF wrap (kind `0x0004`).
    Prf {
        /// Grant id.
        id: [u8; 16],
    },
}

impl From<&WrapEntry<'_>> for Factor {
    fn from(entry: &WrapEntry<'_>) -> Self {
        match entry {
            WrapEntry::Password(_) => Self::Recovery,
            WrapEntry::HumanPassword(wrap) => Self::Password {
                m_kib: wrap.kdf.m_kib,
                t: wrap.kdf.t,
                p: wrap.kdf.p,
            },
            WrapEntry::Device(wrap) => Self::Device { id: wrap.device_id },
            WrapEntry::Chip(wrap) => Self::Chip(Box::new(ChipFactor {
                publics: ChipPublics {
                    id: wrap.id,
                    chip_pub: wrap.chip_pub,
                    pq_pk: wrap.pq_pk,
                },
                eph_pub: wrap.eph_pub,
            })),
            WrapEntry::Prf(wrap) => Self::Prf { id: wrap.id },
        }
    }
}

/// The wrap directory of a vault file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrapDirectory {
    /// Directory generation as stored. Unauthenticated until unlock.
    pub generation: u64,
    /// Factors in file order.
    pub factors: Box<[Factor]>,
}

/// Read the wrap directory of `file` without unlocking it.
///
/// # Errors
///
/// Container parse errors, with the same messages and limits as
/// [`crate::unlock`] (`corrupted length`, `kdf parameters rejected`,
/// `no password wrap`, `unsupported body algorithm`).
pub fn wrap_directory(file: &VaultFile) -> anyhow::Result<WrapDirectory> {
    let parsed = file.parse()?;
    let factors = parsed
        .entries
        .iter()
        .map(Factor::from)
        .collect::<Box<[_]>>();
    Ok(WrapDirectory {
        generation: parsed.generation,
        factors,
    })
}
