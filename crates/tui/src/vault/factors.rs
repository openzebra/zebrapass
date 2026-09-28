//! Factor views built from the public wrap directory. No secret is involved:
//! this is what the unlock chips, the constellation, and the device list
//! draw from.

use session::{Factor, WrapDirectory};

use crate::vault::chip::Chips;

/// Kind of unlock factor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactorKind {
    /// Seed-phrase recovery wrap.
    Recovery,
    /// Human password wrap.
    Password,
    /// Device wrap (X25519 + ML-KEM).
    Device,
    /// Chip wrap (P-256 + ML-KEM).
    Chip,
    /// Hardware key (FIDO2 PRF).
    HwKey,
}

impl FactorKind {
    /// Display noun.
    #[must_use]
    pub const fn noun(self) -> &'static str {
        match self {
            Self::Recovery => "recovery phrase",
            Self::Password => "password",
            Self::Device => "device",
            Self::Chip => "secure chip",
            Self::HwKey => "hardware key",
        }
    }

    /// Whether the wrap uses the post-quantum hybrid KEM.
    #[must_use]
    pub const fn post_quantum(self) -> bool {
        matches!(self, Self::Device | Self::Chip)
    }

    /// Primitive summary shown next to the factor.
    #[must_use]
    pub const fn primitive(self) -> &'static str {
        match self {
            Self::Recovery => "BIP39 seed wrap",
            Self::Password => "Argon2id → KEK",
            Self::Device => "X25519 + ML-KEM hybrid",
            Self::Chip => "P-256 + ML-KEM hybrid",
            Self::HwKey => "FIDO2 PRF",
        }
    }
}

/// One factor as the UI lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactorView {
    /// Wrap id, for kinds that carry one.
    pub id: Option<[u8; 16]>,
    /// Kind.
    pub kind: FactorKind,
    /// This device holds the key (chips and devices).
    pub owned: bool,
    /// Argon2id cost, for password wraps.
    pub cost: Option<(u32, u32, u32)>,
}

/// Which factor kinds a vault has.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Presence {
    /// Devices.
    pub devices: usize,
    /// Devices whose keys this device holds.
    pub owned_devices: usize,
    /// Chips.
    pub chips: usize,
    /// Chips this process owns.
    pub owned_chips: usize,
    /// Hardware keys.
    pub hw_keys: usize,
    /// Recovery wrap present.
    pub recovery: bool,
    /// Password wrap present.
    pub password: bool,
}

/// Views in file order.
#[must_use]
pub fn views(directory: &WrapDirectory, chips: &Chips) -> Vec<FactorView> {
    directory
        .factors
        .iter()
        .map(|factor| match factor {
            Factor::Recovery => FactorView {
                id: None,
                kind: FactorKind::Recovery,
                owned: false,
                cost: None,
            },
            Factor::Password { m_kib, t, p } => FactorView {
                id: None,
                kind: FactorKind::Password,
                owned: false,
                cost: Some((*m_kib, *t, *p)),
            },
            Factor::Device { id } => FactorView {
                id: Some(*id),
                kind: FactorKind::Device,
                owned: chips.keyring().owns(id),
                cost: None,
            },
            Factor::Chip(chip) => FactorView {
                id: Some(chip.publics.id),
                kind: FactorKind::Chip,
                owned: chips.owns(&chip.publics.id),
                cost: None,
            },
            Factor::Prf { id } => FactorView {
                id: Some(*id),
                kind: FactorKind::HwKey,
                owned: false,
                cost: None,
            },
        })
        .collect()
}

/// Count factor kinds.
#[must_use]
pub fn presence(directory: &WrapDirectory, chips: &Chips) -> Presence {
    views(directory, chips)
        .iter()
        .fold(Presence::default(), |mut acc, view| {
            match view.kind {
                FactorKind::Recovery => acc.recovery = true,
                FactorKind::Password => acc.password = true,
                FactorKind::Device => {
                    acc.devices += 1;
                    acc.owned_devices += usize::from(view.owned);
                }
                FactorKind::Chip => {
                    acc.chips += 1;
                    acc.owned_chips += usize::from(view.owned);
                }
                FactorKind::HwKey => acc.hw_keys += 1,
            }
            acc
        })
}
