//! Factor views built from the public wrap directory. No secret is involved:
//! this is what the unlock chips, the constellation, and the device list
//! draw from.

use session::{Factor, WrapDirectory};

/// Kind of unlock factor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactorKind {
    /// Seed-phrase recovery wrap.
    Recovery,
    /// Human password wrap.
    Password,
    /// Device wrap (P-256 + ML-KEM), keys in a PIN-sealed file or a chip.
    Device,
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
            Self::HwKey => "hardware key",
        }
    }

    /// Whether the wrap uses the post-quantum hybrid KEM.
    #[must_use]
    pub const fn post_quantum(self) -> bool {
        matches!(self, Self::Device)
    }

    /// Primitive summary shown next to the factor.
    #[must_use]
    pub const fn primitive(self) -> &'static str {
        match self {
            Self::Recovery => "BIP39 seed wrap",
            Self::Password => "Argon2id → KEK",
            Self::Device => "P-256 + ML-KEM hybrid",
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
    /// This device holds the key (devices).
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
    /// Hardware keys.
    pub hw_keys: usize,
    /// Recovery wrap present.
    pub recovery: bool,
    /// Password wrap present.
    pub password: bool,
}

/// Views in file order. `owned` is the device wrap this machine holds a
/// key file for.
#[must_use]
pub fn views(directory: &WrapDirectory, owned: Option<[u8; 16]>) -> Vec<FactorView> {
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
            Factor::Chip(chip) => FactorView {
                id: Some(chip.publics.id),
                kind: FactorKind::Device,
                owned: owned == Some(chip.publics.id),
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
pub fn presence(directory: &WrapDirectory, owned: Option<[u8; 16]>) -> Presence {
    views(directory, owned)
        .iter()
        .fold(Presence::default(), |mut acc, view| {
            match view.kind {
                FactorKind::Recovery => acc.recovery = true,
                FactorKind::Password => acc.password = true,
                FactorKind::Device => {
                    acc.devices += 1;
                    acc.owned_devices += usize::from(view.owned);
                }
                FactorKind::HwKey => acc.hw_keys += 1,
            }
            acc
        })
}
