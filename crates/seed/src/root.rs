//! Root account identity seam (`BIP39`, future `Email`, future `HardwareKey`)
//! mapping supported account factors to a 512-bit root seed and canonical
//! 512-bit storage identifier.

use secret::Secret;

use crate::SeedPhrase;

/// Supported and upcoming root identity sources for a `ZebraPass` vault.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum RootKind {
    /// 24-word (or 12..=24 word) BIP39 recovery phrase.
    #[default]
    Bip39 = 1,
    /// Email-anchored account key (future release).
    Email = 2,
    /// Hardware-key FIDO2 PRF root key (future release).
    HardwareKey = 3,
}

impl RootKind {
    /// All root identity kinds in display order.
    pub const ALL: [Self; 3] = [Self::Bip39, Self::Email, Self::HardwareKey];

    /// Short display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Bip39 => "BIP39 phrase",
            Self::Email => "Email",
            Self::HardwareKey => "Hardware key",
        }
    }

    /// Whether this root kind is currently supported for vault creation/restore.
    #[must_use]
    pub const fn supported(self) -> bool {
        match self {
            Self::Bip39 => true,
            Self::Email | Self::HardwareKey => false,
        }
    }
}

impl From<RootKind> for u8 {
    fn from(kind: RootKind) -> Self {
        kind as Self
    }
}

impl TryFrom<u8> for RootKind {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> anyhow::Result<Self> {
        match value {
            1 => Ok(Self::Bip39),
            2 => Ok(Self::Email),
            3 => Ok(Self::HardwareKey),
            _ => Err(anyhow::anyhow!("unsupported root identity kind")),
        }
    }
}

/// Credential input for deriving the account's 512-bit root seed.
#[derive(Clone, Copy)]
pub enum RootInput<'a> {
    /// Validated BIP39 recovery phrase.
    Bip39(&'a SeedPhrase),
    /// Email account address (not supported yet).
    Email(&'a str),
    /// Hardware-key PRF assertion bytes (not supported yet).
    HardwareKey(&'a [u8]),
}

impl std::fmt::Debug for RootInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bip39(_) => f.write_str("RootInput::Bip39([REDACTED])"),
            Self::Email(_) => f.write_str("RootInput::Email([REDACTED])"),
            Self::HardwareKey(_) => f.write_str("RootInput::HardwareKey([REDACTED])"),
        }
    }
}

/// Derive the 512-bit (`[u8; 64]`) root seed from `input`.
///
/// # Errors
///
/// Fails closed for unbuilt `Email` and `HardwareKey` paths.
pub fn derive_root_seed(input: RootInput<'_>) -> anyhow::Result<Secret<[u8; 64]>> {
    match input {
        RootInput::Bip39(phrase) => {
            let mut out = Secret::new([0u8; 64]);
            out.expose_mut().copy_from_slice(phrase.seed());
            Ok(out)
        }
        RootInput::Email(_) => {
            // TODO(email): zero-knowledge email enrollment device wrap
            Err(anyhow::anyhow!(
                "email account identity is not supported yet"
            ))
        }
        RootInput::HardwareKey(_) => {
            // TODO(hw-key): FIDO2 PRF root seed derivation
            Err(anyhow::anyhow!(
                "hardware-key account identity is not supported yet"
            ))
        }
    }
}

/// Derive the canonical 512-bit (`[u8; 64]`) storage identifier from `input`.
///
/// # Errors
///
/// Fails closed for unbuilt `Email` and `HardwareKey` paths or KDF rejection.
pub fn derive_storage_id(input: RootInput<'_>) -> anyhow::Result<[u8; 64]> {
    let seed = derive_root_seed(input)?;
    kdf::storage_id(seed.expose())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use secrecy::SecretString;

    use crate::{RootInput, RootKind, SeedPhrase, derive_root_seed, derive_storage_id};

    #[test]
    fn bip39_derives_deterministic_seed_and_512bit_storage_id() {
        let phrase = SeedPhrase::generate_24().unwrap();
        let norm = SecretString::new(phrase.phrase_normalized().to_owned().into_boxed_str());
        let empty = SecretString::new(String::new().into_boxed_str());
        let again = SeedPhrase::parse(&norm, &empty).unwrap();

        let seed_a = derive_root_seed(RootInput::Bip39(&phrase)).unwrap();
        let seed_b = derive_root_seed(RootInput::Bip39(&again)).unwrap();
        assert_eq!(seed_a.expose(), seed_b.expose());

        let id_a = derive_storage_id(RootInput::Bip39(&phrase)).unwrap();
        let id_b = derive_storage_id(RootInput::Bip39(&again)).unwrap();
        assert_eq!(id_a, id_b);
        assert_eq!(id_a.len(), 64);
    }

    #[test]
    fn email_and_hw_key_fail_closed() {
        assert!(RootKind::Bip39.supported());
        assert!(!RootKind::Email.supported());
        assert!(!RootKind::HardwareKey.supported());
        assert!(derive_root_seed(RootInput::Email("user@example.com")).is_err());
        assert!(derive_storage_id(RootInput::Email("user@example.com")).is_err());
        assert!(derive_root_seed(RootInput::HardwareKey(b"token")).is_err());
        assert!(derive_storage_id(RootInput::HardwareKey(b"token")).is_err());
        assert_eq!(RootKind::try_from(1).unwrap(), RootKind::Bip39);
        assert_eq!(RootKind::try_from(2).unwrap(), RootKind::Email);
        assert_eq!(RootKind::try_from(3).unwrap(), RootKind::HardwareKey);
        assert!(RootKind::try_from(99).is_err());
    }
}
