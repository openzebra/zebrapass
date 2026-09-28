/// Argon2id parameter preset stored in the static header, named by how long
/// an unlock takes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KdfProfile {
    /// `m_kib = 65536`, `t = 3`, `p = 4` (64 MiB).
    Fast,
    /// `m_kib = 262144`, `t = 3`, `p = 4` (256 MiB).
    Balanced,
    /// `m_kib = 1048576`, `t = 4`, `p = 4` (1 GiB).
    Strong,
}

impl KdfProfile {
    /// Every preset, cheapest first.
    pub const ALL: [Self; 3] = [Self::Fast, Self::Balanced, Self::Strong];

    /// Memory cost in kibibytes.
    #[must_use]
    pub const fn m_kib(self) -> u32 {
        match self {
            Self::Fast => 65_536,
            Self::Balanced => 262_144,
            Self::Strong => 1_048_576,
        }
    }

    /// Iteration count.
    #[must_use]
    pub const fn t(self) -> u32 {
        match self {
            Self::Fast | Self::Balanced => 3,
            Self::Strong => 4,
        }
    }

    /// Lane count.
    #[must_use]
    pub const fn p(self) -> u32 {
        match self {
            Self::Fast | Self::Balanced | Self::Strong => 4,
        }
    }
}

impl From<KdfProfile> for u8 {
    fn from(profile: KdfProfile) -> Self {
        match profile {
            KdfProfile::Fast => 1,
            KdfProfile::Balanced => 2,
            KdfProfile::Strong => 3,
        }
    }
}

impl TryFrom<u8> for KdfProfile {
    type Error = anyhow::Error;

    /// # Errors
    ///
    /// `kdf parameters rejected` for any byte outside the preset allow-list.
    fn try_from(byte: u8) -> anyhow::Result<Self> {
        Self::ALL
            .into_iter()
            .find(|profile| u8::from(*profile) == byte)
            .ok_or_else(|| anyhow::anyhow!("kdf parameters rejected"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use super::KdfProfile;

    #[test]
    fn profile_ids_round_trip_and_reject_unknown_bytes() {
        for profile in KdfProfile::ALL {
            assert_eq!(KdfProfile::try_from(u8::from(profile)).unwrap(), profile);
        }
        for byte in [0u8, 4, 0x80, 0xFF] {
            assert!(KdfProfile::try_from(byte).is_err());
        }
    }
}
