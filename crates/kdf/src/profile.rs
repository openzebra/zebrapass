/// Argon2id parameter preset stored in the static header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KdfProfile {
    /// `m_kib = 262144`, `t = 3`, `p = 4` (256 MiB).
    Desktop,
    /// `m_kib = 65536`, `t = 3`, `p = 2` (64 MiB).
    Mobile,
}

impl KdfProfile {
    /// Memory cost in kibibytes.
    #[must_use]
    pub const fn m_kib(self) -> u32 {
        match self {
            Self::Desktop => 262_144,
            Self::Mobile => 65_536,
        }
    }

    /// Iteration count.
    #[must_use]
    pub const fn t(self) -> u32 {
        match self {
            Self::Desktop | Self::Mobile => 3,
        }
    }

    /// Lane count.
    #[must_use]
    pub const fn p(self) -> u32 {
        match self {
            Self::Desktop => 4,
            Self::Mobile => 2,
        }
    }
}
