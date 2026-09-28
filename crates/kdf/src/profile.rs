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
