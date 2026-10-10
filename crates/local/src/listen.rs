//! Where this device's sync node accepts connections.

/// Where this device's sync node accepts connections.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Listen {
    /// No listener, and no node unless something else needs one (a shared
    /// vault, a held relay slot).
    Off,
    /// On this device only (`127.0.0.1`).
    Local,
    /// On the local network (`0.0.0.0`).
    #[default]
    Lan,
    /// On the local network, and announced there by a sealed beacon that
    /// only the account's other devices can read.
    Beacon,
    /// No listener, no beacon and no relay slot: the node only dials out,
    /// pulling and pushing at each check-in. For a device that cannot be
    /// reached anyway, such as a phone on mobile data.
    Fetch,
}

impl Listen {
    /// Every mode, in the order a toggle cycles through them.
    pub const ALL: [Self; 5] = [Self::Lan, Self::Beacon, Self::Local, Self::Fetch, Self::Off];

    /// The next mode.
    #[must_use]
    pub fn next(self) -> Self {
        let at = Self::ALL.iter().position(|mode| *mode == self).unwrap_or(0);
        Self::ALL
            .get((at + 1) % Self::ALL.len())
            .copied()
            .unwrap_or(Self::Off)
    }
}

impl From<Listen> for u8 {
    fn from(mode: Listen) -> Self {
        match mode {
            Listen::Off => 0,
            Listen::Local => 1,
            Listen::Lan => 2,
            Listen::Beacon => 3,
            Listen::Fetch => 4,
        }
    }
}

impl TryFrom<u8> for Listen {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> anyhow::Result<Self> {
        Self::ALL
            .into_iter()
            .find(|mode| u8::from(*mode) == byte)
            .ok_or_else(|| anyhow::anyhow!("preference out of range"))
    }
}
