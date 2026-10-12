//! What a member may do in a shared vault.

use anyhow::anyhow;

/// A member's role. The order is the order of power.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Role {
    /// May read records. Records a reader signs are refused by honest peers.
    Reader,
    /// May read, create and edit records.
    Writer,
    /// May also add and remove members and change roles.
    Owner,
}

impl Role {
    /// Whether this role may write records.
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Writer | Self::Owner)
    }

    /// Whether this role may change the member list.
    #[must_use]
    pub const fn can_manage(self) -> bool {
        matches!(self, Self::Owner)
    }
}

impl From<Role> for u8 {
    fn from(role: Role) -> Self {
        match role {
            Role::Reader => 1,
            Role::Writer => 2,
            Role::Owner => 3,
        }
    }
}

impl TryFrom<u8> for Role {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> anyhow::Result<Self> {
        match value {
            1 => Ok(Self::Reader),
            2 => Ok(Self::Writer),
            3 => Ok(Self::Owner),
            _ => Err(anyhow!("member log rejected")),
        }
    }
}
