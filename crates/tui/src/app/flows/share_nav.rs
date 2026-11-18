//! Focus order and 2D button-grid navigation for the share overview screen.

use crate::app::action::Action;

/// Every interactive button on the share overview screen.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ShareButton {
    /// Right pane: copy the full signed contact card (`zp-card1:...`).
    #[default]
    CopyKey,
    /// Right pane: copy the standard `zebrapass://share?...` URI.
    CopyUrl,
    /// Left pane vault row 0: create a new shared vault.
    NewVault,
    /// Left pane vault row 0: join an existing shared vault.
    JoinVault,
    /// Left pane vault row 0: add someone to the selected vault.
    AddPerson,
    /// Left pane vault row 0: retry / sync the selected vault now.
    SyncNow,
    /// Left pane vault row 1: change a member's role.
    ChangeRole,
    /// Left pane vault row 1: remove a member.
    RemovePerson,
    /// Left pane vault row 1: replace the selected vault's key.
    RekeyVault,
    /// Left pane vault row 1: leave or forget the selected vault.
    LeaveVault,
    /// Left pane network row 2: cycle listening mode.
    CycleListen,
    /// Left pane network row 2: set or clear public address.
    PublicAddress,
    /// Left pane network row 2: apply the address a peer observed.
    UseSeen,
    /// Left pane network row 3: add or clear saved relays.
    AddRelay,
    /// Left pane network row 3: toggle announcing through the saved relay.
    ToggleAnnounce,
    /// Left pane network row 3: upgrade an old sync identity.
    UpgradeIdentity,
}

/// Active focus on the share overview screen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareFocus {
    /// The shared-vault list.
    Vaults,
    /// One of the action buttons.
    Button(ShareButton),
}

impl Default for ShareFocus {
    fn default() -> Self {
        Self::Button(ShareButton::CopyKey)
    }
}

impl ShareFocus {
    /// Focused button, if any.
    #[must_use]
    pub const fn button(self) -> Option<ShareButton> {
        match self {
            Self::Button(btn) => Some(btn),
            Self::Vaults => None,
        }
    }

    /// Whether focus is on the right ("your key") pane.
    #[must_use]
    pub const fn is_right_pane(self) -> bool {
        matches!(
            self,
            Self::Button(ShareButton::CopyKey | ShareButton::CopyUrl)
        )
    }
}

const ROW0: [ShareButton; 4] = [
    ShareButton::NewVault,
    ShareButton::JoinVault,
    ShareButton::AddPerson,
    ShareButton::SyncNow,
];

const ROW1: [ShareButton; 4] = [
    ShareButton::ChangeRole,
    ShareButton::RemovePerson,
    ShareButton::RekeyVault,
    ShareButton::LeaveVault,
];

const ROW2: [ShareButton; 3] = [
    ShareButton::CycleListen,
    ShareButton::PublicAddress,
    ShareButton::UseSeen,
];

const ORDER: [ShareFocus; 17] = [
    ShareFocus::Button(ShareButton::CopyKey),
    ShareFocus::Button(ShareButton::CopyUrl),
    ShareFocus::Vaults,
    ShareFocus::Button(ShareButton::NewVault),
    ShareFocus::Button(ShareButton::JoinVault),
    ShareFocus::Button(ShareButton::AddPerson),
    ShareFocus::Button(ShareButton::SyncNow),
    ShareFocus::Button(ShareButton::ChangeRole),
    ShareFocus::Button(ShareButton::RemovePerson),
    ShareFocus::Button(ShareButton::RekeyVault),
    ShareFocus::Button(ShareButton::LeaveVault),
    ShareFocus::Button(ShareButton::CycleListen),
    ShareFocus::Button(ShareButton::PublicAddress),
    ShareFocus::Button(ShareButton::UseSeen),
    ShareFocus::Button(ShareButton::AddRelay),
    ShareFocus::Button(ShareButton::ToggleAnnounce),
    ShareFocus::Button(ShareButton::UpgradeIdentity),
];

const fn is_visible(focus: ShareFocus, has_vaults: bool, identity_is_old: bool) -> bool {
    match focus {
        ShareFocus::Vaults => has_vaults,
        ShareFocus::Button(ShareButton::UpgradeIdentity) => identity_is_old,
        ShareFocus::Button(_) => true,
    }
}

/// Move focus to the next (`forward = true`) or previous (`forward = false`) control.
#[must_use]
pub fn next_focus(
    focus: ShareFocus,
    forward: bool,
    has_vaults: bool,
    identity_is_old: bool,
) -> ShareFocus {
    let len = ORDER.len();
    let start = ORDER.iter().position(|item| *item == focus).unwrap_or(0);
    for step in 1..=len {
        let offset = if forward { step } else { len - step };
        if let Some(&candidate) = ORDER.get((start + offset) % len)
            && is_visible(candidate, has_vaults, identity_is_old)
        {
            return candidate;
        }
    }
    focus
}

fn row_of(btn: ShareButton, identity_is_old: bool) -> &'static [ShareButton] {
    if ROW0.contains(&btn) {
        &ROW0
    } else if ROW1.contains(&btn) {
        &ROW1
    } else if ROW2.contains(&btn) {
        &ROW2
    } else if identity_is_old {
        &[
            ShareButton::AddRelay,
            ShareButton::ToggleAnnounce,
            ShareButton::UpgradeIdentity,
        ]
    } else {
        &[ShareButton::AddRelay, ShareButton::ToggleAnnounce]
    }
}

/// Move horizontally across the active row and cross between left and right panes at edges.
#[must_use]
pub fn move_horizontal(focus: ShareFocus, forward: bool, identity_is_old: bool) -> ShareFocus {
    match focus {
        ShareFocus::Vaults => {
            if forward {
                ShareFocus::Button(ShareButton::CopyKey)
            } else {
                ShareFocus::Vaults
            }
        }
        ShareFocus::Button(ShareButton::CopyKey) => {
            if forward {
                ShareFocus::Button(ShareButton::CopyUrl)
            } else {
                ShareFocus::Button(ShareButton::SyncNow)
            }
        }
        ShareFocus::Button(ShareButton::CopyUrl) => {
            if forward {
                ShareFocus::Button(ShareButton::NewVault)
            } else {
                ShareFocus::Button(ShareButton::CopyKey)
            }
        }
        ShareFocus::Button(btn) => {
            let row = row_of(btn, identity_is_old);
            let pos = row.iter().position(|b| *b == btn).unwrap_or(0);
            if forward {
                row.get(pos + 1)
                    .map_or(ShareFocus::Button(ShareButton::CopyKey), |&next| {
                        ShareFocus::Button(next)
                    })
            } else if pos > 0 {
                row.get(pos - 1)
                    .map_or(focus, |&prev| ShareFocus::Button(prev))
            } else {
                ShareFocus::Button(ShareButton::CopyUrl)
            }
        }
    }
}

fn button_grid_coords(btn: ShareButton, identity_is_old: bool) -> Option<(usize, usize)> {
    let rows: [&[ShareButton]; 4] = [
        &ROW0,
        &ROW1,
        &ROW2,
        if identity_is_old {
            &[
                ShareButton::AddRelay,
                ShareButton::ToggleAnnounce,
                ShareButton::UpgradeIdentity,
            ]
        } else {
            &[ShareButton::AddRelay, ShareButton::ToggleAnnounce]
        },
    ];
    for (r_idx, row) in rows.iter().enumerate() {
        if let Some(c_idx) = row.iter().position(|b| *b == btn) {
            return Some((r_idx, c_idx));
        }
    }
    None
}

/// Move vertically through the left-pane rows or between the right-pane buttons.
#[must_use]
pub fn move_vertical(
    focus: ShareFocus,
    down: bool,
    has_vaults: bool,
    identity_is_old: bool,
) -> ShareFocus {
    match focus {
        ShareFocus::Vaults => {
            if down {
                ShareFocus::Button(ShareButton::NewVault)
            } else {
                ShareFocus::Vaults
            }
        }
        ShareFocus::Button(ShareButton::CopyKey) if down => {
            ShareFocus::Button(ShareButton::CopyUrl)
        }
        ShareFocus::Button(ShareButton::CopyUrl) if !down => {
            ShareFocus::Button(ShareButton::CopyKey)
        }
        ShareFocus::Button(btn) => {
            let Some((row_idx, col)) = button_grid_coords(btn, identity_is_old) else {
                return focus;
            };
            if !down && row_idx == 0 {
                return if has_vaults {
                    ShareFocus::Vaults
                } else {
                    focus
                };
            }
            let next_row_idx = if down {
                (row_idx + 1).min(3)
            } else {
                row_idx - 1
            };
            let target_row: &[ShareButton] = match next_row_idx {
                0 => &ROW0,
                1 => &ROW1,
                2 => &ROW2,
                _ if identity_is_old => &[
                    ShareButton::AddRelay,
                    ShareButton::ToggleAnnounce,
                    ShareButton::UpgradeIdentity,
                ],
                _ => &[ShareButton::AddRelay, ShareButton::ToggleAnnounce],
            };
            target_row
                .get(col.min(target_row.len().saturating_sub(1)))
                .map_or(focus, |&next| ShareFocus::Button(next))
        }
    }
}

/// Map a direct keyboard action to the corresponding UI button.
#[must_use]
pub const fn button_for_action(action: Action) -> Option<ShareButton> {
    match action {
        Action::ShareCopyUrl => Some(ShareButton::CopyUrl),
        Action::ShareNew => Some(ShareButton::NewVault),
        Action::ShareJoin => Some(ShareButton::JoinVault),
        Action::ShareAdd => Some(ShareButton::AddPerson),
        Action::ShareRetry => Some(ShareButton::SyncNow),
        Action::ShareRole => Some(ShareButton::ChangeRole),
        Action::ShareRemove => Some(ShareButton::RemovePerson),
        Action::ShareRekey => Some(ShareButton::RekeyVault),
        Action::ShareLeave => Some(ShareButton::LeaveVault),
        Action::ShareListen => Some(ShareButton::CycleListen),
        Action::ShareAdvertise => Some(ShareButton::PublicAddress),
        Action::ShareFillObserved => Some(ShareButton::UseSeen),
        Action::ShareRelay => Some(ShareButton::AddRelay),
        Action::ShareHold => Some(ShareButton::ToggleAnnounce),
        Action::ShareUpgrade => Some(ShareButton::UpgradeIdentity),
        _ => None,
    }
}

/// Map an activated UI button back to its action.
#[must_use]
pub const fn action_for_button(button: ShareButton) -> Action {
    match button {
        ShareButton::CopyKey => Action::Confirm,
        ShareButton::CopyUrl => Action::ShareCopyUrl,
        ShareButton::NewVault => Action::ShareNew,
        ShareButton::JoinVault => Action::ShareJoin,
        ShareButton::AddPerson => Action::ShareAdd,
        ShareButton::SyncNow => Action::ShareRetry,
        ShareButton::ChangeRole => Action::ShareRole,
        ShareButton::RemovePerson => Action::ShareRemove,
        ShareButton::RekeyVault => Action::ShareRekey,
        ShareButton::LeaveVault => Action::ShareLeave,
        ShareButton::CycleListen => Action::ShareListen,
        ShareButton::PublicAddress => Action::ShareAdvertise,
        ShareButton::UseSeen => Action::ShareFillObserved,
        ShareButton::AddRelay => Action::ShareRelay,
        ShareButton::ToggleAnnounce => Action::ShareHold,
        ShareButton::UpgradeIdentity => Action::ShareUpgrade,
    }
}
