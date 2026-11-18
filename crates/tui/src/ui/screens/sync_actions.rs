//! Button specifications for the share overview screen.

use local::Offer;
use memberlog::Role;

use crate::app::flows::share::ShareState;
use crate::app::flows::share_nav::ShareButton;
use crate::app::flows::unlocked::Unlocked;
use crate::ui::screens::sync_buttons::{ButtonSpec, ButtonTone};
use crate::ui::theme::Theme;

/// Right-pane key copy and share URL copy buttons.
#[must_use]
pub(super) const fn copy_button_row(theme: &Theme) -> [ButtonSpec; 2] {
    [
        ButtonSpec {
            id: ShareButton::CopyKey,
            glyph: theme.glyphs.vk,
            label: "Copy Key",
            short_label: "Key",
            key: if theme.ascii { "Ent" } else { "↵" },
            tone: ButtonTone::Primary,
        },
        ButtonSpec {
            id: ShareButton::CopyUrl,
            glyph: theme.glyphs.command,
            label: "Copy URL",
            short_label: "URL",
            key: "y",
            tone: ButtonTone::Normal,
        },
    ]
}

/// Vault management buttons in two 4-button rows.
#[must_use]
pub(super) fn vault_button_rows(
    state: &Unlocked,
    share: &ShareState,
    theme: &Theme,
) -> ([ButtonSpec; 4], [ButtonSpec; 4]) {
    let selected = state.shared.get(share.cursor);
    let has_selected = selected.is_some();
    let owner_ready =
        selected.is_some_and(|item| item.ready() && item.my_role == Some(Role::Owner));
    let needs_rekey = owner_ready && selected.is_some_and(|item| item.leaves > 0);
    let owner_tone = if owner_ready {
        ButtonTone::Normal
    } else {
        ButtonTone::Muted
    };
    let row0 = [
        ButtonSpec {
            id: ShareButton::NewVault,
            glyph: theme.glyphs.spark,
            label: "New",
            short_label: "New",
            key: "n",
            tone: ButtonTone::Normal,
        },
        ButtonSpec {
            id: ShareButton::JoinVault,
            glyph: theme.glyphs.pointer,
            label: "Join",
            short_label: "Join",
            key: "j",
            tone: ButtonTone::Normal,
        },
        ButtonSpec {
            id: ShareButton::AddPerson,
            glyph: theme.glyphs.ok,
            label: "Add",
            short_label: "Add",
            key: "a",
            tone: owner_tone,
        },
        ButtonSpec {
            id: ShareButton::SyncNow,
            glyph: theme.glyphs.sync,
            label: "Sync",
            short_label: "Sync",
            key: "r",
            tone: if has_selected {
                ButtonTone::Normal
            } else {
                ButtonTone::Muted
            },
        },
    ];
    let row1 = [
        ButtonSpec {
            id: ShareButton::ChangeRole,
            glyph: theme.glyphs.note,
            label: "Role",
            short_label: "Role",
            key: "c",
            tone: owner_tone,
        },
        ButtonSpec {
            id: ShareButton::RemovePerson,
            glyph: theme.glyphs.fail,
            label: "Remove",
            short_label: "Rem",
            key: "x",
            tone: owner_tone,
        },
        ButtonSpec {
            id: ShareButton::RekeyVault,
            glyph: theme.glyphs.recovery,
            label: "Rekey",
            short_label: "Rekey",
            key: "k",
            tone: if needs_rekey {
                ButtonTone::Warn
            } else {
                owner_tone
            },
        },
        ButtonSpec {
            id: ShareButton::LeaveVault,
            glyph: theme.glyphs.arrows[2],
            label: "Leave",
            short_label: "Leave",
            key: "d",
            tone: if has_selected {
                ButtonTone::Danger
            } else {
                ButtonTone::Muted
            },
        },
    ];
    (row0, row1)
}

/// Network listen / address / seen buttons.
#[must_use]
pub(super) fn net_listen_row(state: &Unlocked, theme: &Theme) -> [ButtonSpec; 3] {
    let seen_offer = state
        .p2p
        .as_deref()
        .and_then(|p2p| p2p.observed.as_ref())
        .is_some_and(|offer| {
            matches!(offer, Offer::Public(addr) if state.advertised() != Some(addr.as_ref()))
        });
    let listening = state
        .p2p
        .as_deref()
        .is_some_and(|p2p| p2p.service.local_addr().is_some());
    [
        ButtonSpec {
            id: ShareButton::CycleListen,
            glyph: if listening {
                theme.glyphs.on
            } else {
                theme.glyphs.off
            },
            label: "Listen",
            short_label: "Listen",
            key: "l",
            tone: if listening {
                ButtonTone::Active
            } else {
                ButtonTone::Normal
            },
        },
        ButtonSpec {
            id: ShareButton::PublicAddress,
            glyph: theme.glyphs.device,
            label: "Address",
            short_label: "Addr",
            key: "p",
            tone: if state.advertised().is_some() {
                ButtonTone::Active
            } else {
                ButtonTone::Normal
            },
        },
        ButtonSpec {
            id: ShareButton::UseSeen,
            glyph: theme.glyphs.login,
            label: "Use Seen",
            short_label: "Seen",
            key: "o",
            tone: if seen_offer {
                ButtonTone::Active
            } else {
                ButtonTone::Muted
            },
        },
    ]
}

/// Relay and identity upgrade buttons.
#[must_use]
pub(super) fn net_relay_row(state: &Unlocked, theme: &Theme) -> Vec<ButtonSpec> {
    let has_relays = state
        .p2p
        .as_deref()
        .is_some_and(|p2p| !p2p.relays.is_empty());
    let holding = state
        .info
        .prefs
        .as_ref()
        .is_some_and(|prefs| prefs.p2p_hold);
    let mut row = Vec::with_capacity(3);
    row.push(ButtonSpec {
        id: ShareButton::AddRelay,
        glyph: theme.glyphs.sync,
        label: "Relay",
        short_label: "Relay",
        key: "v",
        tone: if has_relays {
            ButtonTone::Active
        } else {
            ButtonTone::Normal
        },
    });
    row.push(ButtonSpec {
        id: ShareButton::ToggleAnnounce,
        glyph: if holding {
            theme.glyphs.on
        } else {
            theme.glyphs.off
        },
        label: "Announce",
        short_label: "Hold",
        key: "t",
        tone: if holding {
            ButtonTone::Active
        } else if has_relays {
            ButtonTone::Normal
        } else {
            ButtonTone::Muted
        },
    });
    if state.identity_is_old() {
        row.push(ButtonSpec {
            id: ShareButton::UpgradeIdentity,
            glyph: theme.glyphs.arrows[0],
            label: "Upgrade",
            short_label: "Upgr",
            key: "u",
            tone: ButtonTone::Warn,
        });
    }
    row
}
