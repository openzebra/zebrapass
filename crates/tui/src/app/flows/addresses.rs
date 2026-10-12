//! The device addresses an owner types: where this account's other devices
//! can be dialed when no beacon is heard.
//!
//! Entries live in the sealed peer store next to the personal vault, marked
//! manual. They are hints: the handshake still decides who answers.

use crossterm::event::{KeyCode, KeyEvent};
use local::{add_manual_peer, load_personal_entries, remove_personal_peer, Listen, PersonalPeer};

use crate::app::ctx::Ctx;
use crate::app::flows::dialog::{Confirm, ConfirmKind, Dialog};
use crate::app::flows::editing::edit_text;
use crate::app::flows::unlocked::Unlocked;
use crate::app::screen::Nav;
use crate::ui::input::TextInput;
use crate::ui::widgets::toast::Tone;
use crate::vault::Vault;

/// Longest address typed: an IPv6 address with brackets and a port.
const ADDRESS_MAX: usize = local::PERSONAL_PEER_MAX_LEN;

/// The list of typed addresses, and the field that adds one.
#[derive(Debug)]
pub struct Addresses {
    /// Selected entry among the manual ones.
    pub cursor: usize,
    /// The field, while an address is being typed.
    pub input: Option<TextInput>,
}

impl Addresses {
    /// The list, or the list with the field already open.
    #[must_use]
    pub const fn open(adding: bool) -> Self {
        Self {
            cursor: 0,
            input: if adding {
                Some(TextInput::new(ADDRESS_MAX))
            } else {
                None
            },
        }
    }
}

/// Every stored entry of `vault`, manual first; empty when unreadable.
#[must_use]
pub fn load_devices(vault: &Vault) -> Vec<PersonalPeer> {
    vault
        .session
        .personal_peers_key()
        .ok()
        .and_then(|key| load_personal_entries(&vault.paths.peers_store(), &key, true).ok())
        .unwrap_or_default()
}

impl Unlocked {
    /// The addresses typed by the owner.
    pub fn manual_devices(&self) -> impl Iterator<Item = &PersonalPeer> {
        self.devices.iter().filter(|entry| entry.manual)
    }

    /// Read the peer store again after it changed.
    pub fn reload_devices(&mut self) {
        if let Some(vault) = self.vault.as_deref() {
            self.devices = load_devices(vault);
        }
    }

    /// Whether loopback addresses may be dialed: tests and single-machine
    /// setups only.
    fn dials_loopback(&self) -> bool {
        let listen = self
            .p2p
            .as_deref()
            .map_or_else(|| self.listen_mode(), |p2p| p2p.listen);
        matches!(listen, Listen::Local | Listen::Fetch)
            || self.beacon.is_some_and(|config| config.loopback)
    }

    /// Keep `text` as a device address and check in with it.
    fn add_device_address(&mut self, text: &str, ctx: &mut Ctx) -> Result<(), String> {
        let loopback = self.dials_loopback();
        let vault = self
            .vault
            .as_deref()
            .ok_or("Still working on the last change.")?;
        let key = vault
            .session
            .personal_peers_key()
            .map_err(|_| String::from("The address could not be saved."))?;
        add_manual_peer(&vault.paths.peers_store(), &key, text.trim(), loopback)
            .map_err(|error| error.to_string())?;
        self.reload_devices();
        if self.held.is_some() {
            self.adopt_seen = 0;
            if let Some(p2p) = self.p2p.as_deref_mut() {
                p2p.expire_check_timer();
            }
        } else {
            self.sync_now(ctx);
        }
        Ok(())
    }

    /// Take the `index`th typed address away.
    pub fn remove_device_address(&mut self, index: usize, ctx: &mut Ctx) {
        let Some(address) = self
            .manual_devices()
            .nth(index)
            .map(|entry| entry.address.clone())
        else {
            return;
        };
        let removed = self.vault.as_deref().is_some_and(|vault| {
            vault
                .session
                .personal_peers_key()
                .and_then(|key| remove_personal_peer(&vault.paths.peers_store(), &key, &address))
                .is_ok()
        });
        if removed {
            self.reload_devices();
            ctx.toast(Tone::Success, "Address removed.");
        } else {
            ctx.toast(Tone::Danger, "The address could not be removed.");
        }
        self.dialog = Some(Box::new(Dialog::Addresses(Addresses::open(false))));
    }

    /// Open the list from the settings row.
    pub fn open_addresses(&mut self, adding: bool) {
        self.dialog = Some(Box::new(Dialog::Addresses(Addresses::open(adding))));
    }
}

/// Handle a key while the list is open.
pub fn on_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let count = state.manual_devices().count();
    let Some(Dialog::Addresses(addresses)) = state.dialog.as_deref_mut() else {
        return Nav::Stay;
    };
    if let Some(input) = addresses.input.as_mut() {
        match event.code {
            KeyCode::Esc => addresses.input = None,
            KeyCode::Enter => {
                let text = input.value().to_owned();
                match state.add_device_address(&text, ctx) {
                    Ok(()) => {
                        ctx.toast(Tone::Success, "Address saved. Checking it now.");
                        state.open_addresses(false);
                    }
                    Err(reason) => ctx.toast(Tone::Warn, reason),
                }
            }
            _ => {
                edit_text(input, event);
            }
        }
        return Nav::Stay;
    }
    match event.code {
        KeyCode::Up => addresses.cursor = addresses.cursor.saturating_sub(1),
        KeyCode::Down => addresses.cursor = (addresses.cursor + 1).min(count.saturating_sub(1)),
        KeyCode::Char('a') => addresses.input = Some(TextInput::new(ADDRESS_MAX)),
        KeyCode::Delete | KeyCode::Backspace if count > 0 => {
            let index = addresses.cursor.min(count - 1);
            state.dialog = Some(Box::new(Dialog::Confirm(Confirm {
                kind: ConfirmKind::RemoveDeviceAddress(index),
                title: String::from("Remove this address?"),
                body: vec![String::from(
                    "This device stops dialing it. The other device is untouched.",
                )],
            })));
        }
        KeyCode::Esc => state.dialog = None,
        _ => {}
    }
    Nav::Stay
}
