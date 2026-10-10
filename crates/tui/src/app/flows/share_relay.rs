//! Relay slots a person pastes.
//!
//! A slot is where another member can be reached when it cannot be dialed
//! directly. Each is checked, saved in the vault's sealed preferences, and
//! added to the addresses a check-in dials after the direct ones.

use crossterm::event::KeyEvent;
use local::{parse_relay_hint, RELAYS_MAX};

use crate::app::action::Action;
use crate::app::ctx::{Ctx, Task};
use crate::app::flows::editing::edit_text;
use crate::app::flows::share::Step;
use crate::app::flows::unlocked::Unlocked;
use crate::ui::input::TextInput;
use crate::ui::widgets::toast::Tone;
use crate::vault::ops::Op;

/// Longest relay slot typed: an IPv6 relay address, a slash and the slot.
pub const RELAY_MAX: usize = session::MAX_HINT_LEN;

impl Unlocked {
    pub(super) const fn begin_relay() -> Step {
        Step::Relay(TextInput::new(RELAY_MAX))
    }

    pub(super) fn relay_step(
        &mut self,
        mut input: TextInput,
        action: Option<Action>,
        event: &KeyEvent,
        ctx: &mut Ctx,
    ) -> Step {
        match action {
            Some(Action::Back) => Step::Overview,
            Some(Action::Confirm) => match self.add_relay(input.value(), ctx) {
                Ok(()) => Step::Overview,
                Err(reason) => {
                    ctx.toast(Tone::Warn, reason);
                    Step::Relay(input)
                }
            },
            _ => {
                edit_text(&mut input, event);
                Step::Relay(input)
            }
        }
    }

    fn add_relay(&mut self, text: &str, ctx: &mut Ctx) -> Result<(), &'static str> {
        let hint = parse_relay_hint(text)?;
        let mut prefs = self.info.prefs.clone().unwrap_or_default();
        if prefs.p2p_relays.contains(&hint) {
            return Err("That relay is already saved.");
        }
        if prefs.p2p_relays.len() >= RELAYS_MAX {
            return Err("Four relays are saved already.");
        }
        prefs.p2p_relays.push(hint);
        if let Some(p2p) = self.p2p.as_deref_mut() {
            p2p.relays = prefs.p2p_relays.iter().map(ToString::to_string).collect();
        }
        self.info.prefs = Some(prefs.clone());
        self.run(Op::SavePrefs(Box::new(prefs)), Task::Save, ctx);
        ctx.toast(
            Tone::Success,
            "Relay saved. Check-ins will try it after direct addresses.",
        );
        Ok(())
    }

    /// Note that this node holds a slot on a relay, for the node line.
    pub fn note_relayed(&mut self, hint: p2p_net::RelayHint) {
        if let Some(p2p) = self.p2p.as_deref_mut() {
            p2p.relayed = Some(hint);
        }
    }
}
