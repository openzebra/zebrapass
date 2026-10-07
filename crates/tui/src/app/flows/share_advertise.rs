//! The public address this device offers other members.
//!
//! A device behind a router with a forwarded port cannot know the address the
//! world sees. The person writes it here and the node signs it into the
//! addresses it hands to members. An empty entry takes it back.

use local::parse_advertise;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::ctx::Task;
use crate::app::flows::editing::edit_text;
use crate::app::flows::share::Step;
use crate::app::flows::unlocked::Unlocked;
use crate::ui::input::TextInput;
use crate::ui::widgets::toast::Tone;
use crate::vault::ops::Op;
use crossterm::event::KeyEvent;

/// Longest address typed: an IPv6 socket address with a port.
pub const ADDRESS_MAX: usize = 64;

impl Unlocked {
    pub(super) fn begin_advertise(&self) -> Step {
        let mut input = TextInput::new(ADDRESS_MAX);
        if let Some(current) = self.advertised() {
            input.insert_str(current);
        }
        Step::Advertise(input)
    }

    pub(super) fn advertise_step(
        &mut self,
        mut input: TextInput,
        action: Option<Action>,
        event: &KeyEvent,
        ctx: &mut Ctx,
    ) -> Step {
        match action {
            Some(Action::Back) => Step::Overview,
            Some(Action::Confirm) => match self.save_advertised(input.value().trim(), ctx) {
                Ok(()) => Step::Overview,
                Err(reason) => {
                    ctx.toast(Tone::Warn, reason);
                    Step::Advertise(input)
                }
            },
            _ => {
                edit_text(&mut input, event);
                Step::Advertise(input)
            }
        }
    }

    fn save_advertised(&mut self, text: &str, ctx: &mut Ctx) -> Result<(), &'static str> {
        let address = if text.is_empty() {
            None
        } else {
            Some(parse_advertise(text)?)
        };
        let mut prefs = self.info.prefs.clone().unwrap_or_default();
        prefs.p2p_advertise.clone_from(&address);
        self.info.prefs = Some(prefs.clone());
        self.restart_p2p();
        self.run(Op::SavePrefs(Box::new(prefs)), Task::Save, ctx);
        let message = address.map_or_else(
            || String::from("No public address is offered now."),
            |address| format!("Members are told to reach you at {address}."),
        );
        ctx.toast(Tone::Success, message);
        Ok(())
    }
}
