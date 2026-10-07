//! Replacing the key of a shared vault without removing anyone.
//!
//! A member who leaves keeps the key in use. They are no longer in the member
//! list, so the others refuse their device, but only a new key closes what is
//! written afterwards to everything they still hold. Owners replace it here;
//! the others pick the new key up when their device next connects.

use local::Replace;
use memberlog::Role;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::share::Step;
use crate::app::flows::unlocked::Unlocked;
use crate::ui::widgets::toast::Tone;

impl Unlocked {
    pub(super) fn begin_rekey(&self, ctx: &mut Ctx) -> Step {
        let picked = self
            .shared
            .get(self.share_cursor())
            .map(|item| (item.ready(), item.my_role));
        let message = match picked {
            None => "No shared vault is selected.",
            Some((false, _)) => "That vault is still syncing.",
            Some((true, role)) if role != Some(Role::Owner) => "Only owners can replace the key.",
            Some(_) => return Step::RekeyConfirm,
        };
        ctx.toast(Tone::Info, message);
        Step::Overview
    }

    pub(super) fn rekey_step(&mut self, action: Option<Action>, ctx: &mut Ctx) -> Step {
        match action {
            Some(Action::Back) => Step::Overview,
            Some(Action::Confirm) => match self.replace_key(Replace::Rotate) {
                Ok(others) => {
                    let message = match others {
                        0 => String::from("New key. No one else is in this vault."),
                        1 => String::from("New key. One other person gets it when they connect."),
                        n => format!("New key. {n} other people get it when they connect."),
                    };
                    ctx.toast(Tone::Success, message);
                    Step::Overview
                }
                Err(error) => {
                    ctx.toast(Tone::Warn, error.to_string());
                    Step::RekeyConfirm
                }
            },
            _ => Step::RekeyConfirm,
        }
    }
}
