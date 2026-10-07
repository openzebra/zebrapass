//! The share screen: your key, your shared vaults, and the few steps that
//! make or join one. One prompt at a time; long texts are pasted, never
//! typed, and never echoed.

use crossterm::event::KeyEvent;
use memberlog::Role;
use sharing::{ContactCard, Fingerprint, Opened};
use zeroize::Zeroizing;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::editing::edit_text;
use crate::app::flows::factors::palette_action;
pub use crate::app::flows::share_leave::LeaveMode;
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::Nav;
use crate::ui::input::TextInput;

/// Longest name typed for a new shared vault.
pub const NAME_MAX: usize = local::SHARED_NAME_MAX;

/// Where the person is in the flow.
#[derive(Default)]
pub enum Step {
    /// Your key and your shared vaults.
    #[default]
    Overview,
    /// Naming a new shared vault.
    Name(TextInput),
    /// Waiting for a pasted key to add.
    PasteCard,
    /// A pasted key: compare its fingerprint, pick a role.
    AddConfirm { card: Box<ContactCard>, role: Role },
    /// Added: the invitation to hand over.
    AddDone {
        invitation: Zeroizing<String>,
        print: Fingerprint,
        number: String,
    },
    /// Choosing who to remove.
    PickPerson(usize),
    /// Someone picked: compare their fingerprint, then remove.
    RemoveConfirm {
        target: [u8; 64],
        print: Fingerprint,
        role: Role,
    },
    /// Choosing whose role to change.
    PickRole(usize),
    /// Someone picked: choose their new role.
    RoleConfirm {
        target: [u8; 64],
        print: Fingerprint,
        from: Role,
        to: Role,
    },
    /// Leaving or forgetting the selected vault.
    LeaveConfirm(LeaveMode),
    /// Replacing the selected vault's key.
    RekeyConfirm,
    /// Waiting for a pasted invitation.
    PasteInvite,
    /// An opened invitation: check who it is from and which vault.
    JoinConfirm(Box<Opened>),
}

/// This device's own key, ready to hand out.
pub struct Me {
    /// The text to copy.
    pub text: Zeroizing<String>,
    /// The fingerprint to read aloud.
    pub print: Fingerprint,
}

/// State of the share screen.
pub struct ShareState {
    /// The current step.
    pub step: Step,
    /// The selected shared vault.
    pub cursor: usize,
    /// This device's key, when the vault has a sync identity.
    pub me: Option<Me>,
}

impl std::fmt::Debug for ShareState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareState")
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

enum Next {
    Stay(Step),
    Leave,
}

pub(super) fn cycle(role: Role, forward: bool) -> Role {
    const ORDER: [Role; 3] = [Role::Reader, Role::Writer, Role::Owner];
    let at = ORDER.iter().position(|known| *known == role).unwrap_or(0);
    let step = if forward { 1 } else { ORDER.len() - 1 };
    ORDER
        .get((at + step) % ORDER.len())
        .copied()
        .unwrap_or(role)
}

impl Unlocked {
    /// Open the share screen.
    pub fn open_share(&mut self) {
        let me = self.make_me();
        self.view = View::Sync(Box::new(ShareState {
            step: Step::Overview,
            cursor: 0,
            me,
        }));
    }

    fn share_mut(&mut self) -> Option<&mut ShareState> {
        match &mut self.view {
            View::Sync(share) => Some(share),
            _ => None,
        }
    }

    /// Handle a key on the share screen.
    pub fn share_key(&mut self, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
        let Some(step) = self
            .share_mut()
            .map(|share| std::mem::take(&mut share.step))
        else {
            return Nav::Stay;
        };
        let scope = if matches!(step, Step::Overview) {
            Scope::Sync
        } else {
            Scope::Share
        };
        let action = resolve(scope, event);
        if let Some(global @ (Action::Quit | Action::Lock | Action::Palette | Action::Help)) =
            action
        {
            if let Some(share) = self.share_mut() {
                share.step = step;
            }
            return palette_action(self, global, ctx);
        }
        match self.advance(step, action, event, ctx) {
            Next::Stay(next) => {
                if let Some(share) = self.share_mut() {
                    share.step = next;
                }
            }
            Next::Leave => self.view = View::Home,
        }
        Nav::Stay
    }

    /// Handle pasted text on the share screen.
    pub fn share_paste(&mut self, text: &str, ctx: &mut Ctx) {
        let Some(step) = self
            .share_mut()
            .map(|share| std::mem::take(&mut share.step))
        else {
            return;
        };
        let next = match step {
            Step::PasteCard => Self::card_pasted(text, ctx),
            Step::PasteInvite => self.invitation_pasted(text, ctx),
            Step::Name(mut input) => {
                input.insert_str(text);
                Step::Name(input)
            }
            other => other,
        };
        if let Some(share) = self.share_mut() {
            share.step = next;
        }
    }

    fn advance(
        &mut self,
        step: Step,
        action: Option<Action>,
        event: &KeyEvent,
        ctx: &mut Ctx,
    ) -> Next {
        match step {
            Step::Overview => self.overview(action, ctx),
            Step::Name(mut input) => match action {
                Some(Action::Back) => Next::Stay(Step::Overview),
                Some(Action::Confirm) => Next::Stay(self.create_named(input, ctx)),
                _ => {
                    edit_text(&mut input, event);
                    Next::Stay(Step::Name(input))
                }
            },
            Step::PasteCard | Step::PasteInvite => match action {
                Some(Action::Back) => Next::Stay(Step::Overview),
                _ => Next::Stay(step),
            },
            Step::AddConfirm { card, role } => match action {
                Some(Action::Back) => Next::Stay(Step::Overview),
                Some(Action::Left) => Next::Stay(Step::AddConfirm {
                    card,
                    role: cycle(role, false),
                }),
                Some(Action::Right) => Next::Stay(Step::AddConfirm {
                    card,
                    role: cycle(role, true),
                }),
                Some(Action::Confirm) => Next::Stay(self.finish_add(card, role, ctx)),
                _ => Next::Stay(Step::AddConfirm { card, role }),
            },
            Step::AddDone {
                invitation,
                print,
                number,
            } => match action {
                Some(Action::Back) => Next::Stay(Step::Overview),
                Some(Action::Confirm) => {
                    if !ctx.copy(invitation.as_bytes(), "invitation") {
                        self.save_invitation(&invitation, &number, ctx);
                    }
                    Next::Stay(Step::AddDone {
                        invitation,
                        print,
                        number,
                    })
                }
                _ => Next::Stay(Step::AddDone {
                    invitation,
                    print,
                    number,
                }),
            },
            Step::PickPerson(pick) => {
                let count = self.people(self.share_cursor()).len();
                match action {
                    Some(Action::Back) => Next::Stay(Step::Overview),
                    Some(Action::Up) => Next::Stay(Step::PickPerson(pick.saturating_sub(1))),
                    Some(Action::Down) => {
                        Next::Stay(Step::PickPerson((pick + 1).min(count.saturating_sub(1))))
                    }
                    Some(Action::Confirm) => Next::Stay(self.confirm_person(pick)),
                    _ => Next::Stay(Step::PickPerson(pick)),
                }
            }
            Step::PickRole(pick) => Next::Stay(self.pick_role_step(pick, action)),
            Step::RoleConfirm {
                target,
                print,
                from,
                to,
            } => Next::Stay(self.role_confirm_step(target, print, (from, to), action, ctx)),
            Step::LeaveConfirm(mode) => Next::Stay(self.leave_step(mode, action, ctx)),
            Step::RekeyConfirm => Next::Stay(self.rekey_step(action, ctx)),
            Step::RemoveConfirm {
                target,
                print,
                role,
            } => match action {
                Some(Action::Back) => Next::Stay(Step::Overview),
                Some(Action::Confirm) => Next::Stay(self.finish_remove(target, print, role, ctx)),
                _ => Next::Stay(Step::RemoveConfirm {
                    target,
                    print,
                    role,
                }),
            },
            Step::JoinConfirm(opened) => match action {
                Some(Action::Back) => Next::Stay(Step::Overview),
                Some(Action::Confirm) => Next::Stay(self.finish_join_flow(opened, ctx)),
                _ => Next::Stay(Step::JoinConfirm(opened)),
            },
        }
    }

    fn overview(&mut self, action: Option<Action>, ctx: &mut Ctx) -> Next {
        let count = self.shared.len();
        let cursor = self.share_mut().map_or(0, |share| share.cursor);
        match action {
            Some(Action::Back) => return Next::Leave,
            Some(Action::Up) => self.set_cursor(cursor.saturating_sub(1)),
            Some(Action::Down) => self.set_cursor((cursor + 1).min(count.saturating_sub(1))),
            Some(Action::Confirm) => self.copy_my_key(ctx),
            Some(Action::ShareNew) => {
                return Next::Stay(Step::Name(TextInput::new(NAME_MAX)));
            }
            Some(Action::ShareAdd) => return Next::Stay(self.begin_add(ctx)),
            Some(Action::ShareJoin) => return Next::Stay(Step::PasteInvite),
            Some(Action::ShareRemove) => return Next::Stay(self.begin_remove(ctx)),
            Some(Action::ShareRole) => return Next::Stay(self.begin_role(ctx)),
            Some(Action::ShareLeave) => return Next::Stay(self.begin_leave(ctx)),
            Some(Action::ShareRekey) => return Next::Stay(self.begin_rekey(ctx)),
            Some(Action::ShareRetry) => self.retry_selected(ctx),
            Some(Action::ShareListen) => self.cycle_listen(ctx),
            _ => {}
        }
        Next::Stay(Step::Overview)
    }

    fn set_cursor(&mut self, cursor: usize) {
        if let Some(share) = self.share_mut() {
            share.cursor = cursor;
        }
    }
}
