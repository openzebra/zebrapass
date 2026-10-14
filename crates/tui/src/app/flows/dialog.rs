//! Modal dialogs: confirmations, notices, the add-factor menu, and forms
//! that collect the recovery phrase or passwords for dangerous operations.
//! Revoke, rotate, and drop-recovery are hold-to-confirm.

use crossterm::event::{KeyCode, KeyEvent};

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::editing::{edit_secret, edit_text, printable, Hold};
use crate::app::flows::enroll::EnrollFactor;
use crate::app::flows::form::{Form, FormFocus};
use crate::app::flows::unlocked::Unlocked;
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::Nav;
use crate::ui::widgets::toast::Tone;
use crate::vault::ops::FactorRef;

/// What a confirmation does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmKind {
    /// Delete a record.
    Delete(u32),
    /// Remove a wrap without rotation.
    RemoveWrap(FactorRef),
    /// Remove the password wrap.
    RemovePassword,
    /// Drop superseded revisions.
    ClearHistory,
    /// Restore a revision.
    RestoreRevision(u32, u64),
    /// Leave the editor without saving.
    Discard,
    /// Close settings and drop the staged changes.
    DiscardSettings,
    /// Remove the typed device address at this place in the list.
    RemoveDeviceAddress(usize),
}

/// A yes/no question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirm {
    /// What.
    pub kind: ConfirmKind,
    /// Title.
    pub title: String,
    /// Explanation.
    pub body: Vec<String>,
}

/// A notice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    /// Title.
    pub title: String,
    /// Text.
    pub body: Vec<String>,
}

/// A dialog.
#[derive(Debug)]
pub enum Dialog {
    /// Yes/no.
    Confirm(Confirm),
    /// Notice.
    Info(Info),
    /// Inputs.
    Form(Box<Form>),
    /// Add-factor menu with its cursor into [`EnrollFactor::ALL`].
    AddFactor(usize),
    /// The device addresses typed by the owner.
    Addresses(crate::app::flows::addresses::Addresses),
    /// The peer-to-peer state, scrolled this many events back.
    P2p(usize),
    /// Waiting for another device to sync the vault after an empty restore.
    RestoreSync(usize),
}

impl Dialog {
    /// A key was released: end a true hold early.
    pub fn release(&mut self, ctx: &Ctx) {
        if let Self::Form(form) = self {
            if let Some(hold) = form.hold.as_mut() {
                hold.release(ctx.caps.key_release);
            }
        }
    }

    /// Advance timers. `true` when a hold completed and the form submits.
    pub fn tick(&mut self, ctx: &mut Ctx) -> bool {
        let Self::Form(form) = self else { return false };
        if form.reveal.tick(ctx.now, ctx.reveal_after) {
            ctx.redraw();
        }
        form.hold
            .as_mut()
            .is_some_and(|hold: &mut Hold| hold.tick(ctx.now, ctx.caps.key_release))
    }

    /// Paste into the focused input.
    pub fn on_paste(&mut self, text: &str) {
        match self {
            Self::Form(form) => form.on_paste(text),
            Self::Addresses(addresses) => {
                if let Some(input) = addresses.input.as_mut() {
                    input.insert_str(text.trim());
                }
            }
            Self::Confirm(_)
            | Self::Info(_)
            | Self::AddFactor(_)
            | Self::P2p(_)
            | Self::RestoreSync(_) => {}
        }
    }
}

/// Handle a key while a dialog is open.
pub fn on_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let Some(dialog) = state.dialog.as_mut() else {
        return Nav::Stay;
    };
    match dialog.as_mut() {
        Dialog::Info(_) => {
            if matches!(event.code, KeyCode::Enter | KeyCode::Esc) {
                state.dialog = None;
            }
            Nav::Stay
        }
        Dialog::Confirm(confirm) => {
            let kind = confirm.kind;
            match resolve(Scope::Dialog, event) {
                Some(Action::Confirm) => {
                    state.dialog = None;
                    crate::app::flows::form::run_confirm(state, kind, ctx);
                }
                Some(Action::Back) => state.dialog = None,
                _ => {}
            }
            Nav::Stay
        }
        Dialog::AddFactor(cursor) => {
            match event.code {
                KeyCode::Up => *cursor = cursor.saturating_sub(1),
                KeyCode::Down => *cursor = (*cursor + 1).min(EnrollFactor::ALL.len() - 1),
                KeyCode::Enter => {
                    let choice = EnrollFactor::ALL.get(*cursor).copied();
                    state.dialog = None;
                    if let Some(choice) = choice {
                        crate::app::flows::form::add_factor(state, choice, ctx);
                    }
                }
                KeyCode::Esc => state.dialog = None,
                _ => {}
            }
            Nav::Stay
        }
        Dialog::Addresses(_) => crate::app::flows::addresses::on_key(state, event, ctx),
        Dialog::P2p(scroll) => {
            match event.code {
                KeyCode::Up => *scroll += 1,
                KeyCode::Down => *scroll = scroll.saturating_sub(1),
                KeyCode::Esc | KeyCode::Enter => state.dialog = None,
                _ => {}
            }
            Nav::Stay
        }
        Dialog::RestoreSync(scroll) => match event.code {
            KeyCode::Up => {
                *scroll += 1;
                Nav::Stay
            }
            KeyCode::Down => {
                *scroll = scroll.saturating_sub(1);
                Nav::Stay
            }
            KeyCode::Esc => {
                state.cancel_adopt(ctx);
                Nav::Stay
            }
            _ => Nav::Stay,
        },
        Dialog::Form(_) => form_key(state, event, ctx),
    }
}

fn form_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let Some(Dialog::Form(form)) = state.dialog.as_deref_mut() else {
        return Nav::Stay;
    };
    let action = resolve(Scope::Dialog, event);
    if action != Some(Action::Confirm) {
        if let Some(hold) = form.hold.as_mut().filter(|_| !ctx.caps.key_release) {
            hold.cancel();
        }
    }
    if form.focus == FormFocus::Phrase {
        if let Some(phrase) = form.phrase.as_mut() {
            if let Some(ch) = printable(event).filter(|ch| *ch != ' ') {
                phrase.type_char(ch);
                return Nav::Stay;
            }
            if event.code == KeyCode::Backspace {
                phrase.backspace();
                return Nav::Stay;
            }
            if action == Some(Action::NextWord) {
                if !phrase.space() {
                    form.error = Some("Keep typing: that is not a whole word yet.".into());
                }
                return Nav::Stay;
            }
        }
    }
    match action {
        Some(Action::NextField) => form.shift(true, ctx),
        Some(Action::PrevField) => form.shift(false, ctx),
        Some(Action::RevealField) => form.toggle_reveal(ctx),
        Some(Action::Back) => {
            state.dialog = None;
            ctx.redraw();
        }
        Some(Action::Confirm) => {
            let fire = match form.hold.as_mut() {
                Some(hold) => hold.press(ctx.now, ctx.caps.key_release),
                None => true,
            };
            if fire {
                return submit(state, ctx);
            }
        }
        Some(_) | None => {
            form.error = None;
            match form.focus {
                FormFocus::Phrase => {}
                FormFocus::Passphrase | FormFocus::Current | FormFocus::New | FormFocus::Repeat => {
                    if let Some(input) = form.secret_mut(form.focus) {
                        edit_secret(input, event);
                    }
                }
                FormFocus::Text => {
                    if let Some(input) = form.text_mut(form.focus) {
                        edit_text(input, event);
                    }
                }
            }
        }
    }
    Nav::Stay
}

/// Submit the open form (Enter, or a completed hold).
pub fn submit(state: &mut Unlocked, ctx: &mut Ctx) -> Nav {
    let Some(dialog) = state.dialog.take() else {
        return Nav::Stay;
    };
    let Dialog::Form(mut form) = *dialog else {
        state.dialog = Some(dialog);
        return Nav::Stay;
    };
    match form.build() {
        Ok((op, task)) => {
            ctx.redraw();
            state.run(op, task, ctx);
        }
        Err(message) => {
            form.error = Some(message.into());
            if let Some(hold) = form.hold.as_mut() {
                hold.cancel();
            }
            ctx.toast(Tone::Warn, message);
            state.dialog = Some(Box::new(Dialog::Form(form)));
        }
    }
    Nav::Stay
}
