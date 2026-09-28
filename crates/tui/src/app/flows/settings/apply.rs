//! What the settings modal does: save the draft, close it (asking before
//! throwing edits away), and act on rows that open a guarded form.

use crate::app::action::Action;
use crate::app::ctx::{Ctx, Task};
use crate::app::flows::dialog::{Confirm, ConfirmKind, Dialog};
use crate::app::flows::factors::{form, palette_action, FactorsState};
use crate::app::flows::form::Form;
use crate::app::flows::settings::rows::Row;
use crate::app::flows::settings::Focus;
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::screen::Nav;
use crate::ui::widgets::toast::Tone;
use crate::vault::factors::presence;
use crate::vault::ops::{FactorRef, Op};

/// Save the draft to this vault's local metadata.
pub fn save(state: &mut Unlocked, ctx: &mut Ctx) {
    let Some(modal) = state.settings.as_deref() else {
        return;
    };
    if modal.unsaved() == 0 {
        ctx.toast(Tone::Info, "Nothing to apply.");
        return;
    }
    let draft = Box::new(modal.draft.clone());
    state.run(Op::SavePrefs(draft), Task::Save, ctx);
}

/// Close; with unsaved edits, ask first.
pub fn close(state: &mut Unlocked, ctx: &mut Ctx) {
    let Some(unsaved) = state.settings.as_deref().map(super::SettingsModal::unsaved) else {
        return;
    };
    if unsaved == 0 {
        discard(state, ctx);
        return;
    }
    let plural = if unsaved == 1 { "" } else { "s" };
    state.dialog = Some(Box::new(Dialog::Confirm(Confirm {
        kind: ConfirmKind::DiscardSettings,
        title: format!("Discard {unsaved} unsaved change{plural}?"),
        body: vec![String::from(
            "Ctrl-S applies them instead. The preview goes back to what is saved.",
        )],
    })));
}

/// Drop the draft and restore the saved look.
pub fn discard(state: &mut Unlocked, ctx: &mut Ctx) {
    if let Some(modal) = state.settings.take() {
        ctx.preview_look(&modal.saved);
    }
}

/// Enter on `row`.
pub fn activate(state: &mut Unlocked, row: Row, ctx: &mut Ctx) -> Nav {
    let found = presence(&state.info.directory, state.info.owned_device());
    let owned = state.info.owned_device();
    match row {
        Row::AutoLock
        | Row::FocusLock
        | Row::RevealHide
        | Row::SyncMode
        | Row::ClipClear
        | Row::Theme
        | Row::Animation
        | Row::Ascii => {
            if let Some(modal) = state.settings.as_deref_mut() {
                row.adjust(&mut modal.draft, true);
                ctx.preview_look(&modal.draft);
            }
        }
        Row::ServerOrigin => {
            if let Some(modal) = state.settings.as_deref_mut() {
                let current = modal.draft.server_origin.as_deref().unwrap_or("https://");
                modal.edit.set(current);
                modal.focus = Focus::Edit;
                modal.error = None;
            }
        }
        Row::PasswordCost if found.password => form(state, Form::change_password()),
        Row::PasswordCost => form(state, Form::add_password()),
        Row::Factors => leave_for(state, View::Factors(FactorsState::default()), ctx),
        Row::DeviceStatus if owned.is_some() => {
            ctx.toast(
                Tone::Info,
                "This device is enrolled. Revoke it in the danger zone.",
            );
        }
        Row::DeviceStatus => form(state, Form::add_device()),
        Row::DevicePin if owned.is_some() => form(state, Form::change_pin()),
        Row::ServerPin => ctx.toast(
            Tone::Info,
            "The server key is pinned on first contact; r clears the pin.",
        ),
        // TODO(sync-server): run the signed handshake against the origin.
        Row::TestConnection => ctx.toast(
            Tone::Warn,
            "The sync server is not built yet: nothing was sent.",
        ),
        Row::Name => form(state, Form::rename(&state.info.label)),
        Row::RotateKey => form(state, Form::rotate(found.password)),
        Row::ForgetDevice if owned.is_some() => {
            if let Some(id) = owned {
                form(
                    state,
                    Form::revoke(FactorRef::Device(id), "this device", found.password),
                );
            }
        }
        Row::DevicePin | Row::ForgetDevice => {
            ctx.toast(Tone::Info, "This device is not enrolled for this vault.");
        }
        Row::ClearHistory => return palette_action(state, Action::ClearHistory, ctx),
        Row::DeviceFingerprint
        | Row::SecureEnclave
        | Row::ClientId
        | Row::DeviceCert
        | Row::ClipOnLock
        | Row::Cipher
        | Row::Generation
        | Row::Records
        | Row::FilePath
        | Row::Version
        | Row::DataDir
        | Row::Primitives
        | Row::Posture => {}
    }
    Nav::Stay
}

fn leave_for(state: &mut Unlocked, view: View, ctx: &mut Ctx) {
    let dirty = state
        .settings
        .as_deref()
        .is_some_and(|modal| modal.unsaved() > 0);
    if dirty {
        ctx.toast(
            Tone::Info,
            "Apply (Ctrl-S) or discard (Esc) your changes first.",
        );
        return;
    }
    discard(state, ctx);
    state.view = view;
}
