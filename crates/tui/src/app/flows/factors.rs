//! Constellation (factor management), devices, and the palette-only vault
//! commands (rotate, change password, drop recovery).

use std::time::Instant;

use crossterm::event::KeyEvent;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::dialog::{Confirm, ConfirmKind, Dialog, Info};
use crate::app::flows::form::Form;
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::Nav;
use crate::ui::widgets::fingerprint::grouped_hex;
use crate::ui::widgets::toast::Tone;
use crate::vault::factors::{presence, views, FactorKind, FactorView};
use crate::vault::ops::FactorRef;

/// Constellation animation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anim {
    /// A new wrap flies in.
    Add,
    /// An edge shatters, then the key rotates.
    Revoke,
    /// Every edge flashes while the key rotates.
    Rotate,
}

/// Constellation state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FactorsState {
    /// Selected list row (factors, then "+ add factor").
    pub selected: usize,
    /// Running animation.
    pub anim: Option<(Anim, Instant)>,
}

/// The wrap a view addresses, for kinds that carry an id.
#[must_use]
pub const fn factor_ref(view: &FactorView) -> Option<FactorRef> {
    match (view.kind, view.id) {
        (FactorKind::Device, Some(id)) => Some(FactorRef::Device(id)),
        (FactorKind::HwKey, Some(id)) => Some(FactorRef::HwKey(id)),
        (
            FactorKind::Recovery | FactorKind::Password | FactorKind::Device | FactorKind::HwKey,
            _,
        ) => None,
    }
}

/// `device A021-5B7E`.
#[must_use]
pub fn factor_label(view: &FactorView) -> String {
    let id = view.id.map(|id| grouped_hex(&id, 2)).unwrap_or_default();
    let owned = if view.owned { " (this device)" } else { "" };
    format!("{} {id}{owned}", view.kind.noun())
        .trim()
        .to_owned()
}

fn devices(state: &Unlocked) -> Vec<FactorView> {
    views(&state.info.directory, state.info.owned_device())
        .into_iter()
        .filter(|view| matches!(view.kind, FactorKind::Device | FactorKind::HwKey))
        .collect()
}

/// Handle a key on the factors or devices view.
pub fn on_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let scope = if matches!(state.view, View::Devices(_)) {
        Scope::Devices
    } else {
        Scope::Factors
    };
    let Some(action) = resolve(scope, event) else {
        return Nav::Stay;
    };
    let list = match state.view {
        View::Devices(_) => devices(state),
        _ => views(&state.info.directory, state.info.owned_device()),
    };
    let rows = list.len() + usize::from(scope == Scope::Factors);
    let cursor = match &mut state.view {
        View::Factors(factors) => &mut factors.selected,
        View::Devices(cursor) => cursor,
        _ => return Nav::Stay,
    };
    match action {
        Action::Up => *cursor = cursor.saturating_sub(1),
        Action::Down => *cursor = (*cursor + 1).min(rows.saturating_sub(1)),
        Action::Back => state.view = View::Home,
        Action::AddFactor => state.dialog = Some(Box::new(Dialog::AddFactor(0))),
        Action::EnrollDevice => state.dialog = Some(Box::new(enroll_guide())),
        _ => {
            let selected = list.get(*cursor).cloned();
            act(state, action, selected.as_ref(), ctx);
        }
    }
    Nav::Stay
}

fn act(state: &mut Unlocked, action: Action, selected: Option<&FactorView>, ctx: &mut Ctx) {
    let has_password = presence(&state.info.directory, state.info.owned_device()).password;
    let Some(view) = selected else {
        if action == Action::Confirm {
            state.dialog = Some(Box::new(Dialog::AddFactor(0)));
        }
        return;
    };
    let target = factor_ref(view);
    match (action, view.kind, target) {
        (Action::Confirm, FactorKind::Password, _) => form(state, Form::change_password()),
        (Action::Confirm | Action::RemoveFactor, FactorKind::Recovery, _) => {
            form(state, Form::drop_recovery());
        }
        (Action::Confirm, _, _) => state.dialog = Some(Box::new(details(view))),
        (Action::RevokeFactor, _, Some(target)) => form(
            state,
            Form::revoke(target, &factor_label(view), has_password),
        ),
        (Action::RevokeFactor, _, None) => ctx.toast(
            Tone::Info,
            "Revoke applies to devices and keys. Press Enter on the password to change it.",
        ),
        (Action::RemoveFactor, _, Some(target)) => {
            state.dialog = Some(Box::new(Dialog::Confirm(Confirm {
                kind: ConfirmKind::RemoveWrap(target),
                title: format!("Remove {}?", factor_label(view)),
                body: vec![
                    String::from("Its wrap is dropped but the vault key does NOT rotate:"),
                    String::from("a device that already knows the key keeps it. Use r to revoke."),
                ],
            })));
        }
        (Action::RemoveFactor, FactorKind::Password, _) => {
            state.dialog = Some(Box::new(Dialog::Confirm(Confirm {
                kind: ConfirmKind::RemovePassword,
                title: String::from("Remove the password?"),
                body: vec![
                    String::from("The password stops opening this file. Another factor"),
                    String::from("must remain; the vault key does NOT rotate."),
                ],
            })));
        }
        _ => {}
    }
}

/// Open `form` as the dialog.
pub fn form(state: &mut Unlocked, form: Form) {
    state.dialog = Some(Box::new(Dialog::Form(Box::new(form))));
}

fn details(view: &FactorView) -> Dialog {
    let mut body = vec![format!(
        "{}  ·  {}",
        view.kind.noun(),
        view.kind.primitive()
    )];
    if let Some(id) = view.id {
        body.push(format!("wrap id  {}", grouped_hex(&id, 8)));
    }
    if view.kind.post_quantum() {
        body.push(String::from(
            "PQ: the KEK needs both the classical and the ML-KEM secret.",
        ));
    }
    if view.kind == FactorKind::Device && !view.owned {
        body.push(String::from(
            "This machine has no key file for it: it belongs to another device.",
        ));
    }
    body.push(String::from("Device certificates are kept in sync.id."));
    Dialog::Info(Info {
        title: factor_label(view),
        body,
    })
}

fn enroll_guide() -> Dialog {
    Dialog::Info(Info {
        title: String::from("Enroll a new device"),
        body: vec![
            String::from("1. Copy the vault file to the new device (or sync it)."),
            String::from("2. On that device: Restore from phrase, point at the file."),
            String::from("3. It enrolls its own unlock factor; nothing is shared."),
            String::from("QR pairing is not built yet."),
        ],
    })
}

/// Palette-only commands that open a vault dialog.
pub fn palette_action(state: &mut Unlocked, action: Action, ctx: &mut Ctx) -> Nav {
    let found = presence(&state.info.directory, state.info.owned_device());
    match action {
        Action::RotateVaultKey => form(state, Form::rotate(found.password)),
        Action::ChangePassword if found.password => form(state, Form::change_password()),
        Action::ChangePassword => form(state, Form::add_password()),
        Action::DropRecovery if found.recovery => form(state, Form::drop_recovery()),
        Action::DropRecovery => ctx.toast(Tone::Info, "This copy has no recovery wrap."),
        Action::ClearHistory => {
            state.dialog = Some(Box::new(Dialog::Confirm(Confirm {
                kind: ConfirmKind::ClearHistory,
                title: String::from("Clear history?"),
                body: vec![String::from(
                    "Old revisions and deleted records are dropped for good.",
                )],
            })));
        }
        Action::EnrollDevice => state.dialog = Some(Box::new(enroll_guide())),
        Action::RevokeFactor | Action::OpenDevices => state.view = View::Devices(0),
        _ => {}
    }
    Nav::Stay
}
