//! The import wizard inside an open vault: records go through
//! `import::into_session` on the worker, duplicates are skipped.

use crossterm::event::KeyEvent;
use import::Merged;

use crate::app::ctx::{Ctx, Task};
use crate::app::flows::import::{ImportEvent, ImportState, Target};
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::screen::Nav;
use crate::ui::widgets::toast::Tone;
use crate::vault::ops::Op;

/// Open the wizard over the vault.
pub fn open(state: &mut Unlocked) {
    state.settings = None;
    state.view = View::Import(Box::new(ImportState::new(Target::OpenVault)));
}

/// Handle a key while the wizard is shown.
pub fn on_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let View::Import(import) = &mut state.view else {
        return Nav::Stay;
    };
    let plaintext = import.source().plaintext();
    match import.on_key(event, ctx) {
        ImportEvent::Stay | ImportEvent::Phrase => {}
        ImportEvent::Leave => state.view = View::Home,
        ImportEvent::Records(records) => {
            state.import_plaintext = plaintext;
            state.run(Op::Import(records), Task::Save, ctx);
        }
    }
    Nav::Stay
}

/// The worker wrote the records.
pub fn done(state: &mut Unlocked, merged: &Merged, ctx: &mut Ctx) {
    state.view = View::Home;
    state.refresh();
    if let Some(first) = merged.ids.first() {
        state.select(*first);
    }
    let added = merged.ids.len();
    let skipped = match merged.duplicates {
        0 => String::new(),
        count => format!(" · {count} already here, skipped"),
    };
    let delete = if std::mem::take(&mut state.import_plaintext) {
        " Delete the export file: it holds your passwords in plain text."
    } else {
        ""
    };
    ctx.toast(
        Tone::Success,
        format!("Imported {added} records{skipped}.{delete}"),
    );
}
