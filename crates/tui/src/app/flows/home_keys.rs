//! Keys on the vault home: movement, search, copy, reveal, and navigation
//! to the other views.

use crossterm::event::KeyEvent;
use record::{TAG_EMAIL, TAG_NOTES, TAG_PASSWORD, TAG_TOTP, TAG_URL, TAG_USERNAME};

use crate::app::action::Action;
use crate::app::ctx::{Ctx, Task};
use crate::app::flows::dialog::{Confirm, ConfirmKind, Dialog};
use crate::app::flows::editing::edit_text;
use crate::app::flows::editor::EditorState;
use crate::app::flows::factors::FactorsState;
use crate::app::flows::generator::GeneratorState;
use crate::app::flows::history::HistoryState;
use crate::app::flows::home::{filter_entries, Pane, RowKind};
use crate::app::flows::settings::SettingsModal;
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::Nav;
use crate::secure::reveal::RevealKey;
use crate::secure::totp::Totp;
use crate::ui::layout::Breakpoint;
use crate::ui::widgets::toast::Tone;
use crate::vault::create::unix_ms;
use crate::vault::ops::Op;
use crate::vault::records::{custom_text, set_custom_text, CUSTOM_FAVORITE};

/// Rows a page key moves.
const PAGE: usize = 10;

/// Handle a key on the home view.
pub fn on_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    if state.home.searching {
        return match resolve(Scope::Search, event) {
            Some(Action::Back) => {
                state.home.query.clear();
                state.home.searching = false;
                reselect(state, 0);
                Nav::Stay
            }
            Some(Action::Confirm) => {
                state.home.searching = false;
                Nav::Stay
            }
            Some(action @ (Action::Up | Action::Down)) => on_action(state, action, ctx),
            _ => {
                edit_text(&mut state.home.query, event);
                reselect(state, 0);
                Nav::Stay
            }
        };
    }
    resolve(Scope::Home, event).map_or(Nav::Stay, |action| on_action(state, action, ctx))
}

fn reselect(state: &mut Unlocked, row: usize) {
    state.home.selected = row;
    state.load_detail();
}

fn width(ctx: &Ctx) -> Breakpoint {
    Breakpoint::from(ctx.size.0)
}

/// Handle an action on the home view (also used by the palette).
pub fn on_action(state: &mut Unlocked, action: Action, ctx: &mut Ctx) -> Nav {
    match action {
        Action::Up
        | Action::Down
        | Action::PageUp
        | Action::PageDown
        | Action::Top
        | Action::Bottom => {
            move_cursor(state, action);
        }
        Action::NextField | Action::PrevField => {
            cycle_pane(state, action == Action::NextField, ctx);
        }
        Action::Confirm => confirm(state, ctx),
        Action::Back => back(state, ctx),
        Action::Search => {
            state.view = View::Home;
            state.home.searching = true;
            state.home.pane = Pane::List;
        }
        Action::CopyPassword => copy(state, TAG_PASSWORD, "password", ctx),
        Action::CopyUsername => copy(state, TAG_USERNAME, "username", ctx),
        Action::CopyEmail => copy(state, TAG_EMAIL, "email", ctx),
        Action::CopyTotp => copy_totp(state, ctx),
        Action::ShowUrl => show_url(state, ctx),
        Action::Reveal => reveal(state, ctx),
        Action::NewRecord => state.view = View::Editor(Box::new(EditorState::new_record())),
        Action::EditRecord => edit(state, ctx),
        Action::DeleteRecord => delete(state),
        Action::ToggleFavorite => favorite(state, ctx),
        Action::OpenGenerator => state.generator = Some(Box::new(GeneratorState::new(None, ctx))),
        Action::OpenHistory => history(state, ctx),
        Action::OpenFactors => state.view = View::Factors(FactorsState::default()),
        Action::OpenDevices => state.view = View::Devices(0),
        Action::OpenSync => state.view = View::Sync,
        Action::OpenHealth => match state.health {
            Some(_) => state.view = View::Health(0),
            None => state.run(Op::Health, Task::Health, ctx),
        },
        Action::ImportRecords => crate::app::flows::import_vault::open(state),
        Action::OpenSettings => {
            state.settings = Some(Box::new(SettingsModal::open(state, ctx)));
        }
        Action::Lock => return Nav::Lock,
        Action::Quit => return Nav::Quit,
        _ => return crate::app::flows::factors::palette_action(state, action, ctx),
    }
    Nav::Stay
}

fn move_cursor(state: &mut Unlocked, action: Action) {
    match state.home.pane {
        Pane::Filters => {
            let count = filter_entries(&state.cache, state.health.as_deref()).len();
            state.home.filter_cursor = step(state.home.filter_cursor, action, count);
        }
        Pane::List => {
            let count = state.visible().len();
            state.home.selected = step(state.home.selected, action, count);
            state.load_detail();
        }
        Pane::Detail => {
            if let Some(detail) = state.home.detail.as_mut() {
                detail.cursor = step(detail.cursor, action, detail.rows.len());
            }
        }
    }
}

fn step(current: usize, action: Action, count: usize) -> usize {
    let last = count.saturating_sub(1);
    match action {
        Action::Up => current.saturating_sub(1),
        Action::Down => (current + 1).min(last),
        Action::PageUp => current.saturating_sub(PAGE),
        Action::PageDown => (current + PAGE).min(last),
        Action::Top => 0,
        _ => last,
    }
}

fn cycle_pane(state: &mut Unlocked, forward: bool, ctx: &Ctx) {
    let order: &[Pane] = if width(ctx) == Breakpoint::Wide {
        &[Pane::Filters, Pane::List, Pane::Detail]
    } else {
        &[Pane::List, Pane::Detail]
    };
    let at = order
        .iter()
        .position(|pane| *pane == state.home.pane)
        .unwrap_or(0);
    let next = if forward {
        at + 1
    } else {
        at + order.len() - 1
    } % order.len();
    state.home.pane = order.get(next % order.len()).copied().unwrap_or(Pane::List);
}

fn confirm(state: &mut Unlocked, ctx: &mut Ctx) {
    match state.home.pane {
        Pane::Filters => {
            let entries = filter_entries(&state.cache, state.health.as_deref());
            if let Some((filter, _)) = entries.into_iter().nth(state.home.filter_cursor) {
                state.home.filter = filter;
                state.home.pane = Pane::List;
                reselect(state, 0);
            }
        }
        Pane::List => {
            state.home.pane = Pane::Detail;
            state.home.stacked = width(ctx) == Breakpoint::Narrow;
        }
        Pane::Detail => copy_focused(state, ctx),
    }
}

/// Copy the focused detail row: any field, standard or custom. A TOTP row
/// copies the current code, never the secret.
fn copy_focused(state: &Unlocked, ctx: &mut Ctx) {
    let Some(detail) = state.home.detail.as_ref() else {
        return;
    };
    let Some(row) = detail.rows.get(detail.cursor) else {
        return;
    };
    if row.kind == RowKind::Totp {
        copy_totp(state, ctx);
        return;
    }
    let data = detail
        .doc
        .data(row.tag)
        .ok()
        .flatten()
        .filter(|data| !data.is_empty());
    let Some(bytes) = data else {
        ctx.toast(
            Tone::Info,
            format!("\u{201c}{}\u{201d} is empty.", row.label),
        );
        return;
    };
    let label = match row.tag {
        TAG_PASSWORD => "password",
        TAG_USERNAME => "username",
        TAG_EMAIL => "email",
        TAG_URL => "URL",
        TAG_NOTES => "notes",
        _ if row.kind == RowKind::Secret => "secret field",
        _ => "field",
    };
    ctx.copy(bytes, label);
    if record::is_custom(row.tag) {
        ctx.toast(
            Tone::Success,
            format!("Copied \u{201c}{}\u{201d}.", row.label),
        );
    }
}

fn back(state: &mut Unlocked, ctx: &mut Ctx) {
    if let Some(detail) = state.home.detail.as_mut() {
        if detail.reveal.hide() {
            ctx.redraw();
        }
    }
    if state.home.stacked || state.home.pane == Pane::Detail {
        state.home.stacked = false;
        state.home.pane = Pane::List;
    } else if !state.home.query.is_empty() {
        state.home.query.clear();
        reselect(state, 0);
    }
}

fn copy(state: &Unlocked, tag: u16, label: &'static str, ctx: &mut Ctx) {
    let data = state
        .home
        .detail
        .as_ref()
        .and_then(|detail| detail.doc.data(tag).ok().flatten())
        .filter(|data| !data.is_empty());
    match data {
        Some(bytes) => ctx.copy(bytes, label),
        None => ctx.toast(Tone::Info, format!("This record has no {label}.")),
    }
}

fn copy_totp(state: &Unlocked, ctx: &mut Ctx) {
    let field = state
        .home
        .detail
        .as_ref()
        .and_then(|detail| detail.doc.data(TAG_TOTP).ok().flatten())
        .filter(|data| !data.is_empty());
    let Some(field) = field else {
        ctx.toast(Tone::Info, "This record has no TOTP secret.");
        return;
    };
    match Totp::try_from(field) {
        Ok(totp) => ctx.copy(totp.code(unix_ms() / 1000).as_bytes(), "TOTP code"),
        Err(error) => ctx.toast(Tone::Warn, format!("No code: {error}.")),
    }
}

fn show_url(state: &Unlocked, ctx: &mut Ctx) {
    let url = state
        .home
        .detail
        .as_ref()
        .and_then(|detail| detail.doc.text(TAG_URL).ok().flatten())
        .filter(|url| !url.is_empty())
        .map(str::to_owned);
    match url {
        Some(url) => ctx.toast(Tone::Info, format!("URL (not opened): {url}")),
        None => ctx.toast(Tone::Info, "This record has no URL."),
    }
}

fn reveal(state: &mut Unlocked, ctx: &mut Ctx) {
    let Some(detail) = state.home.detail.as_mut() else {
        return;
    };
    let Some(tag) = detail.secret_row().map(|row| row.tag) else {
        ctx.toast(Tone::Info, "Nothing secret to reveal here.");
        return;
    };
    let key = RevealKey(u32::from(tag));
    if ctx.caps.key_release {
        detail.reveal.show(key, ctx.now);
    } else if detail.reveal.toggle(key, ctx.now) {
        ctx.redraw();
    }
}

fn edit(state: &mut Unlocked, ctx: &mut Ctx) {
    let Some(id) = state.selected().map(|summary| summary.id) else {
        ctx.toast(Tone::Info, "Select a record first.");
        return;
    };
    let doc = state
        .vault
        .as_ref()
        .and_then(|vault| session::open_record(&vault.session, id).ok());
    match doc {
        Some(doc) => state.view = View::Editor(Box::new(EditorState::edit(id, &doc))),
        None => ctx.toast(Tone::Danger, "This record did not open."),
    }
}

fn delete(state: &mut Unlocked) {
    if let Some((id, title)) = state
        .selected()
        .map(|summary| (summary.id, summary.display_title().to_owned()))
    {
        state.dialog = Some(Box::new(Dialog::Confirm(Confirm {
            kind: ConfirmKind::Delete(id),
            title: format!("Delete \"{title}\"?"),
            body: vec![String::from(
                "A tombstone revision is written; history keeps older revisions until cleared.",
            )],
        })));
    }
}

fn favorite(state: &mut Unlocked, ctx: &mut Ctx) {
    let Some(id) = state.selected().map(|summary| summary.id) else {
        return;
    };
    let Some(mut doc) = state
        .vault
        .as_ref()
        .and_then(|vault| session::open_record(&vault.session, id).ok())
    else {
        return;
    };
    let on = custom_text(&doc, CUSTOM_FAVORITE) == Some("1");
    if set_custom_text(&mut doc, CUSTOM_FAVORITE, (!on).then_some("1")).is_ok() {
        state.run(
            Op::Write {
                id: Some(id),
                doc: Box::new(doc),
            },
            Task::Save,
            ctx,
        );
    }
}

fn history(state: &mut Unlocked, ctx: &mut Ctx) {
    let Some((id, title)) = state
        .selected()
        .map(|summary| (summary.id, summary.display_title().to_owned()))
    else {
        ctx.toast(Tone::Info, "Select a record first.");
        return;
    };
    if let Some(vault) = state.vault.as_ref() {
        match HistoryState::load(vault, id, title) {
            Ok(history) => state.view = View::History(Box::new(history)),
            Err(_) => ctx.toast(Tone::Danger, "History did not open."),
        }
    }
}
