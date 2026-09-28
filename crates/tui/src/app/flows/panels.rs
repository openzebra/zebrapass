//! Sync and health views.

use crossterm::event::KeyEvent;
use record::TAG_PASSWORD;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::editor::{EditorState, Part};
use crate::app::flows::factors::palette_action;
use crate::app::flows::generator::GeneratorState;
use crate::app::flows::home::{Filter, Pane};
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::Nav;
use crate::secure::health::HealthReport;
use crate::ui::widgets::toast::Tone;

/// A row of the health view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthRow {
    /// All weak passwords.
    Weak,
    /// One reuse group.
    Reused(usize),
    /// All old passwords.
    Old,
}

/// Rows for `report`.
#[must_use]
pub fn health_rows(report: &HealthReport) -> Vec<HealthRow> {
    let mut rows = vec![HealthRow::Weak];
    rows.extend((0..report.reused.len()).map(HealthRow::Reused));
    rows.push(HealthRow::Old);
    rows
}

/// Handle a key on the sync or health view.
pub fn on_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    match state.view {
        View::Sync => sync_key(state, event, ctx),
        View::Health(_) => health_key(state, event, ctx),
        _ => Nav::Stay,
    }
}

fn sync_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let Some(action) = resolve(Scope::Sync, event) else {
        return Nav::Stay;
    };
    if action == Action::Back {
        state.view = View::Home;
        Nav::Stay
    } else {
        palette_action(state, action, ctx)
    }
}

fn health_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let Some(action) = resolve(Scope::Health, event) else {
        return Nav::Stay;
    };
    let Some(report) = state.health.as_deref() else {
        state.view = View::Home;
        return Nav::Stay;
    };
    let rows = health_rows(report);
    let View::Health(cursor) = &mut state.view else {
        return Nav::Stay;
    };
    let row = rows.get(*cursor).copied();
    let ids: Vec<u32> = match row {
        Some(HealthRow::Weak) => report.weak.to_vec(),
        Some(HealthRow::Reused(group)) => report
            .reused
            .get(group)
            .map(|ids| ids.to_vec())
            .unwrap_or_default(),
        Some(HealthRow::Old) => report.old.to_vec(),
        None => Vec::new(),
    };
    match action {
        Action::Up => *cursor = cursor.saturating_sub(1),
        Action::Down => *cursor = (*cursor + 1).min(rows.len().saturating_sub(1)),
        Action::Back => state.view = View::Home,
        Action::Confirm => {
            state.home.filter = match row {
                Some(HealthRow::Weak) => Filter::Weak,
                Some(HealthRow::Reused(_)) => Filter::Reused,
                Some(HealthRow::Old) => Filter::Old,
                None => Filter::All,
            };
            state.home.pane = Pane::List;
            state.view = View::Home;
            state.home.selected = 0;
            if let Some(id) = ids.first() {
                state.select(*id);
            }
            state.load_detail();
        }
        Action::Regenerate => regenerate(state, ids.first().copied(), ctx),
        _ => {}
    }
    Nav::Stay
}

/// Open the editor on `id` with the generator aimed at its password.
fn regenerate(state: &mut Unlocked, id: Option<u32>, ctx: &mut Ctx) {
    let Some(id) = id else {
        ctx.toast(Tone::Info, "Nothing to regenerate in this group.");
        return;
    };
    let Some(doc) = state
        .vault
        .as_ref()
        .and_then(|vault| session::open_record(&vault.session, id).ok())
    else {
        return;
    };
    let mut editor = EditorState::edit(id, &doc);
    let target = editor
        .fields
        .iter()
        .position(|field| field.tag == TAG_PASSWORD);
    if let Some(index) = target {
        editor.focus = editor
            .stops()
            .iter()
            .position(|stop| *stop == (index, Part::Value))
            .unwrap_or(0);
    }
    state.view = View::Editor(Box::new(editor));
    state.generator = Some(Box::new(GeneratorState::new(target, ctx)));
}
