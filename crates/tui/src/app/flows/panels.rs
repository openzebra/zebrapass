//! Sync, health, and settings views.

use std::time::Duration;

use crossterm::event::KeyEvent;
use record::TAG_PASSWORD;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::dialog::Dialog;
use crate::app::flows::editor::{EditorState, Part};
use crate::app::flows::factors::palette_action;
use crate::app::flows::form::Form;
use crate::app::flows::generator::GeneratorState;
use crate::app::flows::home::{Filter, Pane};
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::Nav;
use crate::cli::{Flags, CLIP_CLEAR_RANGE, LOCK_AFTER_RANGE};
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

/// Settings rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setting {
    /// Color theme.
    Theme,
    /// Animations.
    Animation,
    /// ASCII glyphs.
    Ascii,
    /// Auto-lock delay.
    AutoLock,
    /// Clipboard clear delay.
    ClipClear,
    /// Lock on focus loss.
    FocusLock,
    /// Vault name on this device.
    Name,
    /// Clear history.
    ClearHistory,
}

/// Settings in display order.
pub const SETTINGS: [Setting; 8] = [
    Setting::Theme,
    Setting::Animation,
    Setting::Ascii,
    Setting::AutoLock,
    Setting::ClipClear,
    Setting::FocusLock,
    Setting::Name,
    Setting::ClearHistory,
];

/// Settings cursor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SettingsState {
    /// Selected row.
    pub selected: usize,
}

/// Handle a key on the sync, health, or settings view.
pub fn on_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    match state.view {
        View::Sync(_) => sync_key(state, event, ctx),
        View::Health(_) => health_key(state, event, ctx),
        View::Settings(_) => settings_key(state, event, ctx),
        _ => Nav::Stay,
    }
}

fn sync_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let Some(action) = resolve(Scope::Sync, event) else {
        return Nav::Stay;
    };
    let rows = state.pending_sync.len();
    match (action, &mut state.view) {
        (Action::Up, View::Sync(cursor)) => *cursor = cursor.saturating_sub(1),
        (Action::Down, View::Sync(cursor)) => *cursor = (*cursor + 1).min(rows.saturating_sub(1)),
        (Action::Back, _) => state.view = View::Home,
        (action, _) => return palette_action(state, action, ctx),
    }
    Nav::Stay
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

fn settings_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let Some(action) = resolve(Scope::Settings, event) else {
        return Nav::Stay;
    };
    let View::Settings(settings) = &mut state.view else {
        return Nav::Stay;
    };
    let setting = SETTINGS
        .get(settings.selected)
        .copied()
        .unwrap_or(Setting::Theme);
    match action {
        Action::Up => settings.selected = settings.selected.saturating_sub(1),
        Action::Down => settings.selected = (settings.selected + 1).min(SETTINGS.len() - 1),
        Action::Back => state.view = View::Home,
        Action::Left | Action::Right | Action::Confirm => {
            let delta: i64 = if action == Action::Left { -1 } else { 1 };
            match setting {
                Setting::Name if action == Action::Confirm => {
                    state.dialog = Some(Box::new(Dialog::Form(Box::new(Form::rename(
                        &state.info.label,
                    )))));
                }
                Setting::ClearHistory if action == Action::Confirm => {
                    return palette_action(state, Action::ClearHistory, ctx);
                }
                Setting::Name | Setting::ClearHistory => {}
                other => adjust(other, delta, ctx),
            }
        }
        _ => {}
    }
    Nav::Stay
}

/// Change a setting by one step.
pub fn adjust(setting: Setting, delta: i64, ctx: &mut Ctx) {
    match setting {
        Setting::Theme => {
            ctx.theme.name = ctx.theme.name.next();
            ctx.retheme();
            ctx.redraw();
        }
        Setting::Animation => {
            ctx.flags = ctx.flags.with(Flags::ANIM, !ctx.flags.has(Flags::ANIM));
            ctx.retheme();
        }
        Setting::Ascii => {
            ctx.flags = ctx.flags.with(Flags::ASCII, !ctx.flags.has(Flags::ASCII));
            ctx.retheme();
            ctx.redraw();
        }
        Setting::AutoLock => {
            let secs = shift(ctx.idle.after().as_secs(), delta * 30, &LOCK_AFTER_RANGE);
            ctx.idle.set_after(Duration::from_secs(secs));
        }
        Setting::ClipClear => {
            let secs = shift(
                ctx.clipboard.clear_after().as_secs(),
                delta * 5,
                &CLIP_CLEAR_RANGE,
            );
            ctx.clipboard.set_clear_after(Duration::from_secs(secs));
        }
        Setting::FocusLock => {
            ctx.flags = ctx
                .flags
                .with(Flags::FOCUS_LOCK, !ctx.flags.has(Flags::FOCUS_LOCK));
        }
        Setting::Name | Setting::ClearHistory => {}
    }
}

fn shift(value: u64, delta: i64, range: &std::ops::RangeInclusive<u64>) -> u64 {
    let moved = if delta < 0 {
        value.saturating_sub(delta.unsigned_abs())
    } else {
        value.saturating_add(delta.unsigned_abs())
    };
    moved.clamp(*range.start(), *range.end())
}
