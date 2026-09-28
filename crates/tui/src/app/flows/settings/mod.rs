//! The settings modal over Home.
//!
//! A section rail and a row list; staged edits preview live and save only
//! on apply; search spans every row; a posture meter scores the draft.
//! Actions that change keys open the usual guarded forms.

pub mod apply;
pub mod posture;
pub mod rows;

use crossterm::event::KeyEvent;
use local::{Prefs, ORIGIN_MAX};

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::editing::edit_text;
use crate::app::flows::unlocked::Unlocked;
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::Nav;
use crate::ui::input::TextInput;

use rows::{in_section, matching, Row, Section};

/// Longest search query.
const MAX_QUERY: usize = 40;

/// Where typing goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    /// The row list.
    Rows,
    /// The search field.
    Filter,
    /// A text setting being edited.
    Edit,
}

/// Settings modal state.
#[derive(Debug)]
pub struct SettingsModal {
    /// Section on the rail.
    pub section: Section,
    /// Selected row among the visible ones.
    pub cursor: usize,
    /// Where keys go.
    pub focus: Focus,
    /// Staged preferences.
    pub draft: Prefs,
    /// What is saved (or running, before the first save).
    pub saved: Prefs,
    /// Search query across every section.
    pub filter: TextInput,
    /// Text of the setting being edited.
    pub edit: TextInput,
    /// Why the last edit was refused.
    pub error: Option<&'static str>,
}

impl SettingsModal {
    /// Open over the running settings of `state`.
    #[must_use]
    pub fn open(state: &Unlocked, ctx: &Ctx) -> Self {
        let saved = ctx.running_prefs(state.info.prefs.as_ref());
        Self {
            section: Section::Security,
            cursor: 0,
            focus: Focus::Rows,
            draft: saved.clone(),
            saved,
            filter: TextInput::new(MAX_QUERY),
            edit: TextInput::new(ORIGIN_MAX),
            error: None,
        }
    }

    /// Rows on screen: the search hits, or the current section.
    #[must_use]
    pub fn visible(&self) -> Vec<Row> {
        if self.filter.is_empty() {
            in_section(self.section).collect()
        } else {
            matching(self.filter.value()).collect()
        }
    }

    /// The selected row.
    #[must_use]
    pub fn row(&self) -> Option<Row> {
        self.visible().get(self.cursor).copied()
    }

    /// How many rows differ from what is saved.
    #[must_use]
    pub fn unsaved(&self) -> usize {
        rows::changes(&self.draft, &self.saved).count()
    }

    /// Keymap scope of the focus.
    #[must_use]
    pub const fn scope(&self) -> Scope {
        match self.focus {
            Focus::Rows => Scope::Settings,
            Focus::Filter => Scope::Search,
            Focus::Edit => Scope::SettingsEdit,
        }
    }

    fn move_section(&mut self, forward: bool) {
        let all = Section::ALL;
        let at = all
            .iter()
            .position(|section| *section == self.section)
            .unwrap_or(0);
        let next = if forward { at + 1 } else { at + all.len() - 1 } % all.len();
        self.section = all.get(next).copied().unwrap_or(Section::Security);
        self.filter.clear();
        self.cursor = 0;
    }

    fn move_cursor(&mut self, down: bool) {
        let last = self.visible().len().saturating_sub(1);
        self.cursor = if down {
            (self.cursor + 1).min(last)
        } else {
            self.cursor.saturating_sub(1)
        };
    }
}

/// Handle a key while the modal is open.
pub fn on_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let Some(modal) = state.settings.as_deref_mut() else {
        return Nav::Stay;
    };
    match modal.focus {
        Focus::Filter => filter_key(modal, event),
        Focus::Edit => edit_key(modal, event),
        Focus::Rows => return rows_key(state, event, ctx),
    }
    Nav::Stay
}

fn filter_key(modal: &mut SettingsModal, event: &KeyEvent) {
    match resolve(Scope::Search, event) {
        Some(Action::Back) => {
            modal.filter.clear();
            modal.focus = Focus::Rows;
        }
        Some(Action::Confirm) => modal.focus = Focus::Rows,
        Some(Action::Up) => modal.move_cursor(false),
        Some(Action::Down) => modal.move_cursor(true),
        _ => {
            edit_text(&mut modal.filter, event);
            modal.cursor = 0;
        }
    }
}

fn edit_key(modal: &mut SettingsModal, event: &KeyEvent) {
    match resolve(Scope::SettingsEdit, event) {
        Some(Action::Back) => {
            modal.focus = Focus::Rows;
            modal.error = None;
        }
        Some(Action::Confirm) => {
            let typed = modal.edit.value().trim();
            if typed.is_empty() {
                modal.draft.server_origin = None;
                modal.focus = Focus::Rows;
                modal.error = None;
                return;
            }
            match local::parse_origin(typed) {
                Ok(origin) => {
                    modal.draft.server_origin = Some(origin);
                    modal.focus = Focus::Rows;
                    modal.error = None;
                }
                Err(reason) => modal.error = Some(reason),
            }
        }
        _ => {
            edit_text(&mut modal.edit, event);
            modal.error = None;
        }
    }
}

fn rows_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let Some(action) = resolve(Scope::Settings, event) else {
        return Nav::Stay;
    };
    let Some(modal) = state.settings.as_deref_mut() else {
        return Nav::Stay;
    };
    let row = modal.row();
    match action {
        Action::Up => modal.move_cursor(false),
        Action::Down => modal.move_cursor(true),
        Action::NextField => modal.move_section(true),
        Action::PrevField => modal.move_section(false),
        Action::Search => modal.focus = Focus::Filter,
        Action::Left | Action::Right => {
            if let Some(row) = row.filter(|row| row.adjustable()) {
                row.adjust(&mut modal.draft, action == Action::Right);
                ctx.preview_look(&modal.draft);
            }
        }
        Action::ResetSetting => {
            if let Some(row) = row {
                row.reset(&mut modal.draft);
                ctx.preview_look(&modal.draft);
            }
        }
        Action::ResetSection => {
            let section = row.map_or(modal.section, Row::section);
            in_section(section).for_each(|row| row.reset(&mut modal.draft));
            ctx.preview_look(&modal.draft);
        }
        Action::Save => apply::save(state, ctx),
        Action::Back => apply::close(state, ctx),
        Action::Confirm => {
            if let Some(row) = row {
                return apply::activate(state, row, ctx);
            }
        }
        _ => {}
    }
    Nav::Stay
}

/// Paste into the focused text field.
pub fn on_paste(modal: &mut SettingsModal, text: &str) {
    match modal.focus {
        Focus::Filter => {
            modal.filter.insert_str(text);
        }
        Focus::Edit => {
            modal.edit.insert_str(text);
        }
        Focus::Rows => {}
    }
}
