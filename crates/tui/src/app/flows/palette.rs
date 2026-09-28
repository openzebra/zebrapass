//! Command palette and help overlays.

use crossterm::event::KeyEvent;

use crate::app::action::{Action, Section, PALETTE};
use crate::app::flows::editing::edit_text;
use crate::app::keymap::{resolve, Scope};
use crate::ui::input::TextInput;
use crate::vault::records::fuzzy_score;

/// Longest palette query.
const MAX_QUERY: usize = 64;

/// Overlay above any screen.
#[derive(Debug)]
pub enum Overlay {
    /// Command palette.
    Palette(PaletteState),
    /// Key cheat sheet with its scroll offset.
    Help(u16),
}

/// What the palette decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaletteEvent {
    /// Keep open.
    Stay,
    /// Close.
    Close,
    /// Run this action.
    Run(Action),
}

/// Palette state.
#[derive(Debug)]
pub struct PaletteState {
    /// Query.
    pub query: TextInput,
    /// Selected match.
    pub selected: usize,
}

impl Default for PaletteState {
    fn default() -> Self {
        Self {
            query: TextInput::new(MAX_QUERY),
            selected: 0,
        }
    }
}

impl PaletteState {
    /// Entries matching the query, best first.
    #[must_use]
    pub fn matches(&self) -> Vec<(Action, &'static str, Section)> {
        let query = self.query.value().trim();
        let mut scored: Vec<(i32, usize)> = PALETTE
            .iter()
            .enumerate()
            .filter_map(|(index, (_, label, _))| {
                fuzzy_score(query, label).map(|score| (score, index))
            })
            .collect();
        if !query.is_empty() {
            scored.sort_by(|(a, _), (b, _)| b.cmp(a));
        }
        scored
            .into_iter()
            .filter_map(|(_, index)| PALETTE.get(index).copied())
            .collect()
    }

    /// Handle a key.
    pub fn on_key(&mut self, event: &KeyEvent) -> PaletteEvent {
        match resolve(Scope::Palette, event) {
            Some(Action::Up) => self.selected = self.selected.saturating_sub(1),
            Some(Action::Down) => {
                self.selected = (self.selected + 1).min(self.matches().len().saturating_sub(1));
            }
            Some(Action::Back) => return PaletteEvent::Close,
            Some(Action::Confirm) => {
                return self
                    .matches()
                    .get(self.selected)
                    .map_or(PaletteEvent::Stay, |(action, _, _)| {
                        PaletteEvent::Run(*action)
                    });
            }
            _ => {
                edit_text(&mut self.query, event);
                self.selected = 0;
            }
        }
        PaletteEvent::Stay
    }
}
