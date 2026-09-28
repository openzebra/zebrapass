//! The CSV column step of the import wizard: which column feeds what.
//! Headers, samples, and cycling come from the `import` crate.

use import::{csv_columns, Column, Credentials, Mapping};

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::import::{ImportState, ImportStep};

/// Columns being mapped.
#[derive(Debug)]
pub struct Columns {
    /// Headers and first-row samples.
    pub columns: Box<[Column]>,
    /// Target per column.
    pub mapping: Mapping,
    /// Selected column.
    pub cursor: usize,
}

impl ImportState {
    /// Read the CSV header; review the columns when the export is not a
    /// known one, read it straight away otherwise.
    pub(crate) fn open_columns(&mut self, ctx: &mut Ctx) {
        match csv_columns(&self.resolved_path()) {
            Ok((columns, mapping)) => {
                let review = mapping.needs_review();
                self.columns = Some(Box::new(Columns {
                    columns,
                    mapping,
                    cursor: 0,
                }));
                if review {
                    self.step = ImportStep::Mapping;
                } else {
                    self.read(Credentials::default(), ctx);
                }
            }
            Err(error) => self.error = Some(error.to_string().into_boxed_str()),
        }
    }

    /// A key on the column step.
    pub(crate) fn on_mapping(&mut self, action: Action, ctx: &mut Ctx) {
        if action == Action::Back {
            self.columns = None;
            self.error = None;
            self.step = ImportStep::File;
            return;
        }
        if action == Action::Confirm {
            self.error = None;
            self.read(Credentials::default(), ctx);
            return;
        }
        let Some(state) = self.columns.as_deref_mut() else {
            return;
        };
        let last = state.columns.len().saturating_sub(1);
        match action {
            Action::Up => state.cursor = state.cursor.saturating_sub(1),
            Action::Down => state.cursor = (state.cursor + 1).min(last),
            Action::Left | Action::Right => {
                if let Some(target) = state.mapping.targets.get(state.cursor).copied() {
                    let next = target.cycle(action == Action::Right);
                    state.mapping.set(state.cursor, next);
                }
            }
            _ => {}
        }
    }

    /// The mapping to read with, when columns were reviewed.
    pub(crate) fn mapping(&self) -> Option<Mapping> {
        self.columns.as_ref().map(|columns| columns.mapping.clone())
    }
}
