//! Record history: revisions newest first, what changed, masked view, and
//! restore-as-new-revision.

use crossterm::event::KeyEvent;
use record::{Document, ValueType};
use subtle::ConstantTimeEq;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::dialog::{Confirm, ConfirmKind, Dialog};
use crate::app::flows::home::Detail;
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::Nav;
use crate::vault::records::standard_label;
use crate::vault::Vault;

/// One revision row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistRow {
    /// Revision.
    pub revision: u64,
    /// Device that sealed it.
    pub origin: [u8; 16],
    /// Advisory time.
    pub timestamp_ms: u64,
    /// What changed from the previous revision.
    pub change: String,
}

/// History view state.
#[derive(Debug)]
pub struct HistoryState {
    /// Record id.
    pub id: u32,
    /// Record title.
    pub title: String,
    /// Rows, newest first.
    pub rows: Vec<HistRow>,
    /// Selected row.
    pub selected: usize,
    /// A revision opened read-only (masked).
    pub view: Option<Box<Detail>>,
}

impl HistoryState {
    /// Load the history of `id`.
    ///
    /// # Errors
    ///
    /// Frame-index errors from the core.
    pub fn load(vault: &Vault, id: u32, title: String) -> anyhow::Result<Self> {
        let infos = session::history(&vault.session, id)?;
        let docs: Vec<Option<Document>> = infos
            .iter()
            .map(|info| session::open_revision(&vault.session, id, info.revision).ok())
            .collect();
        let mut rows: Vec<HistRow> = infos
            .iter()
            .enumerate()
            .map(|(index, info)| {
                let change = match (
                    index.checked_sub(1).and_then(|prev| docs.get(prev)),
                    docs.get(index),
                ) {
                    (None, _) => String::from("created"),
                    (Some(Some(before)), Some(Some(after))) => diff(before, after),
                    _ => String::from("unreadable"),
                };
                HistRow {
                    revision: info.revision,
                    origin: info.origin_device,
                    timestamp_ms: info.timestamp_ms,
                    change,
                }
            })
            .collect();
        rows.reverse();
        Ok(Self {
            id,
            title,
            rows,
            selected: 0,
            view: None,
        })
    }
}

/// `password changed, url edited` — field names only, compared in constant
/// time, never the values.
#[must_use]
pub fn diff(before: &Document, after: &Document) -> String {
    let mut tags: Vec<u16> = before
        .fields()
        .iter()
        .chain(after.fields())
        .map(|field| field.tag)
        .collect();
    tags.sort_unstable();
    tags.dedup();
    let changes: Vec<String> = tags
        .iter()
        .filter_map(|tag| {
            let name = if record::is_custom(*tag) {
                after
                    .custom_name(*tag)
                    .ok()
                    .flatten()
                    .or_else(|| before.custom_name(*tag).ok().flatten())
                    .unwrap_or("custom")
                    .to_owned()
            } else {
                standard_label(*tag).to_lowercase()
            };
            match (before.get(*tag), after.get(*tag)) {
                (None, Some(_)) => Some(format!("{name} added")),
                (Some(_), None) => Some(format!("{name} removed")),
                (Some(old), Some(new)) if !bool::from(old.value.ct_eq(&new.value)) => {
                    let verb = if new.vtype == ValueType::Text {
                        "edited"
                    } else {
                        "changed"
                    };
                    Some(format!("{name} {verb}"))
                }
                _ => None,
            }
        })
        .collect();
    match changes.len() {
        0 => String::from("no field changes"),
        1 | 2 => changes.join(", "),
        more => format!(
            "{}, {} +{} more",
            changes.first().map_or("", String::as_str),
            changes.get(1).map_or("", String::as_str),
            more - 2
        ),
    }
}

/// Handle a key on the history view.
pub fn on_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let Some(action) = resolve(Scope::History, event) else {
        return Nav::Stay;
    };
    let View::History(history) = &mut state.view else {
        return Nav::Stay;
    };
    let row = history.rows.get(history.selected).cloned();
    match action {
        Action::Up => history.selected = history.selected.saturating_sub(1),
        Action::Down => {
            history.selected = (history.selected + 1).min(history.rows.len().saturating_sub(1));
        }
        Action::Confirm => {
            if history.view.take().is_some() {
                ctx.redraw();
            } else if let Some(row) = row {
                history.view = state
                    .vault
                    .as_ref()
                    .and_then(|vault| {
                        session::open_revision(&vault.session, history.id, row.revision).ok()
                    })
                    .map(|doc| {
                        Box::new(Detail::new(history.id, row.revision, row.timestamp_ms, doc))
                    });
            }
        }
        Action::RestoreRevision => {
            if let Some(row) = row {
                let id = history.id;
                state.dialog = Some(Box::new(Dialog::Confirm(Confirm {
                    kind: ConfirmKind::RestoreRevision(id, row.revision),
                    title: format!("Restore revision {}?", row.revision),
                    body: vec![String::from(
                        "It is copied into a NEW revision; history stays as it is.",
                    )],
                })));
            }
        }
        Action::Back => {
            if history.view.take().is_some() {
                ctx.redraw();
            } else {
                state.view = View::Home;
            }
        }
        _ => {}
    }
    Nav::Stay
}

#[cfg(test)]
mod tests {
    use record::{Document, ValueType, TAG_PASSWORD, TAG_TITLE, TAG_URL};

    use super::diff;

    #[test]
    fn diff_names_fields_without_values() {
        let mut before = Document::new();
        before.set_text(TAG_TITLE, "GitHub");
        before.set_data(TAG_PASSWORD, ValueType::Secret, b"old-secret");
        let mut after = Document::new();
        after.set_text(TAG_TITLE, "GitHub");
        after.set_data(TAG_PASSWORD, ValueType::Secret, b"new-secret");
        after.set_text(TAG_URL, "https://github.com");
        let text = diff(&before, &after);
        assert_eq!(text, "url added, password changed");
        assert!(!text.contains("secret"));
    }
}
