//! Editor keys and save.

use crossterm::event::{KeyCode, KeyEvent};
use record::{Document, ValueType, TAG_TITLE};

use crate::app::action::Action;
use crate::app::ctx::{Ctx, Task};
use crate::app::flows::dialog::{Confirm, ConfirmKind, Dialog};
use crate::app::flows::editing::{edit_secret, edit_text, printable, Edit};
use crate::app::flows::editor::{EditorState, Part, Slot, Value, ADD_KINDS};
use crate::app::flows::generator::GeneratorState;
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::Nav;
use crate::secure::reveal::RevealKey;
use crate::ui::widgets::toast::Tone;
use crate::vault::ops::Op;
use crate::vault::records::{set_custom_text, CUSTOM_FAVORITE, CUSTOM_TAGS};

/// Handle a key in the editor.
pub fn on_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let View::Editor(editor) = &mut state.view else {
        return Nav::Stay;
    };
    if let Some(cursor) = editor.add_menu {
        match event.code {
            KeyCode::Left => editor.add_menu = Some(cursor.saturating_sub(1)),
            KeyCode::Right => editor.add_menu = Some((cursor + 1).min(ADD_KINDS.len() - 1)),
            KeyCode::Enter => {
                editor.add_menu = None;
                if editor.add(cursor) {
                    editor.dirty = true;
                } else {
                    ctx.toast(
                        Tone::Warn,
                        "No room for that field (limit reached or TOTP already present).",
                    );
                }
            }
            KeyCode::Esc => editor.add_menu = None,
            _ => {}
        }
        return Nav::Stay;
    }
    match resolve(Scope::Editor, event) {
        Some(Action::Save) => save(state, ctx),
        Some(Action::Back) => {
            if editor.dirty {
                state.dialog = Some(Box::new(Dialog::Confirm(Confirm {
                    kind: ConfirmKind::Discard,
                    title: String::from("Discard unsaved changes?"),
                    body: vec![String::from("The record stays as it was.")],
                })));
            } else {
                close(state, ctx);
            }
        }
        Some(Action::GenerateInto) => match editor.focused() {
            Some((index, Part::Value))
                if matches!(
                    editor.fields.get(index).map(|f| &f.value),
                    Some(Value::Secret(_))
                ) =>
            {
                state.generator = Some(Box::new(GeneratorState::new(Some(index), ctx)));
            }
            _ => ctx.toast(
                Tone::Info,
                "Move to a secret field (like Password) to generate into it.",
            ),
        },
        Some(action) => on_action(editor, action, ctx),
        None => type_into(editor, event, ctx),
    }
    Nav::Stay
}

fn on_action(editor: &mut EditorState, action: Action, ctx: &mut Ctx) {
    match action {
        Action::NextField | Action::PrevField => {
            let stops = editor.stops().len().max(1);
            editor.focus = if action == Action::NextField {
                (editor.focus + 1) % stops
            } else {
                (editor.focus + stops - 1) % stops
            };
            if editor.reveal.hide() {
                ctx.redraw();
            }
        }
        Action::RevealField => {
            let key = RevealKey(u32::try_from(editor.focus).unwrap_or(u32::MAX));
            if editor.reveal.toggle(key, ctx.now) {
                ctx.redraw();
            }
        }
        Action::AddField => {
            if editor.can_add() {
                editor.add_menu = Some(0);
            } else {
                ctx.toast(Tone::Warn, "Field limit reached.");
            }
        }
        Action::RemoveField => {
            if editor.remove_focused() {
                editor.dirty = true;
            } else {
                ctx.toast(Tone::Info, "Only custom and TOTP fields can be removed.");
            }
        }
        _ => {}
    }
}

fn type_into(editor: &mut EditorState, event: &KeyEvent, ctx: &mut Ctx) {
    editor.cap_focused();
    let Some((index, part)) = editor.focused() else {
        return;
    };
    let Some(field) = editor.fields.get_mut(index) else {
        return;
    };
    let edit = match (part, &mut field.value, field.name.as_mut()) {
        (Part::Name, _, Some(name)) => edit_text(name, event),
        (Part::Value, Value::Text(input), _) => edit_text(input, event),
        (Part::Value, Value::Secret(input), _) => edit_secret(input, event),
        (Part::Value, Value::Toggle(on), _) => {
            if printable(event) == Some(' ') || event.code == KeyCode::Enter {
                *on = !*on;
                Edit::Consumed
            } else {
                Edit::Ignored
            }
        }
        (Part::Name, _, None) => Edit::Ignored,
    };
    match edit {
        Edit::Consumed => editor.dirty = true,
        Edit::Refused => ctx.toast(
            Tone::Warn,
            "Limit reached: field or record size (1 MiB, 64-char names).",
        ),
        Edit::Ignored => {}
    }
}

/// Leave the editor without saving.
pub fn close(state: &mut Unlocked, ctx: &mut Ctx) {
    state.view = View::Home;
    ctx.redraw();
}

fn save(state: &mut Unlocked, ctx: &mut Ctx) {
    let View::Editor(editor) = &state.view else {
        return;
    };
    let title_empty = editor
        .fields
        .iter()
        .any(|field| field.tag == TAG_TITLE && field.value.is_empty());
    if title_empty {
        ctx.toast(Tone::Warn, "Give the record a title.");
        return;
    }
    let unnamed = editor.fields.iter().any(|field| {
        field.slot == Slot::Custom
            && field
                .name
                .as_ref()
                .is_none_or(|name| name.value().trim().is_empty())
    });
    if unnamed {
        ctx.toast(Tone::Warn, "Custom fields need a name.");
        return;
    }
    let base = match (editor.id, state.vault.as_ref()) {
        (Some(id), Some(vault)) => {
            let Ok(doc) = session::open_record(&vault.session, id) else {
                ctx.toast(Tone::Danger, "The record did not open; nothing saved.");
                return;
            };
            doc
        }
        _ => Document::new(),
    };
    match build(editor, base) {
        Ok(doc) => {
            let id = editor.id;
            state.run(
                Op::Write {
                    id,
                    doc: Box::new(doc),
                },
                Task::Save,
                ctx,
            );
        }
        Err(error) => ctx.toast(Tone::Danger, format!("Not saved: {error}")),
    }
}

/// Apply the editor to `doc`: removals first, then custom fields, then the
/// named tags/favorite fields, so new custom tags never collide.
fn build(editor: &EditorState, mut doc: Document) -> anyhow::Result<Document> {
    for tag in &editor.removed {
        doc.remove(*tag);
    }
    let ordered = editor
        .fields
        .iter()
        .filter(|field| matches!(field.slot, Slot::Standard | Slot::Custom))
        .chain(
            editor
                .fields
                .iter()
                .filter(|field| matches!(field.slot, Slot::Tags | Slot::Favorite)),
        );
    for field in ordered {
        match (field.slot, &field.value) {
            (_, value)
                if value.is_empty() && matches!(field.slot, Slot::Standard | Slot::Custom) =>
            {
                doc.remove(field.tag);
            }
            (Slot::Standard, Value::Text(input)) => doc.set_text(field.tag, input.value()),
            (Slot::Standard, Value::Secret(input)) => {
                doc.set_data(field.tag, ValueType::Secret, input.expose());
            }
            (Slot::Custom, value) => {
                let name = field.name.as_ref().map_or("", |name| name.value().trim());
                match value {
                    Value::Text(input) => {
                        doc.set_custom(field.tag, name, ValueType::Text, input.value().as_bytes())?;
                    }
                    Value::Secret(input) => {
                        doc.set_custom(field.tag, name, ValueType::Secret, input.expose())?;
                    }
                    Value::Toggle(_) => {}
                }
            }
            (Slot::Tags, Value::Text(input)) => {
                set_custom_text(&mut doc, CUSTOM_TAGS, Some(input.value().trim()))?;
            }
            (Slot::Favorite, Value::Toggle(on)) => {
                set_custom_text(&mut doc, CUSTOM_FAVORITE, on.then_some("1"))?;
            }
            (Slot::Standard | Slot::Tags | Slot::Favorite, _) => {}
        }
    }
    doc.encode()?;
    Ok(doc)
}
