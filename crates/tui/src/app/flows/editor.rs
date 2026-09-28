//! Record editor state. Text fields use `TextInput`, secret fields use
//! `SecretInput`; the field kind decides and cannot be mixed up. Record
//! limits are enforced while typing, before any buffer grows.

use record::{
    Document, ValueType, MAX_CUSTOM_NAME, MAX_DOC_LEN, MAX_FIELDS, TAG_EMAIL, TAG_NOTES,
    TAG_PASSWORD, TAG_TITLE, TAG_TOTP, TAG_URL, TAG_USERNAME,
};

use crate::secure::reveal::RevealGuard;
use crate::secure::secret_input::SecretInput;
use crate::ui::input::TextInput;
use crate::vault::records::{
    custom_text, next_custom_tag, standard_label, CUSTOM_FAVORITE, CUSTOM_TAGS,
};

/// Largest value of one field (the wire length prefix is a `u16`).
pub const VALUE_MAX: usize = u16::MAX as usize;
/// Wire overhead of one field: tag, type, length.
const FIELD_OVERHEAD: usize = 5;
/// Wire overhead of the document: schema and count.
const DOC_OVERHEAD: usize = 4;

/// A field value.
pub enum Value {
    /// Text.
    Text(TextInput),
    /// Secret.
    Secret(SecretInput),
    /// On/off.
    Toggle(bool),
}

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Text(_) => "Text",
            Self::Secret(_) => "Secret([REDACTED])",
            Self::Toggle(_) => "Toggle",
        })
    }
}

impl Value {
    /// Encoded length.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Text(input) => input.len(),
            Self::Secret(input) => input.len(),
            Self::Toggle(on) => usize::from(*on),
        }
    }

    /// Whether the field would be omitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Where a field is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// A standard tag.
    Standard,
    /// The `tags` custom field.
    Tags,
    /// The `favorite` custom field.
    Favorite,
    /// A named custom field.
    Custom,
}

/// One editable field.
#[derive(Debug)]
pub struct EditField {
    /// Record tag (custom tags are allocated at creation).
    pub tag: u16,
    /// Storage.
    pub slot: Slot,
    /// Label for standard fields.
    pub label: &'static str,
    /// Name input for custom fields.
    pub name: Option<TextInput>,
    /// Value.
    pub value: Value,
}

/// Focus stop inside a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// Custom field name.
    Name,
    /// Value.
    Value,
}

/// New-field types offered by "+ Add field".
pub const ADD_KINDS: [&str; 3] = ["text", "secret", "totp"];

/// Editor state.
#[derive(Debug)]
pub struct EditorState {
    /// Record id; `None` for a new record.
    pub id: Option<u32>,
    /// Title when opened, for the header.
    pub title: String,
    /// Fields in display order.
    pub fields: Vec<EditField>,
    /// Custom tags removed in this edit.
    pub removed: Vec<u16>,
    /// Focus stop index.
    pub focus: usize,
    /// Unsaved changes.
    pub dirty: bool,
    /// "+ Add field" menu cursor, while open.
    pub add_menu: Option<usize>,
    /// Reveal of one secret field.
    pub reveal: RevealGuard,
    /// Next custom tag to allocate.
    pub next_custom: Option<u16>,
    /// Encoded bytes of fields the editor keeps but does not show.
    pub preserved_len: usize,
    /// Count of those fields.
    pub preserved_count: usize,
}

fn text(tag: u16, value: &str) -> EditField {
    EditField {
        tag,
        slot: Slot::Standard,
        label: standard_label(tag),
        name: None,
        value: Value::Text(TextInput::with_value(value, VALUE_MAX)),
    }
}

fn secret(tag: u16, value: &[u8]) -> EditField {
    let mut input = SecretInput::new(VALUE_MAX);
    input.set(value);
    EditField {
        tag,
        slot: Slot::Standard,
        label: standard_label(tag),
        name: None,
        value: Value::Secret(input),
    }
}

impl EditorState {
    /// Empty login template.
    #[must_use]
    pub fn new_record() -> Self {
        let mut fields = vec![
            text(TAG_TITLE, ""),
            text(TAG_URL, ""),
            text(TAG_USERNAME, ""),
            text(TAG_EMAIL, ""),
            secret(TAG_PASSWORD, b""),
            secret(TAG_NOTES, b""),
        ];
        fields.push(EditField {
            tag: 0,
            slot: Slot::Tags,
            label: "Tags",
            name: None,
            value: Value::Text(TextInput::new(VALUE_MAX)),
        });
        fields.push(EditField {
            tag: 0,
            slot: Slot::Favorite,
            label: "Favorite",
            name: None,
            value: Value::Toggle(false),
        });
        Self {
            id: None,
            title: String::from("New record"),
            fields,
            removed: Vec::new(),
            focus: 0,
            dirty: false,
            add_menu: None,
            reveal: RevealGuard::default(),
            next_custom: Some(record::TAG_CUSTOM_MIN),
            preserved_len: 0,
            preserved_count: 0,
        }
    }

    /// Editor for record `id`.
    #[must_use]
    pub fn edit(id: u32, doc: &Document) -> Self {
        let mut state = Self::new_record();
        state.id = Some(id);
        doc.text(TAG_TITLE)
            .ok()
            .flatten()
            .unwrap_or("record")
            .clone_into(&mut state.title);
        state
            .fields
            .retain(|field| matches!(field.slot, Slot::Tags | Slot::Favorite));
        let mut standard: Vec<EditField> = [
            TAG_TITLE,
            TAG_URL,
            TAG_USERNAME,
            TAG_EMAIL,
            TAG_PASSWORD,
            TAG_NOTES,
            TAG_TOTP,
        ]
        .iter()
        .filter(|tag| **tag != TAG_TOTP || doc.get(TAG_TOTP).is_some())
        .map(|tag| match doc.get(*tag) {
            Some(field) if field.vtype == ValueType::Text => {
                text(*tag, doc.text(*tag).ok().flatten().unwrap_or(""))
            }
            Some(field) => secret(*tag, &field.value),
            None if matches!(*tag, TAG_PASSWORD | TAG_NOTES) => secret(*tag, b""),
            None => text(*tag, ""),
        })
        .collect();
        let custom: Vec<EditField> = doc
            .fields()
            .iter()
            .filter(|field| record::is_custom(field.tag) && field.vtype != ValueType::Bytes)
            .filter_map(|field| {
                let name = doc.custom_name(field.tag).ok().flatten()?;
                if name == CUSTOM_TAGS || name == CUSTOM_FAVORITE {
                    return None;
                }
                let data = doc.data(field.tag).ok().flatten().unwrap_or_default();
                let value = if field.vtype == ValueType::Text {
                    Value::Text(TextInput::with_value(
                        std::str::from_utf8(data).unwrap_or(""),
                        VALUE_MAX,
                    ))
                } else {
                    let mut input = SecretInput::new(VALUE_MAX);
                    input.set(data);
                    Value::Secret(input)
                };
                Some(EditField {
                    tag: field.tag,
                    slot: Slot::Custom,
                    label: "Custom",
                    name: Some(TextInput::with_value(name, MAX_CUSTOM_NAME)),
                    value,
                })
            })
            .collect();
        standard.extend(custom);
        standard.append(&mut state.fields);
        state.fields = standard;
        for field in &mut state.fields {
            match (&field.slot, &mut field.value) {
                (Slot::Tags, Value::Text(input)) => {
                    input.set(custom_text(doc, CUSTOM_TAGS).unwrap_or(""));
                }
                (Slot::Favorite, Value::Toggle(on)) => {
                    *on = custom_text(doc, CUSTOM_FAVORITE) == Some("1");
                }
                _ => {}
            }
        }
        let managed = |tag: u16| {
            state.fields.iter().any(|field| field.tag == tag)
                || matches!(
                    doc.custom_name(tag).ok().flatten(),
                    Some(CUSTOM_TAGS | CUSTOM_FAVORITE)
                )
        };
        let preserved: Vec<usize> = doc
            .fields()
            .iter()
            .filter(|field| !managed(field.tag))
            .map(|field| FIELD_OVERHEAD + field.value.len())
            .collect();
        state.preserved_count = preserved.len();
        state.preserved_len = preserved.iter().sum();
        state.next_custom = next_custom_tag(doc);
        state
    }

    /// Focus stops in order.
    #[must_use]
    pub fn stops(&self) -> Vec<(usize, Part)> {
        self.fields
            .iter()
            .enumerate()
            .flat_map(|(index, field)| {
                let name = field.name.is_some().then_some((index, Part::Name));
                name.into_iter()
                    .chain(std::iter::once((index, Part::Value)))
            })
            .collect()
    }

    /// The focused stop.
    #[must_use]
    pub fn focused(&self) -> Option<(usize, Part)> {
        self.stops().get(self.focus).copied()
    }

    /// Encoded size estimate of the document being edited.
    #[must_use]
    pub fn estimated_size(&self) -> usize {
        let managed: usize = self
            .fields
            .iter()
            .filter(|field| !field.value.is_empty())
            .map(|field| {
                let name = match field.slot {
                    Slot::Standard => 0,
                    Slot::Tags => 1 + CUSTOM_TAGS.len(),
                    Slot::Favorite => 1 + CUSTOM_FAVORITE.len(),
                    Slot::Custom => 1 + field.name.as_ref().map_or(0, TextInput::len),
                };
                FIELD_OVERHEAD + name + field.value.len()
            })
            .sum();
        DOC_OVERHEAD + self.preserved_len + managed
    }

    /// Fields the saved document will have.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.preserved_count
            + self
                .fields
                .iter()
                .filter(|field| !field.value.is_empty())
                .count()
    }

    /// Cap the focused input at what the record limits still allow, before
    /// the keystroke lands: the field's own wire length and the document
    /// budget, including the overhead an empty field adds once it has data.
    pub fn cap_focused(&mut self) {
        let Some((index, part)) = self.focused() else {
            return;
        };
        let size = self.estimated_size();
        let Some(field) = self.fields.get_mut(index) else {
            return;
        };
        let name_overhead = match field.slot {
            Slot::Standard => 0,
            Slot::Tags => 1 + CUSTOM_TAGS.len(),
            Slot::Favorite => 1 + CUSTOM_FAVORITE.len(),
            Slot::Custom => 1 + field.name.as_ref().map_or(0, TextInput::len),
        };
        let value_len = field.value.len();
        let pending = if value_len == 0 {
            FIELD_OVERHEAD + name_overhead
        } else {
            0
        };
        let budget = MAX_DOC_LEN.saturating_sub(size + pending);
        let value_cap = VALUE_MAX.saturating_sub(name_overhead);
        match (part, &mut field.value, field.name.as_mut()) {
            (Part::Value, Value::Secret(input), _) => {
                input.set_max((input.len() + budget).min(value_cap));
            }
            (Part::Value, Value::Text(input), _) => {
                input.set_max((input.len() + budget).min(value_cap));
            }
            (Part::Name, _, Some(name)) => {
                let room = if value_len == 0 {
                    MAX_CUSTOM_NAME
                } else {
                    name.len() + budget
                };
                name.set_max(
                    room.min(MAX_CUSTOM_NAME)
                        .min(VALUE_MAX.saturating_sub(value_len + 1)),
                );
            }
            (Part::Name, _, None) | (Part::Value, Value::Toggle(_), _) => {}
        }
    }

    /// Whether another field fits.
    #[must_use]
    pub fn can_add(&self) -> bool {
        self.field_count() < MAX_FIELDS && self.next_custom.is_some()
    }

    /// Add a field of kind `ADD_KINDS[kind]`.
    pub fn add(&mut self, kind: usize) -> bool {
        let totp = kind == 2;
        if totp {
            if self.fields.iter().any(|field| field.tag == TAG_TOTP) {
                return false;
            }
            let at = self
                .fields
                .iter()
                .position(|field| field.slot != Slot::Standard)
                .unwrap_or(self.fields.len());
            self.fields.insert(at, secret(TAG_TOTP, b""));
            return true;
        }
        let Some(tag) = self.next_custom.filter(|_| self.can_add()) else {
            return false;
        };
        self.next_custom = tag.checked_add(1);
        let value = if kind == 0 {
            Value::Text(TextInput::new(VALUE_MAX))
        } else {
            Value::Secret(SecretInput::new(VALUE_MAX))
        };
        let at = self
            .fields
            .iter()
            .position(|field| matches!(field.slot, Slot::Tags | Slot::Favorite))
            .unwrap_or(self.fields.len());
        self.fields.insert(
            at,
            EditField {
                tag,
                slot: Slot::Custom,
                label: "Custom",
                name: Some(TextInput::new(MAX_CUSTOM_NAME)),
                value,
            },
        );
        self.focus = self
            .stops()
            .iter()
            .position(|(index, _)| *index == at)
            .unwrap_or(self.focus);
        true
    }

    /// Remove the focused custom or TOTP field.
    pub fn remove_focused(&mut self) -> bool {
        let Some((index, _)) = self.focused() else {
            return false;
        };
        let removable = self
            .fields
            .get(index)
            .is_some_and(|field| field.slot == Slot::Custom || field.tag == TAG_TOTP);
        if !removable {
            return false;
        }
        let field = self.fields.remove(index);
        self.removed.push(field.tag);
        self.focus = self.focus.min(self.stops().len().saturating_sub(1));
        true
    }

    /// Put a generated value into the focused secret field.
    pub fn fill_generated(&mut self, value: &[u8]) {
        if let Some((index, Part::Value)) = self.focused() {
            if let Some(Value::Secret(input)) =
                self.fields.get_mut(index).map(|field| &mut field.value)
            {
                if input.set(value) {
                    self.dirty = true;
                }
            }
        }
    }

    /// Paste into the focused input.
    pub fn on_paste(&mut self, text: &str) {
        self.cap_focused();
        let Some((index, part)) = self.focused() else {
            return;
        };
        let Some(field) = self.fields.get_mut(index) else {
            return;
        };
        let inserted = match (part, &mut field.value, field.name.as_mut()) {
            (Part::Name, _, Some(name)) => name.insert_str(text),
            (Part::Value, Value::Text(input), _) => input.insert_str(text),
            (Part::Value, Value::Secret(input), _) => input.insert_str(text),
            _ => 0,
        };
        self.dirty |= inserted > 0;
    }
}
