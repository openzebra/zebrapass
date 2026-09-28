//! Enpass `.json` export.

use serde::de::IgnoredAny;
use serde::Deserialize;

use crate::item::{Draft, Item, ItemKind, Slot};
use crate::limits::MAX_ITEMS;
use crate::report::{Report, SkipReason};
use crate::text::{text, Text};

/// Most folder levels followed up the parent chain.
const MAX_FOLDER_DEPTH: usize = 16;

#[derive(Deserialize)]
struct Export {
    #[serde(default)]
    folders: Vec<Folder>,
    #[serde(default)]
    items: Vec<Entry>,
}

#[derive(Deserialize)]
struct Folder {
    uuid: Option<String>,
    parent_uuid: Option<String>,
    title: Option<Text>,
}

#[derive(Deserialize)]
struct Entry {
    title: Option<Text>,
    note: Option<Text>,
    category: Option<String>,
    #[serde(default)]
    favorite: u8,
    #[serde(default)]
    trashed: u8,
    #[serde(default)]
    archived: u8,
    #[serde(default)]
    folders: Vec<String>,
    #[serde(default)]
    fields: Vec<Field>,
    attachments: Option<Vec<IgnoredAny>>,
}

#[derive(Deserialize)]
struct Field {
    label: Option<Text>,
    #[serde(rename = "type")]
    kind: Option<String>,
    value: Option<Text>,
    #[serde(default)]
    sensitive: u8,
    #[serde(default)]
    deleted: u8,
}

/// Read an Enpass export.
///
/// # Errors
///
/// `not an Enpass export` when the JSON does not parse; `too many items`.
pub fn read(bytes: &[u8], folders_as_tags: bool, report: &mut Report) -> anyhow::Result<Vec<Item>> {
    let export: Export =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("not an Enpass export"))?;
    if export.items.len() > MAX_ITEMS {
        anyhow::bail!("too many items");
    }
    let mut items = Vec::with_capacity(export.items.len());
    for (index, entry) in export.items.iter().enumerate() {
        if entry.trashed != 0 {
            report.skip(
                index,
                SkipReason::Trashed,
                text(entry.title.as_ref()).into(),
            );
            continue;
        }
        let mut draft = map(entry);
        let attachments = entry.attachments.as_ref().map_or(0, Vec::len);
        report.attachments = report
            .attachments
            .saturating_add(u32::try_from(attachments).unwrap_or(u32::MAX));
        if folders_as_tags {
            for id in &entry.folders {
                draft.tag(&folder_path(&export.folders, id));
            }
        }
        report.admit(&mut items, index, draft)?;
    }
    Ok(items)
}

fn map(entry: &Entry) -> Draft {
    let mut draft = Draft::new(match entry.category.as_deref() {
        Some("login" | "password") => ItemKind::Login,
        Some("creditcard") => ItemKind::Card,
        Some("identity") => ItemKind::Identity,
        _ => ItemKind::Note,
    });
    draft.put(Slot::Title, text(entry.title.as_ref()));
    draft.put(Slot::Notes, text(entry.note.as_ref()));
    draft.favorite(entry.favorite != 0);
    if entry.archived != 0 {
        draft.tag("archived");
    }
    for field in entry.fields.iter().filter(|field| field.deleted == 0) {
        let label = text(field.label.as_ref());
        let value = text(field.value.as_ref());
        match field.kind.as_deref() {
            Some("username") => draft.put(Slot::Username, value),
            Some("email") => draft.put(Slot::Email, value),
            Some("password") => draft.put(Slot::Password, value),
            Some("url") => draft.put(Slot::Url, value),
            Some("totp") => draft.put(Slot::Totp, value),
            Some("section") => {}
            _ if field.sensitive != 0 => draft.secret(label, value),
            _ => draft.text(label, value),
        }
    }
    if draft.kind() == ItemKind::Login && !draft.has(Slot::Password) {
        draft.set_kind(ItemKind::Note);
    }
    draft
}

/// `Parent/Child` for folder `id`, following at most [`MAX_FOLDER_DEPTH`]
/// parents so a cycle cannot loop.
fn folder_path(folders: &[Folder], id: &str) -> String {
    let mut names = Vec::new();
    let mut current = Some(id);
    for _ in 0..MAX_FOLDER_DEPTH {
        let Some(folder) = current.and_then(|id| {
            folders
                .iter()
                .find(|folder| folder.uuid.as_deref() == Some(id))
        }) else {
            break;
        };
        names.push(text(folder.title.as_ref()));
        current = folder
            .parent_uuid
            .as_deref()
            .filter(|parent| !parent.is_empty());
    }
    names.reverse();
    names.join("/")
}
