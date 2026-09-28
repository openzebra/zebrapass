//! `KeePass` / `KeePassXC` `.kdbx` databases, opened with their password and
//! key file.
//!
//! The KDF cost in the untrusted header is bounded before `keepass` runs
//! the KDF. Every failure to open is one message, so the screen never tells
//! a wrong password from a wrong key file or a damaged file.

use keepass::db::GroupId;
use keepass::{Database, DatabaseKey};

use crate::item::{Draft, Item, ItemKind};
use crate::kdbx_header::{check, kdf_cost};
use crate::keepass_keys::apply_string;
use crate::report::{Report, SkipReason};

/// The single open failure.
const OPEN_FAILED: &str =
    "couldn't open the database: wrong password or key file, or a damaged file";

/// Credentials for a database.
pub struct Credentials<'a> {
    /// Master password, when the database uses one.
    pub password: Option<&'a [u8]>,
    /// Key-file bytes, when the database uses one.
    pub key_file: Option<&'a [u8]>,
}

/// Open and read a database.
///
/// # Errors
///
/// `unlock cost too high` before any KDF runs; `enter the password…` without
/// credentials; one uniform open failure; `too many items`.
pub fn read(
    bytes: &[u8],
    credentials: &Credentials<'_>,
    folders_as_tags: bool,
    report: &mut Report,
) -> anyhow::Result<Vec<Item>> {
    check(kdf_cost(bytes)?)?;
    if credentials.password.is_none() && credentials.key_file.is_none() {
        anyhow::bail!("enter the database password or choose its key file");
    }
    let mut key = DatabaseKey::new();
    if let Some(password) = credentials.password {
        let password = std::str::from_utf8(password).map_err(|_| anyhow::anyhow!(OPEN_FAILED))?;
        key = key.with_password(password);
    }
    if let Some(mut key_file) = credentials.key_file {
        key = key
            .with_keyfile(&mut key_file)
            .map_err(|_| anyhow::anyhow!(OPEN_FAILED))?;
    }
    let db = Database::parse(bytes, key).map_err(|_| anyhow::anyhow!(OPEN_FAILED))?;
    let bin = db.recycle_bin().map(|group| group.id());
    let mut items = Vec::new();
    let mut index = 0usize;
    // Depth-first with an explicit stack: nesting depth never touches the
    // call stack.
    let mut stack: Vec<(GroupId, Vec<String>, bool)> = vec![(db.root().id(), Vec::new(), false)];
    while let Some((id, path, trashed)) = stack.pop() {
        let Some(group) = db.group(id) else {
            continue;
        };
        for entry in group.entries() {
            let title = entry.get_title().unwrap_or_default().into();
            if trashed {
                report.skip(index, SkipReason::Trashed, title);
            } else {
                let draft = map_entry(&entry, &path, folders_as_tags, report);
                report.admit(&mut items, index, draft)?;
            }
            index += 1;
        }
        for child in group.groups() {
            let mut child_path = path.clone();
            child_path.push(child.name.clone());
            let in_bin = trashed || is_bin(bin, child.id());
            stack.push((child.id(), child_path, in_bin));
        }
    }
    Ok(items)
}

fn is_bin(bin: Option<GroupId>, id: GroupId) -> bool {
    bin.is_some_and(|bin| bin == id)
}

fn map_entry(
    entry: &keepass::db::EntryRef<'_>,
    path: &[String],
    folders_as_tags: bool,
    report: &mut Report,
) -> Draft {
    let mut draft = Draft::new(ItemKind::Login);
    let mut keys: Vec<&String> = entry.fields.keys().collect();
    keys.sort_unstable_by_key(|key| (!is_standard(key), key.as_str()));
    let get = |name: &str| entry.fields.get(name).map(|value| value.get().as_str());
    for key in keys {
        if let Some(value) = entry.fields.get(key) {
            apply_string(&mut draft, key, value.get(), value.is_protected(), get);
        }
    }
    for tag in &entry.tags {
        draft.tag(tag);
    }
    if folders_as_tags && !path.is_empty() {
        draft.tag(&path.join("/"));
    }
    if entry.get_password().is_none_or(str::is_empty) {
        draft.set_kind(ItemKind::Note);
    }
    if entry
        .history
        .as_ref()
        .is_some_and(|history| !history.get_entries().is_empty())
    {
        report.history = report.history.saturating_add(1);
    }
    let attachments = u32::try_from(entry.attachments().count()).unwrap_or(u32::MAX);
    report.attachments = report.attachments.saturating_add(attachments);
    draft
}

/// Standard keys go first so they take the standard fields.
fn is_standard(key: &str) -> bool {
    matches!(
        key,
        "Title" | "UserName" | "Password" | "URL" | "Notes" | "otp"
    )
}
