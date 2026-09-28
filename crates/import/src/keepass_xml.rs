//! `KeePass` 2 XML export, read as a stream: memory stays at one entry and
//! nesting depth is bounded. No DTD or custom entity is ever expanded.

use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::Reader;
use zeroize::Zeroizing;

use crate::item::{Draft, Item, ItemKind, Slot};
use crate::keepass_keys::apply_string;
use crate::limits::{MAX_FIELD, MAX_XML_DEPTH};
use crate::report::{Report, SkipReason};

/// One `<String>` of an entry: key, value, protected.
type Pair = (String, Zeroizing<String>, bool);

/// The entry being read.
#[derive(Default)]
struct EntryState {
    strings: Vec<Pair>,
    key: String,
    value: Zeroizing<String>,
    protected: bool,
    tags: String,
    attachments: u32,
    history: bool,
}

/// One open `<Group>`.
struct GroupState {
    name: String,
    trashed: bool,
}

/// Where text goes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sink {
    None,
    BinUuid,
    GroupName,
    GroupUuid,
    Key,
    Value,
    Tags,
}

/// Parser state across events.
struct Walker<'r> {
    report: &'r mut Report,
    folders_as_tags: bool,
    items: Vec<Item>,
    path: Vec<Box<[u8]>>,
    groups: Vec<GroupState>,
    entry: Option<EntryState>,
    bin_uuid: String,
    group_uuid: String,
    sink: Sink,
    index: usize,
    seen_root: bool,
}

/// Read a `KeePass` XML export.
///
/// # Errors
///
/// `not a KeePass XML export`; `XML nested too deeply`; `this XML holds
/// encrypted values` for a raw database dump; `too many items`.
pub fn read(bytes: &[u8], folders_as_tags: bool, report: &mut Report) -> anyhow::Result<Vec<Item>> {
    let mut reader = Reader::from_reader(bytes);
    let mut walker = Walker {
        report,
        folders_as_tags,
        items: Vec::new(),
        path: Vec::new(),
        groups: Vec::new(),
        entry: None,
        bin_uuid: String::new(),
        group_uuid: String::new(),
        sink: Sink::None,
        index: 0,
        seen_root: false,
    };
    loop {
        match reader.read_event().map_err(|_| malformed())? {
            Event::Start(start) => walker.start(&start)?,
            Event::Empty(start) => walker.empty(&start),
            Event::End(_) => walker.end()?,
            Event::Text(text) => walker.text(&text.decode().map_err(|_| malformed())?)?,
            Event::CData(data) => walker.text(&data.decode().map_err(|_| malformed())?)?,
            Event::GeneralRef(reference) => {
                let mut utf8 = [0u8; 4];
                walker.text(entity(&reference)?.encode_utf8(&mut utf8))?;
            }
            Event::DocType(_) => return Err(malformed()),
            Event::Eof => break,
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) => {}
        }
    }
    if !walker.seen_root || !walker.path.is_empty() {
        return Err(malformed());
    }
    Ok(walker.items)
}

impl Walker<'_> {
    fn start(&mut self, start: &BytesStart<'_>) -> anyhow::Result<()> {
        if self.path.len() >= MAX_XML_DEPTH {
            anyhow::bail!("XML nested too deeply");
        }
        let name: Box<[u8]> = start.local_name().as_ref().into();
        self.sink = self.open(&name, start)?;
        match &*name {
            b"KeePassFile" => self.seen_root = true,
            b"Group" => self.group_uuid.clear(),
            _ => {}
        }
        self.path.push(name);
        Ok(())
    }

    /// A self-closing tag: only an attachment reference matters.
    fn empty(&mut self, start: &BytesStart<'_>) {
        if start.local_name().as_ref() == b"Binary" && self.in_entry() && !self.in_history() {
            if let Some(entry) = self.entry.as_mut() {
                entry.attachments = entry.attachments.saturating_add(1);
            }
        }
    }

    /// Handle an opening tag; returns where its text goes.
    fn open(&mut self, name: &[u8], start: &BytesStart<'_>) -> anyhow::Result<Sink> {
        let parent = self.path.last().map(|parent| &**parent);
        let history = self.in_history();
        Ok(match (name, parent) {
            (b"RecycleBinUUID", Some(b"Meta")) => Sink::BinUuid,
            (b"Group", _) => {
                let trashed = self.groups.last().is_some_and(|group| group.trashed);
                self.groups.push(GroupState {
                    name: String::new(),
                    trashed,
                });
                Sink::None
            }
            (b"Name", Some(b"Group")) => Sink::GroupName,
            (b"UUID", Some(b"Group")) => Sink::GroupUuid,
            (b"Entry", _) if history || parent == Some(b"History") => Sink::None,
            (b"Entry", _) => {
                self.entry = Some(EntryState::default());
                Sink::None
            }
            (b"History", Some(b"Entry")) => {
                if let Some(entry) = self.entry.as_mut().filter(|entry| !entry.history) {
                    entry.history = true;
                    self.report.history = self.report.history.saturating_add(1);
                }
                Sink::None
            }
            _ if history => Sink::None,
            (b"Binary", Some(b"Entry")) => {
                self.empty(start);
                Sink::None
            }
            (b"Tags", Some(b"Entry")) => Sink::Tags,
            (b"Key", Some(b"String")) if self.in_entry() => Sink::Key,
            (b"Value", Some(b"String")) if self.in_entry() => {
                if attribute_true(start, b"Protected")? {
                    anyhow::bail!(
                        "this XML holds encrypted values: open the .kdbx instead, or export from KeePass as XML"
                    );
                }
                if let Some(entry) = self.entry.as_mut() {
                    entry.protected = attribute_true(start, b"ProtectInMemory")?;
                }
                Sink::Value
            }
            _ => Sink::None,
        })
    }

    fn end(&mut self) -> anyhow::Result<()> {
        let name = self.path.pop().ok_or_else(malformed)?;
        self.sink = Sink::None;
        let parent_is_group = self.path.last().is_some_and(|parent| &**parent == b"Group");
        let live_entry = self.in_entry() && !self.in_history();
        match &*name {
            b"UUID" if parent_is_group => {
                let matches = !self.bin_uuid.is_empty() && self.group_uuid == self.bin_uuid;
                if let Some(group) = self.groups.last_mut() {
                    group.trashed |= matches;
                }
            }
            b"String" if live_entry => {
                if let Some(entry) = self.entry.as_mut() {
                    let key = std::mem::take(&mut entry.key);
                    let value = std::mem::take(&mut entry.value);
                    entry.strings.push((key, value, entry.protected));
                }
            }
            b"Group" => {
                self.groups.pop();
            }
            b"Entry" if !self.in_history() => {
                if let Some(done) = self.entry.take() {
                    self.finish(&done)?;
                    self.index += 1;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn text(&mut self, text: &str) -> anyhow::Result<()> {
        let target = match self.sink {
            Sink::None => return Ok(()),
            Sink::BinUuid => &mut self.bin_uuid,
            Sink::GroupUuid => &mut self.group_uuid,
            Sink::GroupName => match self.groups.last_mut() {
                Some(group) => &mut group.name,
                None => return Ok(()),
            },
            Sink::Key => match self.entry.as_mut() {
                Some(entry) => &mut entry.key,
                None => return Ok(()),
            },
            Sink::Tags => match self.entry.as_mut() {
                Some(entry) => &mut entry.tags,
                None => return Ok(()),
            },
            Sink::Value => match self.entry.as_mut() {
                Some(entry) => &mut *entry.value,
                None => return Ok(()),
            },
        };
        if target.len().saturating_add(text.len()) > MAX_FIELD {
            anyhow::bail!("a value in this export is too large");
        }
        target.push_str(text);
        Ok(())
    }

    /// Map a finished entry.
    fn finish(&mut self, entry: &EntryState) -> anyhow::Result<()> {
        self.report.attachments = self.report.attachments.saturating_add(entry.attachments);
        let lookup = |name: &str| {
            entry
                .strings
                .iter()
                .find(|(key, _, _)| key == name)
                .map(|(_, value, _)| value.as_str())
        };
        if self.groups.last().is_some_and(|group| group.trashed) {
            let title = lookup("Title").unwrap_or_default().into();
            self.report.skip(self.index, SkipReason::Trashed, title);
            return Ok(());
        }
        let mut draft = Draft::new(ItemKind::Login);
        let mut order: Vec<&Pair> = entry.strings.iter().collect();
        order.sort_by_key(|(key, _, _)| !is_standard(key));
        for (key, value, protected) in order {
            apply_string(&mut draft, key, value, *protected, lookup);
        }
        for tag in entry.tags.split([';', ',']) {
            draft.tag(tag);
        }
        // The first group is the database root; its name is not a folder.
        let folders: Vec<&str> = self
            .groups
            .iter()
            .skip(1)
            .map(|group| group.name.as_str())
            .collect();
        if self.folders_as_tags && !folders.is_empty() {
            draft.tag(&folders.join("/"));
        }
        if !draft.has(Slot::Password) {
            draft.set_kind(ItemKind::Note);
        }
        self.report.admit(&mut self.items, self.index, draft)
    }

    fn in_entry(&self) -> bool {
        self.path.iter().any(|name| &**name == b"Entry")
    }

    fn in_history(&self) -> bool {
        self.path.iter().any(|name| &**name == b"History")
    }
}

fn is_standard(key: &str) -> bool {
    matches!(
        key,
        "Title" | "UserName" | "Password" | "URL" | "Notes" | "otp"
    )
}

fn attribute_true(start: &BytesStart<'_>, name: &[u8]) -> anyhow::Result<bool> {
    Ok(start
        .try_get_attribute(name)
        .map_err(|_| malformed())?
        .is_some_and(|attribute| attribute.value.eq_ignore_ascii_case(b"true")))
}

/// The five predefined entities and character references; anything else
/// is refused rather than expanded.
fn entity(reference: &BytesRef<'_>) -> anyhow::Result<char> {
    if let Some(ch) = reference.resolve_char_ref().map_err(|_| malformed())? {
        return Ok(ch);
    }
    match reference.decode().map_err(|_| malformed())?.as_ref() {
        "amp" => Ok('&'),
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "quot" => Ok('"'),
        "apos" => Ok('\''),
        _ => Err(malformed()),
    }
}

fn malformed() -> anyhow::Error {
    anyhow::anyhow!("not a KeePass XML export")
}
