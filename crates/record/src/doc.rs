//! Document parse, encode, and field access.

use std::fmt;

use zeroize::Zeroize;

use crate::limits::{MAX_CUSTOM_NAME, MAX_DOC_LEN, MAX_FIELDS, SCHEMA_VERSION};
use crate::tags::is_custom;

/// Wire type of one field value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueType {
    /// UTF-8 text, validated at parse time.
    Text,
    /// Secret bytes; wiped with the document.
    Secret,
    /// Opaque bytes.
    Bytes,
}

impl ValueType {
    const TEXT: u8 = 0;
    const SECRET: u8 = 1;
    const BYTES: u8 = 2;

    /// Wire discriminator.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Text => Self::TEXT,
            Self::Secret => Self::SECRET,
            Self::Bytes => Self::BYTES,
        }
    }

    /// `None` when the byte is not a known wire type.
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            Self::TEXT => Some(Self::Text),
            Self::SECRET => Some(Self::Secret),
            Self::BYTES => Some(Self::Bytes),
            _ => None,
        }
    }
}

/// One document field.
///
/// `value` is the raw wire value: the data itself for standard tags, and
/// `name_len ‖ name ‖ data` for custom tags. Unknown tags are kept here
/// verbatim so they survive an edit round trip.
pub struct Field {
    /// Field tag.
    pub tag: u16,
    /// Wire type of `value`.
    pub vtype: ValueType,
    /// Raw wire value.
    pub value: Vec<u8>,
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("tag", &self.tag)
            .field("vtype", &self.vtype)
            .field("value_len", &self.value.len())
            .finish()
    }
}

impl Drop for Field {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// A parsed document: schema version plus typed fields.
///
/// Dropping the document wipes every field value.
#[derive(Debug)]
pub struct Document {
    fields: Vec<Field>,
}

impl Default for Document {
    fn default() -> Self {
        Self::new()
    }
}

impl Document {
    /// An empty document.
    #[must_use]
    pub const fn new() -> Self {
        Self { fields: Vec::new() }
    }

    /// All fields in wire order.
    #[must_use]
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    /// Parse an encoded document.
    ///
    /// Text values and custom names are validated as UTF-8 here; unknown
    /// tags and unknown kinds of payload are kept as they are.
    ///
    /// # Errors
    ///
    /// `schema too new` when the schema version is greater than
    /// [`SCHEMA_VERSION`]; `too many fields` above [`MAX_FIELDS`];
    /// `document too large` above [`MAX_DOC_LEN`]; `unknown value type`
    /// for a wire type this build does not know; `custom name too long`
    /// past [`MAX_CUSTOM_NAME`]; `invalid text encoding` for non-UTF-8
    /// `Text` data; `corrupted length` for any truncation or trailing bytes.
    pub fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() > MAX_DOC_LEN {
            anyhow::bail!("document too large");
        }
        let mut pos = 0usize;
        let schema = read_u16(bytes, &mut pos)?;
        if schema > SCHEMA_VERSION {
            anyhow::bail!("schema too new");
        }
        let count = read_u16(bytes, &mut pos)? as usize;
        if count > MAX_FIELDS {
            anyhow::bail!("too many fields");
        }
        let mut fields = Vec::with_capacity(count);
        for _ in 0..count {
            let tag = read_u16(bytes, &mut pos)?;
            let byte = read_u8(bytes, &mut pos)?;
            let vtype = ValueType::from_u8(byte).ok_or_else(|| anyhow::anyhow!("unknown value type"))?;
            let len = read_u16(bytes, &mut pos)? as usize;
            let value = read_bytes(bytes, &mut pos, len)?.to_vec();
            validate_field(tag, vtype, &value)?;
            fields.push(Field { tag, vtype, value });
        }
        if pos != bytes.len() {
            anyhow::bail!("corrupted length");
        }
        Ok(Self { fields })
    }

    /// Encode the document.
    ///
    /// # Errors
    ///
    /// `too many fields` above [`MAX_FIELDS`]; `value too long` when a field
    /// value exceeds 64 KiB; `document too large` above [`MAX_DOC_LEN`].
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        if self.fields.len() > MAX_FIELDS {
            anyhow::bail!("too many fields");
        }
        let mut out = Vec::new();
        out.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
        let count = u16::try_from(self.fields.len()).map_err(|_| anyhow::anyhow!("too many fields"))?;
        out.extend_from_slice(&count.to_le_bytes());
        for field in &self.fields {
            let len = u16::try_from(field.value.len()).map_err(|_| anyhow::anyhow!("value too long"))?;
            out.extend_from_slice(&field.tag.to_le_bytes());
            out.push(field.vtype.to_u8());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&field.value);
        }
        if out.len() > MAX_DOC_LEN {
            anyhow::bail!("document too large");
        }
        Ok(out)
    }

    /// The field with `tag`, if present.
    #[must_use]
    pub fn get(&self, tag: u16) -> Option<&Field> {
        self.fields.iter().find(|field| field.tag == tag)
    }

    /// The data of `tag`: the value for standard tags, the part after the
    /// name for custom tags.
    ///
    /// # Errors
    ///
    /// `corrupted length` when a custom value does not carry a name prefix.
    pub fn data(&self, tag: u16) -> anyhow::Result<Option<&[u8]>> {
        self.get(tag).map_or(Ok(None), |field| field_data(field).map(Some))
    }

    /// The UTF-8 data of a `Text` field.
    ///
    /// # Errors
    ///
    /// Same as [`Self::data`].
    pub fn text(&self, tag: u16) -> anyhow::Result<Option<&str>> {
        self.data(tag)?
            .map(std::str::from_utf8)
            .transpose()
            .map_err(|_| anyhow::anyhow!("invalid text encoding"))
    }

    /// The name of a custom field.
    ///
    /// # Errors
    ///
    /// `corrupted length` when the value carries no valid name prefix.
    pub fn custom_name(&self, tag: u16) -> anyhow::Result<Option<&str>> {
        self.get(tag).map_or(Ok(None), |field| {
            custom_prefix(&field.value).map(|(name, _)| Some(name))
        })
    }

    /// Replace or append a standard field with `data`.
    pub fn set_data(&mut self, tag: u16, vtype: ValueType, data: &[u8]) {
        self.replace(Field {
            tag,
            vtype,
            value: data.to_vec(),
        });
    }

    /// Replace or append a `Text` field.
    pub fn set_text(&mut self, tag: u16, text: &str) {
        self.set_data(tag, ValueType::Text, text.as_bytes());
    }

    /// Replace or append a custom field with `name` and `data`.
    ///
    /// # Errors
    ///
    /// `custom name too long` when `name` exceeds [`MAX_CUSTOM_NAME`].
    pub fn set_custom(&mut self, tag: u16, name: &str, vtype: ValueType, data: &[u8]) -> anyhow::Result<()> {
        if name.len() > MAX_CUSTOM_NAME {
            anyhow::bail!("custom name too long");
        }
        let name_len = u8::try_from(name.len()).map_err(|_| anyhow::anyhow!("custom name too long"))?;
        let mut value = Vec::with_capacity(1 + name.len() + data.len());
        value.push(name_len);
        value.extend_from_slice(name.as_bytes());
        value.extend_from_slice(data);
        self.replace(Field {
            tag,
            vtype,
            value,
        });
        Ok(())
    }

    /// Remove the field with `tag`. Returns `true` when it was present.
    pub fn remove(&mut self, tag: u16) -> bool {
        let before = self.fields.len();
        self.fields.retain(|field| field.tag != tag);
        self.fields.len() != before
    }

    fn replace(&mut self, field: Field) {
        for existing in &mut self.fields {
            if existing.tag == field.tag {
                *existing = field;
                return;
            }
        }
        self.fields.push(field);
    }
}

/// Validate one parsed field: UTF-8 text and custom name shapes.
fn validate_field(tag: u16, vtype: ValueType, value: &[u8]) -> anyhow::Result<()> {
    if is_custom(tag) {
        let (name, data) = custom_prefix(value)?;
        if name.len() > MAX_CUSTOM_NAME {
            anyhow::bail!("custom name too long");
        }
        if vtype == ValueType::Text {
            std::str::from_utf8(data).map_err(|_| anyhow::anyhow!("invalid text encoding"))?;
        }
    } else if vtype == ValueType::Text {
        std::str::from_utf8(value).map_err(|_| anyhow::anyhow!("invalid text encoding"))?;
    }
    Ok(())
}

/// The data of a field: everything for standard tags, the part after the
/// name for custom tags.
///
/// # Errors
///
/// `corrupted length` when a custom value does not carry a name prefix.
pub fn field_data(field: &Field) -> anyhow::Result<&[u8]> {
    if is_custom(field.tag) {
        Ok(custom_prefix(&field.value)?.1)
    } else {
        Ok(&field.value)
    }
}

/// Split a custom value into its name and data.
///
/// # Errors
///
/// `corrupted length` when the value does not carry a valid name prefix.
fn custom_prefix(value: &[u8]) -> anyhow::Result<(&str, &[u8])> {
    let name_len = value
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))? as usize;
    let after_len = value
        .len()
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    if name_len > after_len {
        anyhow::bail!("corrupted length");
    }
    let name = std::str::from_utf8(
        value
            .get(1..1 + name_len)
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?,
    )
    .map_err(|_| anyhow::anyhow!("invalid text encoding"))?;
    let data = value
        .get(1 + name_len..)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    Ok((name, data))
}

fn read_u8(bytes: &[u8], pos: &mut usize) -> anyhow::Result<u8> {
    let byte = *bytes
        .get(*pos)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    *pos += 1;
    Ok(byte)
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> anyhow::Result<u16> {
    let end = (*pos)
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let slice = bytes
        .get(*pos..end)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    *pos = end;
    let mut raw = [0u8; 2];
    raw.copy_from_slice(slice);
    Ok(u16::from_le_bytes(raw))
}

fn read_bytes<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> anyhow::Result<&'a [u8]> {
    let end = (*pos)
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let slice = bytes
        .get(*pos..end)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    *pos = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests may unwrap")]

    use crate::limits::{MAX_CUSTOM_NAME, MAX_FIELDS, SCHEMA_VERSION};
    use crate::tags;
    use crate::{Document, ValueType};

    fn sample_doc() -> Document {
        let mut doc = Document::new();
        doc.set_text(tags::TAG_TITLE, "Blog");
        doc.set_data(tags::TAG_PASSWORD, ValueType::Secret, b"hunter2");
        doc
    }

    #[test]
    fn round_trip_preserves_fields() {
        let doc = sample_doc();
        let bytes = doc.encode().unwrap();
        let parsed = Document::parse(&bytes).unwrap();
        assert_eq!(parsed.text(tags::TAG_TITLE).unwrap().unwrap(), "Blog");
        assert_eq!(
            parsed.data(tags::TAG_PASSWORD).unwrap().unwrap(),
            b"hunter2".as_slice()
        );
        assert_eq!(parsed.get(tags::TAG_PASSWORD).unwrap().vtype, ValueType::Secret);
    }

    #[test]
    fn unknown_tags_survive_edit_of_known_field() {
        let mut doc = sample_doc();
        // A future standard tag this build does not interpret, and a
        // custom tag this build does not know, both byte for byte.
        doc.set_data(0x0501, ValueType::Bytes, b"abc");
        doc.set_custom(0xDEAD, "z", ValueType::Secret, &[0xAA, 0xBB]).unwrap();
        let bytes = doc.encode().unwrap();
        let mut parsed = Document::parse(&bytes).unwrap();
        assert_eq!(parsed.text(tags::TAG_TITLE).unwrap().unwrap(), "Blog");
        // Edit the known field; unknown fields must be re-emitted byte for byte.
        parsed.set_text(tags::TAG_TITLE, "New");
        let out = parsed.encode().unwrap();
        assert!(out.windows(3).any(|w| w == b"abc"));
        assert!(out.ends_with(&[0xAA, 0xBB]));
        let reparsed = Document::parse(&out).unwrap();
        assert_eq!(reparsed.text(tags::TAG_TITLE).unwrap().unwrap(), "New");
        assert_eq!(
            reparsed.custom_name(0xDEAD).unwrap().unwrap(),
            "z"
        );
        assert_eq!(
            reparsed.data(0xDEAD).unwrap().unwrap(),
            [0xAA_u8, 0xBB].as_slice()
        );
    }

    #[test]
    fn custom_fields_add_and_lookup() {
        let mut doc = sample_doc();
        doc.set_custom(0x8001, "ssh key", ValueType::Bytes, b"SHA256:...").unwrap();
        let out = doc.encode().unwrap();
        let parsed = Document::parse(&out).unwrap();
        assert_eq!(parsed.custom_name(0x8001).unwrap().unwrap(), "ssh key");
        assert_eq!(
            parsed.data(0x8001).unwrap().unwrap(),
            b"SHA256:...".as_slice()
        );
        assert!(doc.get(0x8001).is_some());
    }

    #[test]
    fn custom_name_length_is_enforced() {
        let mut doc = Document::new();
        let long = "x".repeat(MAX_CUSTOM_NAME + 1);
        assert!(doc.set_custom(0x8001, &long, ValueType::Bytes, b"").is_err());
        let ok = "x".repeat(MAX_CUSTOM_NAME);
        doc.set_custom(0x8001, &ok, ValueType::Bytes, b"").unwrap();
        let parsed = Document::parse(&doc.encode().unwrap()).unwrap();
        assert_eq!(parsed.custom_name(0x8001).unwrap().unwrap(), ok.as_str());
    }

    #[test]
    fn garbage_text_is_rejected() {
        let mut doc = Document::new();
        doc.set_data(tags::TAG_NOTES, ValueType::Text, b"\xff\xfe");
        let bytes = doc.encode().unwrap();
        let err = Document::parse(&bytes).unwrap_err();
        assert_eq!(err.to_string(), "invalid text encoding");
    }

    #[test]
    fn custom_text_data_must_be_utf8() {
        let mut doc = Document::new();
        doc.set_custom(0x8001, "n", ValueType::Text, b"\xff").unwrap();
        let bytes = doc.encode().unwrap();
        assert_eq!(Document::parse(&bytes).unwrap_err().to_string(), "invalid text encoding");
    }

    #[test]
    fn newer_schema_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(SCHEMA_VERSION + 1).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let err = Document::parse(&bytes).unwrap_err();
        assert_eq!(err.to_string(), "schema too new");
    }

    #[test]
    fn unknown_value_type_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&tags::TAG_TITLE.to_le_bytes());
        bytes.push(9);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let err = Document::parse(&bytes).unwrap_err();
        assert_eq!(err.to_string(), "unknown value type");
    }

    #[test]
    fn truncated_and_trailing_input_rejected() {
        let bytes = sample_doc().encode().unwrap();
        let short = bytes
            .get(..bytes.len() - 1)
            .expect("one byte less than the encoding");
        assert_eq!(Document::parse(short).unwrap_err().to_string(), "corrupted length");
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(Document::parse(&long).unwrap_err().to_string(), "corrupted length");
        assert_eq!(Document::parse(&[]).unwrap_err().to_string(), "corrupted length");
    }

    #[test]
    fn field_count_limit() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
        bytes.extend_from_slice(&u16::try_from(MAX_FIELDS + 1).unwrap().to_le_bytes());
        assert_eq!(Document::parse(&bytes).unwrap_err().to_string(), "too many fields");

        let mut doc = Document::new();
        for (i, _) in (0..=MAX_FIELDS).enumerate() {
            let tag = u16::try_from(i).unwrap();
            doc.set_data(tag, ValueType::Bytes, b"");
        }
        assert!(doc.encode().is_err());
    }

    #[test]
    fn setter_replaces_by_tag_in_place() {
        let mut doc = sample_doc();
        assert_eq!(doc.fields().len(), 2);
        doc.set_text(tags::TAG_TITLE, "Other");
        assert_eq!(doc.fields().len(), 2);
        assert_eq!(doc.text(tags::TAG_TITLE).unwrap().unwrap(), "Other");
        assert!(doc.remove(tags::TAG_TITLE));
        assert!(!doc.remove(tags::TAG_TITLE));
        assert_eq!(doc.fields().len(), 1);
    }

    #[test]
    fn oversize_document_rejected() {
        let mut doc = Document::new();
        let blob = vec![0u8; u16::MAX as usize];
        // 17 distinct tags x 64 KiB+5 exceeds the 1 MiB document limit.
        for tag in 0x0100..0x0111_u16 {
            doc.set_data(tag, ValueType::Bytes, &blob);
        }
        assert_eq!(doc.encode().unwrap_err().to_string(), "document too large");
    }

    #[test]
    fn custom_name_corruption_detected() {
        let mut doc = Document::new();
        doc.set_custom(0x8001, "n", ValueType::Bytes, b"d").unwrap();
        let mut bytes = doc.encode().unwrap();
        // schema(2) + count(2) + tag(2) + vtype(1) + len(2) = the name-length byte.
        let name_len_pos = 9usize;
        *bytes.get_mut(name_len_pos).unwrap() = 0x7F;
        assert_eq!(Document::parse(&bytes).unwrap_err().to_string(), "corrupted length");
    }
}
