//! `Document` encode/parse round trips, limits, and rejection paths.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap, index, and panic"
)]

use record::{MAX_CUSTOM_NAME, MAX_FIELDS, SCHEMA_VERSION};
use record::{Document, ValueType, TAG_NOTES, TAG_PASSWORD, TAG_TITLE};

fn sample_doc() -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, "Blog");
    doc.set_data(TAG_PASSWORD, ValueType::Secret, b"hunter2");
    doc
}

#[test]
fn round_trip_preserves_fields() {
    let doc = sample_doc();
    let bytes = doc.encode().unwrap();
    let parsed = Document::parse(&bytes).unwrap();
    assert_eq!(parsed.text(TAG_TITLE).unwrap().unwrap(), "Blog");
    assert_eq!(
        parsed.data(TAG_PASSWORD).unwrap().unwrap(),
        b"hunter2".as_slice()
    );
    assert_eq!(parsed.get(TAG_PASSWORD).unwrap().vtype, ValueType::Secret);
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
    assert_eq!(parsed.text(TAG_TITLE).unwrap().unwrap(), "Blog");
    // Edit the known field; unknown fields must be re-emitted byte for byte.
    parsed.set_text(TAG_TITLE, "New");
    let out = parsed.encode().unwrap();
    assert!(out.windows(3).any(|w| w == b"abc"));
    assert!(out.ends_with(&[0xAA, 0xBB]));
    let reparsed = Document::parse(&out).unwrap();
    assert_eq!(reparsed.text(TAG_TITLE).unwrap().unwrap(), "New");
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
    doc.set_data(TAG_NOTES, ValueType::Text, b"\xff\xfe");
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
    bytes.extend_from_slice(&TAG_TITLE.to_le_bytes());
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
    doc.set_text(TAG_TITLE, "Other");
    assert_eq!(doc.fields().len(), 2);
    assert_eq!(doc.text(TAG_TITLE).unwrap().unwrap(), "Other");
    assert!(doc.remove(TAG_TITLE));
    assert!(!doc.remove(TAG_TITLE));
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
