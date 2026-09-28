//! The shared `Draft` → `Document` mapping and the report.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap, index, and panic"
)]

use import::{Draft, Item, ItemKind, Report, SkipReason, Slot, MAX_CUSTOM, MAX_FIELD, MAX_ITEMS};
use record::{ValueType, CUSTOM_FAVORITE, CUSTOM_TAGS, TAG_PASSWORD, TAG_TITLE, TAG_TOTP, TAG_URL};

fn custom<'a>(item: &'a Item, name: &str) -> Option<&'a [u8]> {
    item.doc
        .fields()
        .iter()
        .filter(|field| record::is_custom(field.tag))
        .find(|field| item.doc.custom_name(field.tag).unwrap() == Some(name))
        .map(|field| item.doc.data(field.tag).unwrap().unwrap())
}

#[test]
fn login_maps_to_standard_fields() {
    let mut draft = Draft::new(ItemKind::Login);
    draft.put(Slot::Title, " GitHub ");
    draft.put(Slot::Url, "https://github.com");
    draft.put(Slot::Url, "https://gist.github.com");
    draft.put(Slot::Password, " spaced secret ");
    draft.put(Slot::Totp, "JBSWY3DPEHPK3PXP");
    draft.secret("recovery code", "abcd-efgh");
    draft.tag("Work/Dev");
    draft.tag("a,b");
    draft.tag("Work/Dev");
    draft.favorite(true);
    let item = Item::try_from(draft).unwrap();
    let doc = &item.doc;
    assert_eq!(doc.text(TAG_TITLE).unwrap(), Some("GitHub"));
    assert_eq!(doc.text(TAG_URL).unwrap(), Some("https://github.com"));
    assert_eq!(doc.data(TAG_PASSWORD).unwrap().unwrap(), b" spaced secret ");
    assert_eq!(doc.get(TAG_PASSWORD).unwrap().vtype, ValueType::Secret);
    assert_eq!(doc.get(TAG_TOTP).unwrap().vtype, ValueType::Secret);
    assert_eq!(custom(&item, "url 2").unwrap(), b"https://gist.github.com");
    assert_eq!(custom(&item, CUSTOM_TAGS).unwrap(), b"Work/Dev, a b");
    assert_eq!(custom(&item, CUSTOM_FAVORITE).unwrap(), b"1");
    assert!(custom(&item, "kind").is_none());
    let field = doc
        .fields()
        .iter()
        .filter(|field| record::is_custom(field.tag))
        .find(|field| doc.custom_name(field.tag).unwrap() == Some("recovery code"))
        .unwrap();
    assert_eq!(field.vtype, ValueType::Secret);
}

#[test]
fn card_is_marked_and_untitled_items_get_a_title() {
    let mut draft = Draft::new(ItemKind::Card);
    draft.secret("number", "4111111111111111");
    let item = Item::try_from(draft).unwrap();
    assert_eq!(custom(&item, "kind").unwrap(), b"card");
    assert_eq!(item.doc.text(TAG_TITLE).unwrap(), Some("Imported item"));

    let mut draft = Draft::new(ItemKind::Login);
    draft.put(Slot::Url, "https://www.example.com/login");
    let item = Item::try_from(draft).unwrap();
    assert_eq!(item.doc.text(TAG_TITLE).unwrap(), Some("example.com"));
}

#[test]
fn oversize_field_skips_instead_of_truncating() {
    let mut draft = Draft::new(ItemKind::Note);
    draft.put(Slot::Title, "Big");
    draft.put(Slot::Notes, &"x".repeat(MAX_FIELD + 1));
    assert_eq!(Item::try_from(draft).unwrap_err(), SkipReason::TooLarge);
}

#[test]
fn too_many_custom_fields_skip() {
    let mut draft = Draft::new(ItemKind::Login);
    for n in 0..=MAX_CUSTOM {
        draft.text(&format!("f{n}"), "v");
    }
    assert_eq!(
        Item::try_from(draft).unwrap_err(),
        SkipReason::TooManyFields
    );
}

#[test]
fn empty_items_are_reported_with_their_index() {
    let mut report = Report::default();
    let mut items = Vec::new();
    let mut draft = Draft::new(ItemKind::Login);
    draft.put(Slot::Password, "");
    report.admit(&mut items, 4, draft).unwrap();
    let mut draft = Draft::new(ItemKind::Login);
    draft.put(Slot::Title, "Kept");
    report.admit(&mut items, 5, draft).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(report.imported(), 1);
    assert_eq!(report.skipped[0].index, 4);
    assert_eq!(report.skipped[0].reason, SkipReason::Empty);
}

#[test]
fn item_count_is_bounded() {
    let mut report = Report::default();
    let mut items = Vec::new();
    for index in 0..MAX_ITEMS {
        let mut draft = Draft::new(ItemKind::Note);
        draft.put(Slot::Title, "n");
        report.admit(&mut items, index, draft).unwrap();
    }
    let mut draft = Draft::new(ItemKind::Note);
    draft.put(Slot::Title, "one too many");
    assert_eq!(
        report
            .admit(&mut items, MAX_ITEMS, draft)
            .unwrap_err()
            .to_string(),
        "too many items"
    );
}

#[test]
fn debug_output_is_redacted() {
    let mut draft = Draft::new(ItemKind::Login);
    draft.put(Slot::Title, "Bank");
    draft.put(Slot::Password, "hunter2-secret");
    assert!(!format!("{draft:?}").contains("hunter2"));
    let item = Item::try_from(draft).unwrap();
    assert!(!format!("{item:?}").contains("hunter2"));
}
