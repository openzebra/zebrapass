//! CSV column editing: headers, safe samples, cycling, and re-reading
//! with an edited mapping.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::multiple_crate_versions,
    reason = "tests may unwrap, index, and panic; keepass pulls duplicate crates"
)]

use std::path::PathBuf;

use import::{csv_columns, Credentials, Load, Slot, Source, Target, TARGETS};
use record::{TAG_TITLE, TAG_USERNAME};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn columns_show_samples_only_where_they_cannot_be_secret() {
    let (columns, mapping) = csv_columns(&fixture("generic.csv")).unwrap();
    let headers: Vec<&str> = columns.iter().map(|column| &*column.header).collect();
    assert_eq!(headers, ["Account", "Login", "Password", "Recovery PIN"]);
    assert!(mapping.needs_review());
    let samples: Vec<Option<&str>> = columns
        .iter()
        .zip(mapping.targets.iter())
        .map(|(column, target)| column.sample(*target))
        .collect();
    assert_eq!(samples, [None, Some("dave"), None, None]);
    assert_eq!(
        columns[0].sample(Target::Field(Slot::Title)),
        Some("Bank, Inc.")
    );
    assert!(!format!("{columns:?}").contains("pw4"));
}

#[test]
fn known_exports_need_no_review() {
    let (_, mapping) = csv_columns(&fixture("chrome.csv")).unwrap();
    assert!(!mapping.needs_review());
}

#[test]
fn targets_cycle_both_ways_through_every_target() {
    let mut target = TARGETS[0];
    for _ in 0..TARGETS.len() {
        target = target.cycle(true);
    }
    assert_eq!(target, TARGETS[0]);
    assert_eq!(TARGETS[0].cycle(false), TARGETS[TARGETS.len() - 1]);
}

#[test]
fn an_edited_mapping_is_used_when_reading() {
    let (_, mut mapping) = csv_columns(&fixture("generic.csv")).unwrap();
    mapping.set(0, Target::Field(Slot::Title));
    mapping.set(3, Target::Ignore);
    let parsed = Load {
        path: fixture("generic.csv"),
        source: Source::Csv,
        credentials: Credentials::default(),
        mapping: Some(mapping),
    }
    .run()
    .unwrap();
    let doc = &parsed.items[0].doc;
    assert_eq!(doc.text(TAG_TITLE).unwrap(), Some("Bank, Inc."));
    assert_eq!(doc.text(TAG_USERNAME).unwrap(), Some("dave"));
    assert!(doc
        .fields()
        .iter()
        .all(|field| !record::is_custom(field.tag)));
}
