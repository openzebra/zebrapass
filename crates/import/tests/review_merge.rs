//! The review model and merging into an open vault.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::multiple_crate_versions,
    reason = "tests may unwrap, index, and panic; keepass pulls duplicate crates"
)]

use std::path::PathBuf;

use import::{expand_home, inspect, into_session, load, Credentials, FileHint, Review, Source};
use record::{Document, TAG_TITLE};
use session::{create, list_records, open_record, BodyAlg, KdfProfile};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn review(name: &str, source: Source) -> Review {
    Review::from(load(&fixture(name), source, Credentials::default()).unwrap())
}

#[test]
fn review_rows_toggles_and_records() {
    let mut review = review("bitwarden.json", Source::BitwardenJson);
    assert_eq!(review.rows().len(), 5);
    let github = &review.rows()[0];
    assert_eq!(
        (&*github.title, &*github.username, &*github.tags),
        ("GitHub", "octocat", "Work")
    );
    assert_eq!(review.included_count(), 5);
    review.toggle(0);
    assert!(!review.is_included(0));
    review.toggle_all();
    assert_eq!(review.included_count(), 5);
    review.toggle_all();
    assert_eq!(review.included_count(), 0);
    review.toggle(1);
    let records = review.into_records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].text(TAG_TITLE).unwrap(), Some("Wifi"));
}

#[test]
fn rows_never_hold_secrets() {
    let review = review("bitwarden.json", Source::BitwardenJson);
    let dump = format!("{:?}", review.rows());
    assert!(!dump.contains("fixture-pw-github"));
    assert!(!dump.contains("4111111111111111"));
}

#[test]
fn merging_twice_adds_nothing_the_second_time() {
    let (mut file, mut session) = create(&[7u8; 64], KdfProfile::Fast, BodyAlg::Frames).unwrap();
    let first = into_session(
        &mut session,
        &mut file,
        review("bitwarden.json", Source::BitwardenJson).into_records(),
    )
    .unwrap();
    assert_eq!((first.ids.len(), first.duplicates), (5, 0));
    let generation = session.generation();

    let second = into_session(
        &mut session,
        &mut file,
        review("bitwarden.json", Source::BitwardenJson).into_records(),
    )
    .unwrap();
    assert_eq!((second.ids.len(), second.duplicates), (0, 5));
    assert_eq!(list_records(&session).unwrap().len(), 5);
    assert!(session.generation() >= generation);
}

#[test]
fn a_changed_record_is_not_a_duplicate() {
    let (mut file, mut session) = create(&[7u8; 64], KdfProfile::Fast, BodyAlg::Frames).unwrap();
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, "GitHub");
    let mut twin = Document::new();
    twin.set_text(TAG_TITLE, "GitHub");
    let mut other = Document::new();
    other.set_text(TAG_TITLE, "GitHub");
    other.set_text(record::TAG_USERNAME, "someone-else");
    let merged = into_session(&mut session, &mut file, vec![doc, twin, other]).unwrap();
    assert_eq!((merged.ids.len(), merged.duplicates), (2, 1));
    let titles: Vec<String> = list_records(&session)
        .unwrap()
        .iter()
        .map(|row| {
            open_record(&session, row.id)
                .unwrap()
                .text(TAG_TITLE)
                .unwrap()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(titles, ["GitHub", "GitHub"]);
}

#[test]
fn inspect_and_expand_home() {
    assert!(matches!(
        inspect(&fixture("bitwarden.json")),
        FileHint::Found(Some(Source::BitwardenJson), _)
    ));
    assert_eq!(inspect(&fixture("missing.json")), FileHint::Missing);
    assert_eq!(inspect(std::path::Path::new("")), FileHint::Missing);
    if let Some(home) = std::env::var_os("HOME") {
        assert_eq!(expand_home("~/x.csv"), PathBuf::from(home).join("x.csv"));
    }
    assert_eq!(expand_home(" /tmp/a.csv "), PathBuf::from("/tmp/a.csv"));
}

#[test]
fn credentials_debug_is_redacted() {
    let credentials = Credentials {
        password: Some(zeroize::Zeroizing::new(b"hunter2".to_vec())),
        key_file: None,
    };
    assert!(!format!("{credentials:?}").contains("hunter2"));
}
