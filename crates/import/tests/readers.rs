//! Bitwarden JSON and CSV readers against synthetic fixtures.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap, index, and panic"
)]

use std::path::PathBuf;

use import::{
    parse, read_file, sniff, Item, ItemKind, Parsed, Preset, Request, SkipReason, Source,
};
use record::{
    ValueType, CUSTOM_FAVORITE, CUSTOM_TAGS, TAG_EMAIL, TAG_NOTES, TAG_PASSWORD, TAG_TITLE,
    TAG_TOTP, TAG_URL, TAG_USERNAME,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn run(name: &str, source: Source) -> anyhow::Result<Parsed> {
    parse(&Request {
        bytes: read_file(&fixture(name)).unwrap(),
        source,
        mapping: None,
        folders_as_tags: true,
    })
}

fn custom<'a>(item: &'a Item, name: &str) -> Option<(&'a [u8], ValueType)> {
    item.doc
        .fields()
        .iter()
        .filter(|field| record::is_custom(field.tag))
        .find(|field| item.doc.custom_name(field.tag).unwrap() == Some(name))
        .map(|field| (item.doc.data(field.tag).unwrap().unwrap(), field.vtype))
}

fn titled<'a>(parsed: &'a Parsed, title: &str) -> &'a Item {
    parsed
        .items
        .iter()
        .find(|item| item.doc.text(TAG_TITLE).unwrap() == Some(title))
        .unwrap()
}

#[test]
fn bitwarden_maps_every_type() {
    let parsed = run("bitwarden.json", Source::BitwardenJson).unwrap();
    assert_eq!(parsed.items.len(), 5);
    let report = &parsed.report;
    assert_eq!(report.kinds, [1, 1, 1, 1, 1]);
    assert_eq!(
        (report.passkeys, report.history, report.linked_fields),
        (1, 1, 1)
    );
    let reasons: Vec<_> = report.skipped.iter().map(|skip| skip.reason).collect();
    assert_eq!(reasons, [SkipReason::Trashed, SkipReason::Empty]);

    let github = titled(&parsed, "GitHub");
    let doc = &github.doc;
    assert_eq!(doc.text(TAG_URL).unwrap(), Some("https://github.com"));
    assert_eq!(doc.text(TAG_USERNAME).unwrap(), Some("octocat"));
    assert_eq!(
        doc.data(TAG_PASSWORD).unwrap().unwrap(),
        b"fixture-pw-github"
    );
    assert_eq!(doc.get(TAG_TOTP).unwrap().vtype, ValueType::Secret);
    assert_eq!(doc.text(TAG_NOTES).unwrap(), Some("dev account"));
    assert_eq!(
        custom(github, "url 2").unwrap().0,
        b"https://gist.github.com"
    );
    assert_eq!(
        custom(github, "recovery").unwrap(),
        (b"rc-secret-777".as_slice(), ValueType::Secret)
    );
    assert_eq!(custom(github, "team").unwrap().1, ValueType::Text);
    assert_eq!(custom(github, CUSTOM_TAGS).unwrap().0, b"Work");
    assert_eq!(custom(github, CUSTOM_FAVORITE).unwrap().0, b"1");

    let card = titled(&parsed, "Visa");
    assert_eq!(card.kind, ItemKind::Card);
    assert_eq!(custom(card, "number").unwrap().1, ValueType::Secret);
    assert_eq!(custom(card, "security code").unwrap().1, ValueType::Secret);
    assert_eq!(custom(card, "expires").unwrap().0, b"12/2030");
    assert_eq!(custom(card, "kind").unwrap().0, b"card");

    let me = titled(&parsed, "Me");
    assert_eq!(me.doc.text(TAG_EMAIL).unwrap(), Some("jane@example.com"));
    assert_eq!(custom(me, "full name").unwrap().0, b"Jane Doe");
    assert_eq!(custom(me, "ssn").unwrap().1, ValueType::Secret);

    let key = titled(&parsed, "Server key");
    assert_eq!(key.kind, ItemKind::SshKey);
    assert_eq!(custom(key, "private key").unwrap().1, ValueType::Secret);
}

#[test]
fn bitwarden_encrypted_export_is_refused() {
    let error = run("bitwarden_encrypted.json", Source::BitwardenJson).unwrap_err();
    assert!(error.to_string().contains("password-protected"));
}

#[test]
fn garbage_is_not_a_bitwarden_export_and_the_error_echoes_nothing() {
    let error = parse(&Request {
        bytes: zeroize::Zeroizing::new(b"{\"items\": [{\"type\": \"leaked-secret\"}]}".to_vec()),
        source: Source::BitwardenJson,
        mapping: None,
        folders_as_tags: true,
    })
    .unwrap_err()
    .to_string();
    assert_eq!(error, "not a Bitwarden export");
}

#[test]
fn chrome_and_firefox_csv() {
    let chrome = run("chrome.csv", Source::Csv).unwrap();
    assert_eq!(chrome.mapping.as_ref().unwrap().preset, Preset::Chrome);
    assert_eq!(chrome.items.len(), 2);
    let github = titled(&chrome, "GitHub");
    assert_eq!(
        github.doc.data(TAG_PASSWORD).unwrap().unwrap(),
        b"fixture-pw-chrome"
    );
    assert_eq!(github.doc.text(TAG_NOTES).unwrap(), Some("dev"));

    let firefox = run("firefox.csv", Source::Csv).unwrap();
    assert_eq!(firefox.mapping.as_ref().unwrap().preset, Preset::Firefox);
    let only = &firefox.items[0];
    assert_eq!(
        only.doc.text(TAG_TITLE).unwrap(),
        Some("accounts.example.org")
    );
    assert!(only
        .doc
        .fields()
        .iter()
        .all(|field| !record::is_custom(field.tag)));
}

#[test]
fn lastpass_notes_folders_and_favorites() {
    let parsed = run("lastpass.csv", Source::Csv).unwrap();
    assert_eq!(parsed.mapping.as_ref().unwrap().preset, Preset::LastPass);
    let site = titled(&parsed, "Site");
    assert_eq!(custom(site, CUSTOM_TAGS).unwrap().0, b"Personal/Web");
    assert_eq!(custom(site, CUSTOM_FAVORITE).unwrap().0, b"1");
    let note = titled(&parsed, "My note");
    assert_eq!(note.kind, ItemKind::Note);
    assert!(note.doc.get(TAG_URL).is_none());
    assert_eq!(note.doc.text(TAG_NOTES).unwrap(), Some("secret note body"));
}

#[test]
fn generic_csv_keeps_unknown_columns_and_skips_short_rows() {
    let parsed = run("generic.csv", Source::Csv).unwrap();
    assert_eq!(parsed.mapping.as_ref().unwrap().preset, Preset::Generic);
    assert_eq!(parsed.items.len(), 1);
    let bank = &parsed.items[0];
    assert_eq!(bank.doc.text(TAG_USERNAME).unwrap(), Some("dave"));
    assert_eq!(custom(bank, "Account").unwrap().0, b"Bank, Inc.");
    assert_eq!(custom(bank, "Recovery PIN").unwrap().1, ValueType::Secret);
    assert_eq!(parsed.report.skipped[0].reason, SkipReason::Malformed);
}

#[test]
fn csv_without_known_headers_is_refused() {
    let error = parse(&Request {
        bytes: zeroize::Zeroizing::new(b"a,b\n1,2\n".to_vec()),
        source: Source::Csv,
        mapping: None,
        folders_as_tags: true,
    })
    .unwrap_err();
    assert!(error.to_string().starts_with("no known columns"));
}

#[test]
fn sniff_guesses_each_format() {
    assert_eq!(
        sniff(
            &[0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0, 0],
            None
        ),
        Some(Source::Kdbx)
    );
    assert_eq!(
        sniff(b"<?xml ?><KeePassFile>", None),
        Some(Source::KeepassXml)
    );
    assert_eq!(
        sniff(b"{\"encrypted\": false", None),
        Some(Source::BitwardenJson)
    );
    assert_eq!(
        sniff(b"{\"items\":[{\"category\":\"login\"", None),
        Some(Source::EnpassJson)
    );
    assert_eq!(sniff(b"name,url\n", Some("txt")), Some(Source::Csv));
    assert_eq!(sniff(b"hello", Some("bin")), None);
}

#[test]
fn parsed_debug_never_shows_passwords() {
    let parsed = run("bitwarden.json", Source::BitwardenJson).unwrap();
    let dump = format!("{parsed:?}");
    assert!(!dump.contains("fixture-pw-github"));
    assert!(!dump.contains("rc-secret-777"));
}
