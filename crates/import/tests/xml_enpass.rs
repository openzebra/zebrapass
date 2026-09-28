//! `KeePass` XML and Enpass JSON readers against synthetic fixtures.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::multiple_crate_versions,
    reason = "tests may unwrap, index, and panic; keepass pulls duplicate crates"
)]

use std::path::PathBuf;

use import::{parse, read_file, Item, ItemKind, Parsed, Request, SkipReason, Source};
use record::{
    ValueType, CUSTOM_FAVORITE, CUSTOM_TAGS, TAG_EMAIL, TAG_NOTES, TAG_PASSWORD, TAG_TITLE,
    TAG_TOTP, TAG_URL, TAG_USERNAME,
};
use zeroize::Zeroizing;

fn run_bytes(bytes: &[u8], source: Source) -> anyhow::Result<Parsed> {
    parse(&Request {
        bytes: Zeroizing::new(bytes.to_vec()),
        source,
        mapping: None,
        folders_as_tags: true,
        password: None,
        key_file: None,
    })
}

fn run(name: &str, source: Source) -> anyhow::Result<Parsed> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    run_bytes(&read_file(&path).unwrap(), source)
}

fn titled<'a>(parsed: &'a Parsed, title: &str) -> &'a Item {
    parsed
        .items
        .iter()
        .find(|item| item.doc.text(TAG_TITLE).unwrap() == Some(title))
        .unwrap()
}

fn custom<'a>(item: &'a Item, name: &str) -> Option<(&'a [u8], ValueType)> {
    item.doc
        .fields()
        .iter()
        .filter(|field| record::is_custom(field.tag))
        .find(|field| item.doc.custom_name(field.tag).unwrap() == Some(name))
        .map(|field| (item.doc.data(field.tag).unwrap().unwrap(), field.vtype))
}

#[test]
fn keepass_xml_maps_entries_groups_and_entities() {
    let parsed = run("keepass.xml", Source::KeepassXml).unwrap();
    assert_eq!(parsed.items.len(), 2);
    let report = &parsed.report;
    assert_eq!((report.history, report.attachments), (1, 1));
    let skipped: Vec<_> = report
        .skipped
        .iter()
        .map(|s| (s.reason, &*s.title))
        .collect();
    assert_eq!(skipped, [(SkipReason::Trashed, "Deleted login")]);

    let github = titled(&parsed, "GitHub");
    let doc = &github.doc;
    assert_eq!(doc.data(TAG_PASSWORD).unwrap().unwrap(), b"xml-pw-<github>");
    assert_eq!(doc.text(TAG_USERNAME).unwrap(), Some("octocat"));
    assert_eq!(doc.text(TAG_URL).unwrap(), Some("https://github.com"));
    assert_eq!(doc.text(TAG_NOTES).unwrap(), Some("line one\nline two"));
    assert_eq!(doc.get(TAG_TOTP).unwrap().vtype, ValueType::Secret);
    assert_eq!(
        custom(github, "Recovery").unwrap(),
        (b"xml-rc-1".as_slice(), ValueType::Secret)
    );
    assert_eq!(custom(github, "Team").unwrap().1, ValueType::Text);
    assert_eq!(
        custom(github, CUSTOM_TAGS).unwrap().0,
        b"code, infra, Work/Dev & Ops"
    );

    let wifi = titled(&parsed, "Wifi");
    assert_eq!(wifi.kind, ItemKind::Note);
    assert!(
        custom(wifi, CUSTOM_TAGS).is_none(),
        "root-level entries get no folder tag"
    );
}

#[test]
fn keepass_xml_history_never_leaks_into_the_entry() {
    let parsed = run("keepass.xml", Source::KeepassXml).unwrap();
    let dump: Vec<u8> = parsed
        .items
        .iter()
        .flat_map(|item| item.doc.encode().unwrap())
        .collect();
    let needle = b"xml-old-pw";
    assert!(!dump.windows(needle.len()).any(|window| window == needle));
}

#[test]
fn hostile_xml_is_refused() {
    let deep = format!(
        "<KeePassFile>{}{}</KeePassFile>",
        "<a>".repeat(100),
        "</a>".repeat(100)
    );
    assert_eq!(
        run_bytes(deep.as_bytes(), Source::KeepassXml)
            .unwrap_err()
            .to_string(),
        "XML nested too deeply"
    );
    let entity =
        br#"<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><KeePassFile>&a;</KeePassFile>"#;
    assert!(run_bytes(entity, Source::KeepassXml).is_err());
    let custom_ref = b"<KeePassFile><Root>&boom;</Root></KeePassFile>";
    assert!(run_bytes(custom_ref, Source::KeepassXml).is_err());
    let raw_dump = br#"<KeePassFile><Root><Group><Entry><String><Key>Password</Key><Value Protected="True">AAAA</Value></String></Entry></Group></Root></KeePassFile>"#;
    assert!(run_bytes(raw_dump, Source::KeepassXml)
        .unwrap_err()
        .to_string()
        .contains("encrypted values"));
    assert!(run_bytes(b"<html></html>", Source::KeepassXml).is_err());
    assert!(run_bytes(b"<KeePassFile><Root>", Source::KeepassXml).is_err());
}

#[test]
fn enpass_maps_fields_folders_and_kinds() {
    let parsed = run("enpass.json", Source::EnpassJson).unwrap();
    assert_eq!(parsed.items.len(), 2);
    assert_eq!(parsed.report.attachments, 1);
    assert_eq!(parsed.report.skipped[0].reason, SkipReason::Trashed);

    let github = titled(&parsed, "GitHub");
    let doc = &github.doc;
    assert_eq!(doc.text(TAG_USERNAME).unwrap(), Some("octocat"));
    assert_eq!(doc.text(TAG_EMAIL).unwrap(), Some("octo@example.com"));
    assert_eq!(
        doc.data(TAG_PASSWORD).unwrap().unwrap(),
        b"enpass-pw-github"
    );
    assert_eq!(doc.text(TAG_URL).unwrap(), Some("https://github.com"));
    assert_eq!(doc.get(TAG_TOTP).unwrap().vtype, ValueType::Secret);
    assert_eq!(doc.text(TAG_NOTES).unwrap(), Some("dev account"));
    assert_eq!(
        custom(github, "Security answer").unwrap().1,
        ValueType::Secret
    );
    assert!(custom(github, "Old field").is_none());
    assert!(custom(github, "Details").is_none());
    assert_eq!(custom(github, CUSTOM_TAGS).unwrap().0, b"Work/Dev");
    assert_eq!(custom(github, CUSTOM_FAVORITE).unwrap().0, b"1");

    let visa = titled(&parsed, "Visa");
    assert_eq!(visa.kind, ItemKind::Card);
    assert_eq!(custom(visa, "Number").unwrap().1, ValueType::Secret);
    assert_eq!(custom(visa, "Cardholder").unwrap().1, ValueType::Text);
    assert_eq!(custom(visa, CUSTOM_TAGS).unwrap().0, b"archived");
}

#[test]
fn enpass_folder_cycles_terminate() {
    let cyclic = br#"{"folders":[{"uuid":"a","parent_uuid":"b","title":"A"},{"uuid":"b","parent_uuid":"a","title":"B"}],
        "items":[{"title":"X","category":"note","folders":["a"],"fields":[]}]}"#;
    let parsed = run_bytes(cyclic, Source::EnpassJson).unwrap();
    assert_eq!(parsed.items.len(), 1);
    assert_eq!(
        run_bytes(b"[1,2]", Source::EnpassJson)
            .unwrap_err()
            .to_string(),
        "not an Enpass export"
    );
}

#[test]
fn xml_and_enpass_debug_never_show_passwords() {
    for (name, source, secret) in [
        ("keepass.xml", Source::KeepassXml, "xml-pw"),
        ("enpass.json", Source::EnpassJson, "enpass-pw-github"),
    ] {
        let dump = format!("{:?}", run(name, source).unwrap());
        assert!(!dump.contains(secret), "{name}");
    }
}
