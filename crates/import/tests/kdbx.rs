//! `.kdbx` import: databases built at test time with `keepass`, opened with
//! a password and a key file; the KDF cost is bounded before it runs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::multiple_crate_versions,
    reason = "tests may unwrap, index, and panic; keepass pulls duplicate crates"
)]

use std::time::{Duration, Instant};

use import::{kdf_cost, parse, Item, KdfCost, Parsed, Request, SkipReason, Source};
use keepass::config::KdfConfig;
use keepass::db::Value;
use keepass::{Database, DatabaseKey};
use record::{ValueType, CUSTOM_TAGS, TAG_NOTES, TAG_PASSWORD, TAG_TITLE, TAG_TOTP, TAG_USERNAME};
use zeroize::Zeroizing;

const PASSWORD: &str = "kdbx-master-pass";
const KEY_FILE: &[u8] = b"zebrapass test key file contents";

fn sample_db() -> Database {
    let mut db = Database::new();
    let bin_id = {
        let mut root = db.root_mut();
        {
            let mut work = root.add_group();
            work.name = "Work".into();
            let mut dev = work.add_group();
            dev.name = "Dev".into();
            let mut entry = dev.add_entry();
            entry.set_unprotected("Title", "GitHub");
            entry.set_unprotected("UserName", "octocat");
            entry.set_protected("Password", "kdbx-pw-github");
            entry.set_unprotected("URL", "https://github.com");
            entry.set_protected("otp", "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP");
            entry.set_protected("Recovery", "kdbx-rc-1");
            entry.set_unprotected("Team", "core");
            entry.tags.push("code".into());
            entry.add_attachment("key.txt", Value::protected(b"attached".to_vec()));
        }
        {
            let mut entry = root.add_entry();
            entry.set_unprotected("Title", "Bank");
            entry.set_protected("Password", "kdbx-pw-bank");
            entry.set_unprotected("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP");
            entry.set_unprotected("TimeOtp-Length", "8");
        }
        {
            let mut entry = root.add_entry();
            entry.set_unprotected("Title", "Door code");
            entry.set_unprotected("Notes", "4711 at the back door");
        }
        let mut bin = root.add_group();
        bin.name = "Recycle Bin".into();
        bin.add_entry().set_unprotected("Title", "Deleted login");
        bin.id()
    };
    db.meta.recyclebin_uuid = Some(bin_id.uuid());
    db
}

fn save(db: &Database, key: DatabaseKey) -> Vec<u8> {
    let mut bytes = Vec::new();
    db.save(&mut bytes, key).unwrap();
    bytes
}

fn open(bytes: &[u8], password: Option<&str>, key_file: Option<&[u8]>) -> anyhow::Result<Parsed> {
    parse(&Request {
        bytes: Zeroizing::new(bytes.to_vec()),
        source: Source::Kdbx,
        mapping: None,
        folders_as_tags: true,
        password: password.map(|pw| Zeroizing::new(pw.as_bytes().to_vec())),
        key_file: key_file.map(|kf| Zeroizing::new(kf.to_vec())),
    })
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
fn kdbx_round_trip_with_password() {
    let bytes = save(&sample_db(), DatabaseKey::new().with_password(PASSWORD));
    let parsed = open(&bytes, Some(PASSWORD), None).unwrap();
    assert_eq!(parsed.items.len(), 3);
    assert_eq!(parsed.report.attachments, 1);
    let trashed: Vec<_> = parsed
        .report
        .skipped
        .iter()
        .map(|s| (s.reason, &*s.title))
        .collect();
    assert_eq!(trashed, [(SkipReason::Trashed, "Deleted login")]);

    let github = titled(&parsed, "GitHub");
    assert_eq!(github.doc.text(TAG_USERNAME).unwrap(), Some("octocat"));
    assert_eq!(
        github.doc.data(TAG_PASSWORD).unwrap().unwrap(),
        b"kdbx-pw-github"
    );
    assert_eq!(github.doc.get(TAG_TOTP).unwrap().vtype, ValueType::Secret);
    assert_eq!(
        custom(github, "Recovery").unwrap(),
        (b"kdbx-rc-1".as_slice(), ValueType::Secret)
    );
    assert_eq!(custom(github, "Team").unwrap().1, ValueType::Text);
    assert_eq!(custom(github, CUSTOM_TAGS).unwrap().0, b"code, Work/Dev");

    let bank = titled(&parsed, "Bank");
    assert_eq!(
        bank.doc.data(TAG_TOTP).unwrap().unwrap(),
        b"otpauth://totp/Imported?secret=JBSWY3DPEHPK3PXP&digits=8"
    );
    assert!(custom(bank, "TimeOtp-Length").is_none());

    let door = titled(&parsed, "Door code");
    assert_eq!(door.kind, import::ItemKind::Note);
    assert_eq!(
        door.doc.text(TAG_NOTES).unwrap(),
        Some("4711 at the back door")
    );
}

#[test]
fn kdbx_with_key_file_and_aes_kdf() {
    let mut db = sample_db();
    db.config.kdf_config = KdfConfig::Aes { rounds: 1_000 };
    let key = DatabaseKey::new()
        .with_password(PASSWORD)
        .with_keyfile(&mut &KEY_FILE[..])
        .unwrap();
    let bytes = save(&db, key);
    assert_eq!(kdf_cost(&bytes).unwrap(), KdfCost::Aes { rounds: 1_000 });
    assert_eq!(
        open(&bytes, Some(PASSWORD), Some(KEY_FILE))
            .unwrap()
            .items
            .len(),
        3
    );
    assert!(open(&bytes, Some(PASSWORD), None).is_err());
}

#[test]
fn wrong_password_and_wrong_key_file_fail_the_same_way() {
    let key = DatabaseKey::new()
        .with_password(PASSWORD)
        .with_keyfile(&mut &KEY_FILE[..])
        .unwrap();
    let bytes = save(&sample_db(), key);
    let wrong_password = open(&bytes, Some("nope"), Some(KEY_FILE))
        .unwrap_err()
        .to_string();
    let wrong_key_file = open(&bytes, Some(PASSWORD), Some(b"other"))
        .unwrap_err()
        .to_string();
    let mut damaged = bytes.clone();
    let last = damaged.len() - 40;
    damaged[last] ^= 0x01;
    let damaged = open(&damaged, Some(PASSWORD), Some(KEY_FILE))
        .unwrap_err()
        .to_string();
    assert_eq!(wrong_password, wrong_key_file);
    assert_eq!(wrong_password, damaged);
    assert!(!wrong_password.contains(PASSWORD));
    assert!(open(&bytes, None, None)
        .unwrap_err()
        .to_string()
        .contains("password"));
}

#[test]
fn kdf_cost_is_bounded_before_the_kdf_runs() {
    let bytes = save(&sample_db(), DatabaseKey::new().with_password(PASSWORD));
    assert!(matches!(
        kdf_cost(&bytes).unwrap(),
        KdfCost::Argon2 {
            memory: 1_048_576,
            iterations: 50,
            ..
        }
    ));
    // Patch the announced Argon2 memory to 4 GiB.
    let marker: &[u8] = b"\x01\x00\x00\x00M\x08\x00\x00\x00";
    let at = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap()
        + marker.len();
    let mut hostile = bytes;
    hostile[at..at + 8].copy_from_slice(&(4u64 << 30).to_le_bytes());
    let started = Instant::now();
    let error = open(&hostile, Some(PASSWORD), None)
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("unlock cost too high"), "{error}");
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[test]
fn truncated_headers_are_refused() {
    let bytes = save(&sample_db(), DatabaseKey::new().with_password(PASSWORD));
    for len in [0, 4, 11, 12, 20, 60] {
        assert!(kdf_cost(&bytes[..len]).is_err(), "prefix of {len} bytes");
    }
    assert!(kdf_cost(b"not a database at all").is_err());
}

#[test]
fn kdbx_debug_never_shows_passwords() {
    let bytes = save(&sample_db(), DatabaseKey::new().with_password(PASSWORD));
    let parsed = open(&bytes, Some(PASSWORD), None).unwrap();
    let dump = format!("{parsed:?}");
    assert!(!dump.contains("kdbx-pw-github"));
    assert!(!dump.contains("kdbx-rc-1"));
}
