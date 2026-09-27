//! Rollback detection across cold opens.
//!
//! The cursor lives in `local.meta`, not in the caller's hands: after
//! `mark_seen`, handing the vault file an older copy must fail even when
//! the caller passes no `Seen` of its own.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap, index, and panic"
)]

use aead::BodyAlg;
use kdf::KdfProfile;
use local::{create_vault, load_local_meta, mark_seen, LocalMeta};
use record::{Document, ValueType, TAG_PASSWORD, TAG_TITLE};
use seed::SeedPhrase;
use session::{unlock, UnlockCreds, VaultFile};

/// A fresh directory under the system temp dir; caller removes it.
fn temp_base(tag: &str) -> std::path::PathBuf {
    const HEX: [&str; 16] = [
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
    ];
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).unwrap();
    let mut name = format!("zp-rollback-{tag}-");
    for byte in suffix {
        name.push_str(HEX.get(usize::from(byte >> 4)).copied().unwrap_or("0"));
        name.push_str(HEX.get(usize::from(byte & 0x0F)).copied().unwrap_or("0"));
    }
    let dir = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn login_doc(title: &str, password: &str) -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, title);
    doc.set_data(TAG_PASSWORD, ValueType::Secret, password.as_bytes());
    doc
}

#[test]
fn persisted_seen_stops_rollback_without_caller_state() {
    let phrase = SeedPhrase::generate_24().unwrap();
    let seed = *phrase.seed();
    let base = temp_base("cursor");
    let (paths, mut session, mut file, mut meta) =
        create_vault(&base, &seed, KdfProfile::Mobile, BodyAlg::Frames).unwrap();

    // create_vault writes generation 1; mark it accepted, then bump.
    mark_seen(&paths, &mut meta, &session).unwrap();
    assert_eq!(meta.seen.map(|s| s.generation), Some(1));
    session::write_record(&mut session, &mut file, None, &login_doc("Blog", "hunter2")).unwrap();
    mark_seen(&paths, &mut meta, &session).unwrap();
    assert_eq!(meta.seen.map(|s| s.generation), Some(2));
    let generation_one = file.as_bytes().to_vec();
    let meta_key = session.local_meta_key().unwrap();
    drop(session);

    // A third record bumps to generation 3 and the cursor follows.
    let mut file = VaultFile::new(generation_one.clone());
    let mut session = unlock(&file, &UnlockCreds::master(&seed), None).unwrap();
    session::write_record(&mut session, &mut file, None, &login_doc("Mail", "s3cret")).unwrap();
    mark_seen(&paths, &mut meta, &session).unwrap();
    assert_eq!(meta.seen.map(|s| s.generation), Some(3));
    drop(session);

    // The meta file carries the cursor, so a fresh process reconstructs it.
    let reloaded: LocalMeta = load_local_meta(&paths.local_meta, &meta_key).unwrap();
    assert_eq!(reloaded.seen, meta.seen);

    // Handing back the generation-1 file must fail as a rollback.
    let stale = VaultFile::new(generation_one);
    let cursor = reloaded.seen.map(|seen| session::Seen {
        generation: seen.generation,
        commit_tag: seen.commit_tag,
    });
    assert_eq!(
        unlock(&stale, &UnlockCreds::master(&seed), cursor)
            .unwrap_err()
            .to_string(),
        "rollback"
    );

    // The current file still opens against the persisted cursor.
    unlock(&file, &UnlockCreds::master(&seed), cursor).unwrap();

    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn meta_without_cursor_still_loads() {
    // Files written before rollback detection existed have no seen tags.
    let phrase = SeedPhrase::generate_24().unwrap();
    let seed = *phrase.seed();
    let base = temp_base("legacy");
    let (paths, session, _file, mut meta) =
        create_vault(&base, &seed, KdfProfile::Desktop, BodyAlg::Aegis256).unwrap();
    meta.seen = None;
    local::save_local_meta(&paths.local_meta, &meta, &session.local_meta_key().unwrap()).unwrap();
    let meta_key = session.local_meta_key().unwrap();
    let reloaded = load_local_meta(&paths.local_meta, &meta_key).unwrap();
    assert!(reloaded.seen.is_none());
    std::fs::remove_dir_all(&base).unwrap();
}
