//! A vault whose sync identity was written before the account gate secret
//! existed cannot serve its personal vault. The Share screen offers an
//! upgrade with the account's phrase; a wrong phrase changes nothing.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use std::path::{Path, PathBuf};

use crossterm::event::KeyCode;
use record::{Document, TAG_TITLE};
use seed::SeedPhrase;
use session::write_record;
use tui::app::flows::restore::RestoreField;
use tui::app::flows::share::{ShareState, Step};
use tui::app::flows::unlocked::{Unlocked, View};
use tui::app::screen::Screen;
use tui::vault::discover::discover;
use tui::vault::open::{unlock_vault, Credential};
use tui::App;
use zeroize::Zeroizing;

use common::{
    app, ctrl, keep_to_this_device, make_vault, press, render, temp_dir, type_text, unlock, wait,
    PASSWORD,
};

const SECOND_PASSWORD: &str = "another-long-password-for-B-77";

fn credential() -> Credential {
    Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec()))
}

/// Records for the vault under `base`, and its identity file rewritten as the
/// first revision wrote it. Returns the identity file.
fn old_vault(base: &Path) -> PathBuf {
    let paths = discover(base).first().unwrap().paths.clone();
    let mut vault = unlock_vault(paths.clone(), credential()).unwrap();
    for title in ["wifi", "bank"] {
        let mut doc = Document::new();
        doc.set_text(TAG_TITLE, title);
        write_record(&mut vault.session, &mut vault.file, None, &doc).unwrap();
    }
    vault.persist().unwrap();
    let key = vault.session.sync_identity_key().unwrap();
    let path = paths.sync_identity();
    let bytes = std::fs::read(&path).unwrap();
    let header = frame::parse(&bytes).unwrap();
    assert_eq!(
        header.revision, 2,
        "a new vault writes the current revision"
    );
    let plain = frame::open(&key, &bytes).unwrap();
    let (signing_seed, rest) = plain.expose().split_at(32);
    let legacy = [signing_seed, &rest[32..]].concat();
    let meta = frame::FrameMeta {
        kind: header.kind,
        record_id: header.record_id,
        revision: 1,
        origin_device: header.origin_device,
        timestamp_ms: header.timestamp_ms,
        alg: header.alg,
    };
    local::write_atomic(&path, &frame::seal(&key, &meta, &legacy).unwrap()).unwrap();
    path
}

fn revision_of(path: &Path) -> u64 {
    frame::parse(&std::fs::read(path).unwrap())
        .unwrap()
        .revision
}

fn state(app: &App) -> &Unlocked {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked: {}", app.screen.name())
    };
    state
}

fn share(app: &App) -> &ShareState {
    let View::Sync(share) = &state(app).view else {
        panic!("not on the share screen")
    };
    share
}

fn type_phrase(app: &mut App, words: &str) {
    for word in words.split(' ') {
        type_text(app, word);
        press(app, KeyCode::Char(' '));
    }
}

fn open_share(app: &mut App) {
    press(app, KeyCode::Char('S'));
    assert!(matches!(share(app).step, Step::Overview));
}

/// An old-identity vault, unlocked on the share screen.
fn unlocked_old(tag: &str) -> (App, String, PathBuf) {
    let base = temp_dir(tag);
    let words = make_vault(&base);
    keep_to_this_device(&base);
    let file = old_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    open_share(&mut app);
    (app, words, file)
}

#[test]
fn an_old_identity_is_offered_an_upgrade_and_serves_nothing_until_it_is_done() {
    let (mut first, words, file) = unlocked_old("up-first");
    assert!(state(&first).identity_is_old());
    assert!(
        state(&first).p2p.is_none(),
        "without the gate secret there is no node to serve the personal vault"
    );
    let screen = render(&first, 120, 40);
    assert!(screen.contains("old format"), "{screen}");
    assert!(screen.contains("u to upgrade"), "{screen}");

    press(&mut first, KeyCode::Char('u'));
    assert!(matches!(share(&first).step, Step::Upgrade(_)));
    type_phrase(&mut first, &words);
    let screen = render(&first, 120, 40);
    assert!(
        !screen.contains(words.split(' ').next().unwrap()),
        "no echo:\n{screen}"
    );
    press(&mut first, KeyCode::Enter);

    assert!(matches!(share(&first).step, Step::Overview));
    assert!(!state(&first).identity_is_old());
    assert_eq!(revision_of(&file), 2, "upgraded in place");
    let screen = render(&first, 120, 40);
    assert!(
        !screen.contains("old format"),
        "the line is gone:\n{screen}"
    );
    let address = state(&first)
        .p2p
        .as_ref()
        .expect("the node runs now")
        .service
        .local_addr()
        .expect("and listens")
        .to_string();

    // A second device restores over the network from it.
    let mut second = app(&temp_dir("up-second"));
    press(&mut second, KeyCode::Right);
    press(&mut second, KeyCode::Enter);
    press(&mut second, KeyCode::Enter);
    assert_eq!(second.screen.name(), "restore");
    type_phrase(&mut second, &words);
    second.on_key(&ctrl('n'));
    press(&mut second, KeyCode::Tab);
    let Screen::Restore(restore) = &second.screen else {
        panic!("not restore")
    };
    assert_eq!(restore.field, RestoreField::Source);
    type_text(&mut second, &address);
    press(&mut second, KeyCode::Enter);
    type_text(&mut second, SECOND_PASSWORD);
    press(&mut second, KeyCode::Tab);
    type_text(&mut second, SECOND_PASSWORD);
    press(&mut second, KeyCode::Enter);
    wait(&mut second);
    assert_eq!(second.screen.name(), "unlocked");
    let titles: Vec<String> = state(&second)
        .cache
        .iter()
        .map(|row| row.title.to_string())
        .collect();
    assert!(titles.contains(&"wifi".to_owned()) && titles.contains(&"bank".to_owned()));
}

#[test]
fn a_wrong_phrase_changes_nothing() {
    let (mut app, words, file) = unlocked_old("up-wrong");
    let before = std::fs::read(&file).unwrap();

    // Not yet a whole phrase.
    press(&mut app, KeyCode::Char('u'));
    type_text(&mut app, "abandon");
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Enter);
    assert!(matches!(share(&app).step, Step::Upgrade(_)));
    assert!(render(&app, 120, 40).contains("Enter all 12"));
    press(&mut app, KeyCode::Esc);
    assert!(matches!(share(&app).step, Step::Overview));

    // A phrase that is valid, but of another account.
    let other = SeedPhrase::generate_24().unwrap();
    let other = other.phrase_normalized().to_owned();
    assert_ne!(other, words);
    press(&mut app, KeyCode::Char('u'));
    type_phrase(&mut app, &other);
    press(&mut app, KeyCode::Enter);
    assert!(matches!(share(&app).step, Step::Upgrade(_)));
    let screen = render(&app, 120, 40);
    assert!(
        screen.contains("not the phrase of this account"),
        "{screen}"
    );

    // The right words in the wrong order fail the checksum before anything
    // else is looked at.
    let mut shuffled: Vec<&str> = words.split(' ').collect();
    shuffled.reverse();
    for _ in 0..24 {
        press(&mut app, KeyCode::Backspace);
    }
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('u'));
    type_phrase(&mut app, &shuffled.join(" "));
    press(&mut app, KeyCode::Enter);
    assert!(matches!(share(&app).step, Step::Upgrade(_)));

    assert_eq!(std::fs::read(&file).unwrap(), before, "not a byte changed");
    assert_eq!(revision_of(&file), 1);
    press(&mut app, KeyCode::Esc);
    assert!(state(&app).identity_is_old());
    assert!(state(&app).p2p.is_none());
}

#[test]
fn a_current_identity_has_nothing_to_upgrade() {
    let base = temp_dir("up-current");
    make_vault(&base);
    keep_to_this_device(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    open_share(&mut app);
    assert!(!state(&app).identity_is_old());
    assert!(!render(&app, 120, 40).contains("old format"));
    press(&mut app, KeyCode::Char('u'));
    assert!(matches!(share(&app).step, Step::Overview));
}
