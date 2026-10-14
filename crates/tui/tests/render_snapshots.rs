//! Every screen renders at 100×30, 60×20, and 140×40 with its landmarks,
//! and the welcome screen matches its golden snapshot.
//!
//! Re-bless the golden after an intended change with
//! `ZEBRAPASS_BLESS=1 cargo test -p tui --test render_snapshots`.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use crossterm::event::KeyCode;
use record::{Document, ValueType, TAG_PASSWORD, TAG_TITLE, TAG_URL, TAG_USERNAME};
use tui::app::ctx::Task;
use tui::app::screen::Screen;
use tui::vault::ops::Op;

use common::{
    app, ctrl, make_vault, press, render, render_all, temp_dir, type_text, unlock, wait, PASSWORD,
};

fn assert_all(screens: &[String], needles: &[&str]) {
    for (index, screen) in screens.iter().enumerate() {
        for needle in needles {
            assert!(
                screen.contains(needle),
                "size #{index} lacks {needle:?}:\n{screen}"
            );
        }
    }
}

#[test]
fn welcome_matches_golden_and_every_size() {
    let base = temp_dir("welcome");
    let app = app(&base);
    assert_eq!(app.screen.name(), "welcome");
    let [normal, small, large] = render_all(&app);
    assert_all(
        &[normal.clone(), large],
        &["Create a new vault", "Restore or import", "quantum-safe"],
    );
    assert!(small.contains("Create a new vault"), "{small}");
    let golden =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/welcome_100x30.txt");
    let bless = std::env::var_os("ZEBRAPASS_BLESS").is_some();
    if bless || !golden.exists() {
        std::fs::create_dir_all(golden.parent().unwrap()).unwrap();
        std::fs::write(&golden, &normal).unwrap();
    }
    let expected = std::fs::read_to_string(&golden).unwrap();
    assert_eq!(
        normal, expected,
        "welcome screen drifted from its golden snapshot"
    );
}

#[test]
fn too_small_terminal_shows_a_card() {
    let base = temp_dir("small");
    let app = app(&base);
    let screen = render(&app, 59, 19);
    assert!(screen.contains("Terminal too small"), "{screen}");
}

#[test]
fn create_wizard_steps_render() {
    let base = temp_dir("wizard");
    let mut app = app(&base);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.screen.name(), "create");
    assert_all(&render_all(&app), &["New vault", "Balanced", "Encryption"]);
    let wide = render(&app, 100, 30);
    assert!(wide.contains("AEGIS-256 inside Kuznyechik-CTR"), "{wide}");
    assert!(!wide.contains("Body cipher"), "no cipher choice: {wide}");
    press(&mut app, KeyCode::Enter);
    let screens = render_all(&app);
    assert_all(&screens, &["Your recovery phrase", "I wrote it down"]);
    let Screen::Create(state) = &app.screen else {
        panic!("not create")
    };
    let phrase = state
        .phrase
        .as_ref()
        .unwrap()
        .phrase_normalized()
        .to_owned();
    // A single word can equal a word of the interface ("phrase"); three in a
    // row cannot, so that is what must never be on screen while masked.
    let words: Vec<&str> = phrase.split(' ').collect();
    for run in words.windows(3) {
        let shown = format!(" {} {} {} ", run[0], run[1], run[2]);
        for screen in &screens {
            assert!(
                !screen.contains(&shown),
                "phrase words {shown:?} visible while masked"
            );
        }
    }
    type_text(&mut app, "x");
    press(&mut app, KeyCode::Enter);
    assert_all(&render_all(&app), &["Prove you saved it", "Pick word #"]);
}

#[test]
fn restore_and_unlock_screens_render() {
    let base = temp_dir("restore-unlock");
    let mut app = app(&base);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.screen.name(), "import");
    assert_all(
        &render_all(&app),
        &[
            "Restore or import",
            "ZebraPass recovery phrase",
            "Bitwarden",
        ],
    );
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.screen.name(), "restore");
    assert_all(
        &render_all(&app),
        &["Restore from phrase", "Passphrase", "Vault file"],
    );
    make_vault(&base);
    let app = common::app(&base);
    assert_eq!(app.screen.name(), "unlock");
    assert_all(&render_all(&app), &["phrase", "locked"]);
}

#[test]
fn unlocked_views_render_at_every_size() {
    let base = temp_dir("views");
    make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    assert_eq!(app.screen.name(), "unlocked");
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, "GitHub");
    doc.set_text(TAG_URL, "https://github.com");
    doc.set_text(TAG_USERNAME, "octocat");
    doc.set_data(TAG_PASSWORD, ValueType::Secret, b"k7#Qm2^vR9!pLx@4wZ$e8Nb&");
    let Screen::Unlocked(state) = &mut app.screen else {
        panic!("not unlocked")
    };
    state.run(
        Op::Write {
            id: None,
            doc: Box::new(doc),
        },
        Task::Save,
        &mut app.ctx,
    );
    wait(&mut app);

    let wide = render(&app, 140, 40);
    assert!(
        wide.contains("Filters") && wide.contains("GitHub") && wide.contains("octocat"),
        "{wide}"
    );
    assert_all(&render_all(&app), &["GitHub", "CAS-0xA005"]);

    let views: [(char, &str); 6] = [
        ('F', "Constellation"),
        ('D', "Devices"),
        ('S', "your key"),
        (',', "Settings"),
        ('h', "History"),
        ('g', "Generator"),
    ];
    for (key, landmark) in views {
        press(&mut app, KeyCode::Char(key));
        assert_all(&render_all(&app), &[landmark]);
        press(&mut app, KeyCode::Esc);
    }
    press(&mut app, KeyCode::Char('H'));
    wait(&mut app);
    assert_all(&render_all(&app), &["Vault health", "score"]);
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('E'));
    assert_all(&render_all(&app), &["Edit", "Title", "Password"]);
    press(&mut app, KeyCode::Esc);
    app.on_key(&ctrl('k'));
    assert_all(&render_all(&app), &["command", "Rotate vault key"]);
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('?'));
    assert!(render(&app, 140, 40).contains("Keys"));
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('L'));
    assert_all(&render_all(&app), &["locked", "press any key to unlock"]);
}
