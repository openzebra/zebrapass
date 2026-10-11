//! The terminal interface has no sync backend other than peer-to-peer: the
//! retired word appears nowhere in this crate, and the devices screen and enroll
//! guide say what is true locally.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests may unwrap; ratatui pulls duplicate transitive crates"
)]

mod common;

use std::path::Path;

use crossterm::event::KeyCode;
use tui::app::screen::Screen;

use common::{app, make_vault, press, render, temp_dir, unlock, PASSWORD};

fn walk(dir: &Path, hits: &mut Vec<String>) {
    let needle = ["ser", "ver"].concat();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, hits);
        } else if let Ok(text) = std::fs::read_to_string(&path) {
            if text.to_ascii_lowercase().contains(&needle) {
                hits.push(path.display().to_string());
            }
        }
    }
}

#[test]
fn the_retired_word_appears_nowhere_in_the_tui_crate() {
    let mut hits = Vec::new();
    walk(Path::new(env!("CARGO_MANIFEST_DIR")), &mut hits);
    assert!(hits.is_empty(), "{hits:?}");
}

#[test]
fn devices_and_factors_say_what_is_true_locally() {
    let base = temp_dir("retired-copy");
    make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    assert!(matches!(app.screen, Screen::Unlocked(_)));

    press(&mut app, KeyCode::Char('D'));
    let devices = render(&app, 160, 40);
    assert!(
        devices.contains("Device certificates are kept in sync.id; check-in times are per peer."),
        "{devices}"
    );

    press(&mut app, KeyCode::Char('n'));
    let guide = render(&app, 160, 40);
    assert!(guide.contains("QR pairing is not built yet."), "{guide}");
}
