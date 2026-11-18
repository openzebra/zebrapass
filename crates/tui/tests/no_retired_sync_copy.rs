//! Legacy 2026-10 sync preference tags never appear anywhere in the TUI crate,
//! and device/factor screens accurately describe local storage.

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

use common::{PASSWORD, app, make_vault, press, render, temp_dir, unlock};

fn walk_sources(dir: &Path, hits: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_sources(&path, hits);
        } else if let Ok(text) = std::fs::read_to_string(&path) {
            let lower = text.to_ascii_lowercase();
            if ["0x0206", "0x0207", "0x0208", "nostr_relays"]
                .iter()
                .any(|tag| lower.contains(tag))
            {
                hits.push(path.display().to_string());
            }
        }
    }
}

#[test]
fn retired_legacy_sync_tags_never_appear_in_tui() {
    let mut hits = Vec::new();
    walk_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut hits,
    );
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
