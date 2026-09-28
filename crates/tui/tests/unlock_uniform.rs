//! A wrong password and a tampered vault file (correct password) produce
//! byte-identical screens: the UI is not an oracle for which one happened.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use std::path::{Path, PathBuf};

use crossterm::event::KeyCode;
use tui::vault::discover::discover;

use common::{app, make_vault, press, render, temp_dir, type_text, wait, PASSWORD};

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn vault_file(base: &Path) -> PathBuf {
    discover(base).first().unwrap().paths.vault_file.clone()
}

fn flip(path: &Path, from_end: usize) {
    let mut bytes = std::fs::read(path).unwrap();
    let index = bytes.len() - from_end;
    bytes[index] ^= 0x01;
    std::fs::write(path, bytes).unwrap();
}

fn failed_screen(base: &Path, password: &str) -> String {
    let mut app = app(base);
    type_text(&mut app, password);
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(app.screen.name(), "unlock", "the attempt must fail");
    render(&app, 100, 30)
}

#[test]
fn wrong_password_and_tampered_file_look_the_same() {
    let original = temp_dir("uniform-original");
    make_vault(&original);
    let body_flip = temp_dir("uniform-body");
    copy_tree(&original, &body_flip);
    // The byte just before the 32-byte commit tag: inside the body.
    flip(&vault_file(&body_flip), 33);

    let wrong_password = failed_screen(&original, "not-the-password");
    let tampered = failed_screen(&body_flip, PASSWORD);
    assert!(
        wrong_password.contains("Couldn't unlock this vault."),
        "{wrong_password}"
    );
    assert_eq!(wrong_password, tampered, "the failure screens differ");

    // The commit tag itself: also the same screen.
    let tag_flip = temp_dir("uniform-tag");
    copy_tree(&original, &tag_flip);
    flip(&vault_file(&tag_flip), 1);
    assert_eq!(wrong_password, failed_screen(&tag_flip, PASSWORD));
}
