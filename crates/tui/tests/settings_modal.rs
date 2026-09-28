//! The settings modal: opens over Home, stages edits with a live preview,
//! saves them into the vault's encrypted local metadata, refuses a bad
//! server origin, asks before discarding, and searches across sections.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests may unwrap; ratatui pulls duplicate transitive crates"
)]

mod common;

use std::time::Duration;

use crossterm::event::KeyCode;
use tui::app::screen::Screen;
use tui::ui::theme::ThemeName;
use tui::App;

use common::{
    app, ctrl, make_vault, press, render, render_all, temp_dir, type_text, unlock, wait, PASSWORD,
};

fn open_settings(tag: &str) -> (App, std::path::PathBuf) {
    let base = temp_dir(tag);
    make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    assert_eq!(app.screen.name(), "unlocked");
    type_text(&mut app, ",");
    (app, base)
}

fn modal_open(app: &App) -> bool {
    matches!(&app.screen, Screen::Unlocked(state) if state.settings.is_some())
}

/// Tab to the `n`-th section after Security.
fn section(app: &mut App, n: usize) {
    for _ in 0..n {
        press(app, KeyCode::Tab);
    }
}

#[test]
fn comma_opens_the_modal_at_every_size() {
    let (app, _) = open_settings("settings-open");
    assert!(modal_open(&app));
    for screen in render_all(&app) {
        assert!(screen.contains("Settings"), "{screen}");
        assert!(screen.contains("Auto-lock after"), "{screen}");
    }
    let wide = render(&app, 140, 40);
    assert!(wide.contains("posture"), "{wide}");
    assert!(wide.contains("Danger zone"), "{wide}");
}

#[test]
fn a_saved_change_survives_a_new_process() {
    let (mut app, base) = open_settings("settings-save");
    press(&mut app, KeyCode::Right);
    assert!(render(&app, 120, 40).contains("1 unsaved change"));
    app.on_key(&ctrl('s'));
    wait(&mut app);
    assert!(render(&app, 120, 40).contains("stored encrypted with this vault"));
    assert_eq!(app.ctx.idle.after(), Duration::from_secs(600));
    press(&mut app, KeyCode::Esc);
    assert!(!modal_open(&app), "nothing unsaved: Esc just closes");

    let mut fresh = common::app(&base);
    unlock(&mut fresh, PASSWORD);
    assert_eq!(fresh.ctx.idle.after(), Duration::from_secs(600));
}

#[test]
fn theme_previews_live_and_discard_restores_it() {
    let (mut app, _) = open_settings("settings-theme");
    let before = app.ctx.theme.name;
    section(&mut app, 4);
    press(&mut app, KeyCode::Right);
    assert_ne!(app.ctx.theme.name, before, "the preview is live");
    press(&mut app, KeyCode::Esc);
    assert!(render(&app, 120, 40).contains("Discard 1 unsaved change?"));
    press(&mut app, KeyCode::Enter);
    assert!(!modal_open(&app));
    assert_eq!(app.ctx.theme.name, before);
    assert_eq!(before, ThemeName::StripesDark);
}

#[test]
fn server_origin_must_be_https_host_and_port() {
    let (mut app, _) = open_settings("settings-origin");
    section(&mut app, 2);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    type_text(&mut app, "sync.example/path");
    press(&mut app, KeyCode::Enter);
    assert!(render(&app, 120, 40).contains("no path, query, or user name"));
    for _ in 0.."/path".len() {
        press(&mut app, KeyCode::Backspace);
    }
    press(&mut app, KeyCode::Enter);
    let screen = render(&app, 120, 40);
    assert!(screen.contains("https://sync.example"), "{screen}");
    assert!(screen.contains("1 unsaved change"), "{screen}");
}

#[test]
fn test_connection_fails_closed() {
    let (mut app, _) = open_settings("settings-sync");
    section(&mut app, 2);
    for _ in 0..5 {
        press(&mut app, KeyCode::Down);
    }
    press(&mut app, KeyCode::Enter);
    assert!(render(&app, 120, 40).contains("not built yet: nothing was sent"));
}

#[test]
fn search_reaches_rows_in_other_sections() {
    let (mut app, _) = open_settings("settings-search");
    type_text(&mut app, "/enclave");
    let screen = render(&app, 120, 40);
    assert!(screen.contains("Secure Enclave"), "{screen}");
    assert!(!screen.contains("Auto-lock after"), "{screen}");
    press(&mut app, KeyCode::Esc);
    assert!(render(&app, 120, 40).contains("Auto-lock after"));
}
