//! Preferences live in the vault's encrypted `local.meta`: saved once, they
//! apply on the next unlock in a fresh process, and a start-up request for
//! no color is never overridden by a saved theme.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests may unwrap; ratatui pulls duplicate transitive crates"
)]

mod common;

use std::time::Duration;

use local::{Prefs, SyncMode};
use tui::cli::Config;
use tui::cli::Flags;
use tui::ui::theme::ThemeName;
use tui::vault::discover::discover;
use tui::vault::open::{unlock_vault, Credential};
use tui::vault::ops::{apply, Op, Outcome};
use zeroize::Zeroizing;

use common::{app, app_with, make_vault, temp_dir, unlock, CAPS, PASSWORD};

fn saved() -> Prefs {
    Prefs {
        server_origin: Some("https://sync.example.com".into()),
        server_key_pin: None,
        lock_after_s: 120,
        clip_clear_s: 10,
        reveal_hide_s: 3,
        theme: u8::from(ThemeName::StripesLight),
        sync_mode: SyncMode::Manual,
        anim: false,
        ascii: true,
        focus_lock: true,
        p2p_listen: local::Listen::Local,
        p2p_advertise: Some("93.184.216.35:8000".into()),
        p2p_relays: vec![format!("93.184.216.36:7447/{}", "cd".repeat(16)).into()],
    }
}

fn save(base: &std::path::Path) {
    let paths = discover(base).first().unwrap().paths.clone();
    let password = Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec()));
    let mut vault = unlock_vault(paths.clone(), password).unwrap();
    let outcome = apply(&mut vault, Op::SavePrefs(Box::new(saved()))).unwrap();
    assert!(matches!(outcome, Outcome::PrefsSaved));
    drop(vault);
    let password = Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec()));
    assert_eq!(
        unlock_vault(paths, password).unwrap().meta.prefs,
        Some(saved())
    );
}

#[test]
fn saved_prefs_apply_on_the_next_unlock() {
    let base = temp_dir("prefs");
    make_vault(&base);
    save(&base);

    let mut app = app(&base);
    assert_eq!(
        app.ctx.idle.after(),
        Duration::from_secs(300),
        "defaults before unlock"
    );
    unlock(&mut app, PASSWORD);
    assert_eq!(app.screen.name(), "unlocked");
    assert_eq!(app.ctx.idle.after(), Duration::from_secs(120));
    assert_eq!(app.ctx.clipboard.clear_after(), Duration::from_secs(10));
    assert_eq!(app.ctx.reveal_after, Duration::from_secs(3));
    assert_eq!(app.ctx.theme.name, ThemeName::StripesLight);
    assert!(!app.ctx.flags.has(Flags::ANIM));
    assert!(app.ctx.flags.has(Flags::ASCII));
    assert!(app.ctx.flags.has(Flags::FOCUS_LOCK));
}

#[test]
fn no_color_at_start_up_beats_a_saved_theme() {
    let base = temp_dir("prefs-mono");
    make_vault(&base);
    save(&base);

    let config = Config {
        theme: ThemeName::Mono,
        ..common::config(&base)
    };
    let mut app = app_with(&config, &base, CAPS);
    unlock(&mut app, PASSWORD);
    assert_eq!(app.ctx.theme.name, ThemeName::Mono);
    assert_eq!(app.ctx.idle.after(), Duration::from_secs(120));
}
