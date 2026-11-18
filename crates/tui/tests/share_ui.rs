//! Split-screen share workbench: real focusable buttons on the left, live QR
//! code + RFC 3986 share URI on the right, clean hint bar, and secret hygiene.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use std::time::Duration;

use crossterm::event::KeyCode;
use local::Listen;
use sharing::ShareUri;
use tui::App;
use tui::app::flows::share::{ShareState, Step};
use tui::app::flows::share_nav::{ShareButton, ShareFocus};
use tui::app::flows::unlocked::{Unlocked, View};
use tui::app::screen::Screen;
use tui::secure::clipboard::extract_osc52_payload;

use common::{PASSWORD, app, make_vault, press, render, temp_dir, tick, type_text, unlock, wait};

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

fn last_copied(app: &mut App) -> String {
    let seq = app
        .take_outbox()
        .pop()
        .expect("expected a clipboard sequence");
    let raw = extract_osc52_payload(&seq).expect("valid osc52 payload");
    String::from_utf8(raw.to_vec()).expect("utf8 clipboard text")
}

fn signed_in(tag: &str) -> App {
    let base = temp_dir(tag);
    make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    press(&mut app, KeyCode::Char('S'));
    assert!(matches!(share(&app).step, Step::Overview));
    app
}

#[test]
fn split_screen_renders_buttons_qr_and_standard_url_with_clean_hints() {
    let app = signed_in("share-ui-render");
    let fp = share(&app).me.as_ref().unwrap().print;
    let fp_hex = fp.to_hex_compact();

    for (w, h) in [(140, 40), (100, 30)] {
        let screen = render(&app, w, h);
        assert!(screen.contains("Vaults & Actions"), "{w}x{h}:\n{screen}");
        assert!(screen.contains("your key"), "{w}x{h}:\n{screen}");
        assert!(screen.contains("Copy Key"), "{w}x{h}:\n{screen}");
        assert!(screen.contains("Copy URL"), "{w}x{h}:\n{screen}");
        assert!(
            screen.contains('▀') || screen.contains('▄') || screen.contains('█'),
            "QR half-blocks missing at {w}x{h}:\n{screen}"
        );
        assert!(
            screen.contains("zebrapass://share?v=1&fp="),
            "standard share URI missing at {w}x{h}:\n{screen}"
        );
        assert!(
            !screen.contains("use seen address")
                && !screen.contains("upgrade identity")
                && !screen.contains("announce via relay"),
            "old 15-item hint bar leaked at {w}x{h}:\n{screen}"
        );
        assert!(
            !screen.contains(PASSWORD),
            "vault password leaked at {w}x{h}:\n{screen}"
        );
    }

    // At 140x40 the full 40-hex fingerprint fits cleanly across 1–2 wrapped lines.
    let wide = render(&app, 140, 40);
    let compact_wide: String = wide
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '│')
        .collect();
    assert!(
        compact_wide.contains(&format!("zebrapass://share?v=1&fp={fp_hex}")),
        "full fp hex missing at 140x40:\n{wide}"
    );

    // Narrow 60x20 layout renders cleanly without panicking.
    let narrow = render(&app, 60, 20);
    assert!(narrow.contains("your key"), "{narrow}");
    assert!(!narrow.contains(PASSWORD), "{narrow}");
}

#[test]
fn button_navigation_activates_copy_key_copy_url_new_vault_and_listen_mode() {
    let mut app = signed_in("share-ui-nav");
    let fp = share(&app).me.as_ref().unwrap().print;
    assert_eq!(share(&app).focus, ShareFocus::Button(ShareButton::CopyKey));

    // Default CopyKey copies the signed contact card.
    press(&mut app, KeyCode::Enter);
    let copied_card = last_copied(&mut app);
    assert!(copied_card.starts_with("zp-card1:"), "{copied_card}");

    // Tab moves to CopyUrl; Enter copies the RFC 3986 share URL.
    press(&mut app, KeyCode::Tab);
    assert_eq!(share(&app).focus, ShareFocus::Button(ShareButton::CopyUrl));
    press(&mut app, KeyCode::Enter);
    let copied_url = last_copied(&mut app);
    let parsed = ShareUri::parse(&copied_url).expect("valid ShareUri");
    assert_eq!(parsed.fingerprint, fp);
    assert!(!copied_url.contains(PASSWORD));

    // Direct `y` hotkey also copies the share URL.
    press(&mut app, KeyCode::Char('y'));
    assert_eq!(last_copied(&mut app), copied_url);

    // Navigate from CopyUrl -> NewVault via Tab, then right across Row 0 and down to Row 2.
    press(&mut app, KeyCode::Tab);
    assert_eq!(share(&app).focus, ShareFocus::Button(ShareButton::NewVault));
    press(&mut app, KeyCode::Right);
    assert_eq!(
        share(&app).focus,
        ShareFocus::Button(ShareButton::JoinVault)
    );
    press(&mut app, KeyCode::Left);
    assert_eq!(share(&app).focus, ShareFocus::Button(ShareButton::NewVault));

    // Activate NewVault button via Enter -> opens Step::Name, then Esc back.
    press(&mut app, KeyCode::Enter);
    assert!(matches!(share(&app).step, Step::Name(_)));
    press(&mut app, KeyCode::Esc);
    assert!(matches!(share(&app).step, Step::Overview));

    // Move Down twice from Row 0 -> Row 1 -> Row 2 (CycleListen), activate via Enter.
    let initial_listen = state(&app).listen_mode();
    press(&mut app, KeyCode::Down);
    assert_eq!(
        share(&app).focus,
        ShareFocus::Button(ShareButton::ChangeRole)
    );
    press(&mut app, KeyCode::Down);
    assert_eq!(
        share(&app).focus,
        ShareFocus::Button(ShareButton::CycleListen)
    );
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_ne!(state(&app).listen_mode(), initial_listen);

    // BackTab walks cleanly in reverse (to column 3 of row 1: LeaveVault).
    press(&mut app, KeyCode::BackTab);
    assert_eq!(
        share(&app).focus,
        ShareFocus::Button(ShareButton::LeaveVault)
    );

    // Up from Row 1 col 3 reaches Row 0 col 3 (SyncNow) and stays when no vaults exist,
    // or enters Vaults from Row 0 once a vault exists.
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Up);
    assert_eq!(share(&app).focus, ShareFocus::Button(ShareButton::SyncNow));
    press(&mut app, KeyCode::Char('n'));
    type_text(&mut app, "Team");
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(state(&app).shared.len(), 1);
    press(&mut app, KeyCode::Up);
    assert_eq!(share(&app).focus, ShareFocus::Vaults);
    press(&mut app, KeyCode::Down);
    assert_eq!(share(&app).focus, ShareFocus::Button(ShareButton::NewVault));
}

#[test]
fn public_address_updates_displayed_and_copied_share_url() {
    let mut app = signed_in("share-ui-addr");
    assert_eq!(state(&app).listen_mode(), Listen::Beacon);

    press(&mut app, KeyCode::Char('p'));
    assert!(matches!(share(&app).step, Step::Advertise(_)));
    type_text(&mut app, "93.184.216.34:7447");
    press(&mut app, KeyCode::Enter);
    wait(&mut app);

    press(&mut app, KeyCode::Char('y'));
    let copied_url = last_copied(&mut app);
    assert!(
        copied_url.contains("&addr=93.184.216.34%3A7447"),
        "{copied_url}"
    );
    let parsed = ShareUri::parse(&copied_url).expect("valid ShareUri with addr");
    assert_eq!(parsed.addr.as_deref(), Some("93.184.216.34:7447"));

    // Expire transient toasts / clipboard countdown so the full URL is unoccluded.
    tick(&mut app, Duration::from_secs(21));
    let screen = render(&app, 140, 40);
    let compact: String = screen
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '│')
        .collect();
    assert!(compact.contains("addr=93.184.216.34%3A7447"), "{screen}");
}
