//! Every detail row copies with Enter: standard fields, custom text, and
//! custom secrets alike.

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
use record::{Document, ValueType, TAG_PASSWORD, TAG_TITLE, TAG_URL};
use tui::app::ctx::Task;
use tui::app::flows::home::Pane;
use tui::app::screen::Screen;
use tui::secure::clipboard::osc52;
use tui::vault::ops::Op;
use tui::App;

use common::{app, make_vault, press, render, temp_dir, unlock, wait, PASSWORD};

fn vault_with_custom_fields() -> App {
    let base = temp_dir("detail-copy");
    make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, "cellframe");
    doc.set_text(TAG_URL, "https://cellframe.net");
    doc.set_data(TAG_PASSWORD, ValueType::Secret, b"main-password");
    doc.set_custom(0x8000, "WalletName", ValueType::Text, b"masterNode")
        .unwrap();
    doc.set_custom(
        0x8001,
        "password node",
        ValueType::Secret,
        b"node-secret-42",
    )
    .unwrap();
    doc.set_custom(
        0x8002,
        "node wallet",
        ValueType::Text,
        b"Rj7J7MiX2bWy8sNyZEowp9oywmtFXTkASX4ExpkyCCNJEp4",
    )
    .unwrap();
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
    app
}

fn focus_row(app: &mut App, label: &str) {
    let Screen::Unlocked(state) = &mut app.screen else {
        panic!("not unlocked")
    };
    let detail = state.home.detail.as_mut().unwrap();
    detail.cursor = detail
        .rows
        .iter()
        .position(|row| row.label == label)
        .unwrap();
}

#[test]
fn enter_copies_any_focused_field() {
    let mut app = vault_with_custom_fields();
    press(&mut app, KeyCode::Enter);
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    assert_eq!(
        state.home.pane,
        Pane::Detail,
        "Enter on the list focuses the detail"
    );

    for (label, value) in [
        ("password", b"main-password".as_slice()),
        ("url", b"https://cellframe.net".as_slice()),
        ("WalletName", b"masterNode".as_slice()),
        ("password node", b"node-secret-42".as_slice()),
        (
            "node wallet",
            b"Rj7J7MiX2bWy8sNyZEowp9oywmtFXTkASX4ExpkyCCNJEp4".as_slice(),
        ),
    ] {
        focus_row(&mut app, label);
        let _ = app.take_outbox();
        press(&mut app, KeyCode::Enter);
        let out = app.take_outbox();
        assert_eq!(out.len(), 1, "{label} copies");
        assert_eq!(out[0].as_slice(), osc52(value).as_slice(), "{label} value");
    }
}

#[test]
fn arrows_reach_custom_rows_and_labels_stay_apart() {
    let mut app = vault_with_custom_fields();
    press(&mut app, KeyCode::Enter);
    for _ in 0..10 {
        press(&mut app, KeyCode::Down);
    }
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    let detail = state.home.detail.as_ref().unwrap();
    assert_eq!(detail.rows[detail.cursor].label, "node wallet");
    let screen = render(&app, 160, 40);
    assert!(screen.contains("Enter copy"));
    assert!(
        screen.contains("node wallet   Rj7J7MiX"),
        "label and value keep a gap:\n{screen}"
    );
    assert!(
        !screen.contains("node-secret-42"),
        "custom secrets stay masked"
    );
}
