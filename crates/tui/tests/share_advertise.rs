//! A device behind a port forward tells its members the address to use.

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
use tui::app::flows::share::{ShareState, Step};
use tui::app::flows::unlocked::{Unlocked, View};
use tui::app::screen::Screen;
use tui::App;

use common::{app, make_vault, press, render, temp_dir, type_text, unlock, wait, PASSWORD};

fn state(app: &App) -> &Unlocked {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    state
}

fn share(app: &App) -> &ShareState {
    let View::Sync(share) = &state(app).view else {
        panic!("not on the share screen")
    };
    share
}

fn with_shared_vault() -> App {
    let base = temp_dir("advertise");
    make_vault(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    press(&mut app, KeyCode::Char('S'));
    press(&mut app, KeyCode::Char('n'));
    type_text(&mut app, "Family");
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    app
}

fn offered(app: &App) -> Vec<String> {
    state(app).p2p.as_deref().unwrap().hints()
}

#[test]
fn the_address_is_validated_saved_offered_first_and_can_be_cleared() {
    let mut app = with_shared_vault();
    assert!(!offered(&app).is_empty());
    assert!(state(&app).advertised().is_none());

    press(&mut app, KeyCode::Char('p'));
    assert!(matches!(share(&app).step, Step::Advertise(_)));
    let screen = render(&app, 100, 30);
    assert!(screen.contains("public address"), "{screen}");

    // Nonsense and unreachable addresses are refused and nothing changes.
    for bad in ["example.com:7447", "127.0.0.1:7447", "203.0.113.5"] {
        type_text(&mut app, bad);
        press(&mut app, KeyCode::Enter);
        assert!(matches!(share(&app).step, Step::Advertise(_)), "{bad}");
        assert!(state(&app).advertised().is_none(), "{bad}");
        for _ in 0..bad.len() {
            press(&mut app, KeyCode::Backspace);
        }
    }

    type_text(&mut app, "93.184.216.34:7447");
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert!(matches!(share(&app).step, Step::Overview));
    assert_eq!(state(&app).advertised(), Some("93.184.216.34:7447"));
    let hints = offered(&app);
    assert_eq!(hints[0], "93.184.216.34:7447", "offered before the others");
    assert!(hints.len() <= 4);
    let screen = render(&app, 110, 30);
    assert!(screen.contains("offering"), "{screen}");
    assert!(screen.contains("93.184.216.34:7447"), "{screen}");

    // Editing starts from what is saved; an empty entry takes it back.
    press(&mut app, KeyCode::Char('p'));
    let Step::Advertise(input) = &share(&app).step else {
        panic!("not editing")
    };
    assert_eq!(input.value(), "93.184.216.34:7447");
    for _ in 0.."93.184.216.34:7447".len() {
        press(&mut app, KeyCode::Backspace);
    }
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert!(state(&app).advertised().is_none());
    assert!(!offered(&app).contains(&String::from("93.184.216.34:7447")));
}

fn observe(app: &mut App, seen: &str) {
    let Screen::Unlocked(state) = &mut app.screen else {
        panic!("not unlocked")
    };
    state.observe(seen.parse().unwrap());
}

#[test]
fn the_address_a_member_saw_is_offered_never_applied_and_fills_the_field_on_one_key() {
    let mut app = with_shared_vault();
    let port = state(&app)
        .p2p
        .as_deref()
        .unwrap()
        .service
        .local_addr()
        .unwrap()
        .port();

    // Nothing seen yet: no offer, and the key says so without opening anything.
    assert!(!render(&app, 110, 30).contains("your router sees"));
    press(&mut app, KeyCode::Char('o'));
    assert!(matches!(share(&app).step, Step::Overview));

    // A member on this machine: shown, marked as local, never offered.
    observe(&mut app, "127.0.0.1:50000");
    let screen = render(&app, 110, 30);
    assert!(
        screen.contains("this machine, cannot be offered"),
        "{screen}"
    );
    assert!(!screen.contains("your router sees"), "{screen}");
    press(&mut app, KeyCode::Char('o'));
    assert!(matches!(share(&app).step, Step::Overview));

    // An address that could never be dialed leaves no trace.
    observe(&mut app, "169.254.169.254:50000");
    let screen = render(&app, 110, 30);
    assert!(!screen.contains("your router sees"), "{screen}");
    assert!(!screen.contains("cannot be offered"), "{screen}");

    // A public address is offered with this node's port, and nothing is
    // applied until the person confirms.
    observe(&mut app, "93.184.216.34:50000");
    let seen_at = format!("93.184.216.34:{port}");
    let screen = render(&app, 110, 30);
    assert!(
        screen.contains(&format!("your router sees {seen_at}")),
        "{screen}"
    );
    assert!(state(&app).advertised().is_none());
    press(&mut app, KeyCode::Char('o'));
    let Step::Advertise(input) = &share(&app).step else {
        panic!("the field was not opened")
    };
    assert_eq!(input.value(), seen_at);
    assert!(state(&app).advertised().is_none(), "filled, not applied");
    press(&mut app, KeyCode::Esc);
    assert!(
        state(&app).advertised().is_none(),
        "backing out applies nothing"
    );
    assert!(!offered(&app).contains(&seen_at));

    // Confirming saves it; the offer then has nothing left to say.
    press(&mut app, KeyCode::Char('o'));
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(state(&app).advertised(), Some(seen_at.as_str()));
    assert!(!render(&app, 110, 30).contains("your router sees"));
}
