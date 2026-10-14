//! The home screen's peer-to-peer indication: the status strip, the traffic
//! light, and the info dialog with its in-memory event log.

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

use std::time::Duration;

use crossterm::event::KeyCode;
use p2p_net::Event;
use ratatui::backend::TestBackend;
use ratatui::style::Color;
use ratatui::Terminal;
use tui::app::flows::dialog::Dialog;
use tui::app::node::log::{EventLog, LOG_CAP};
use tui::app::node::CheckOutcome;
use tui::ui::screens::p2p_status::{summary, Light};
use tui::App;

use common::{
    adopted_pair, app, ctrl, make_vault, press, render, sync_off_with, temp_dir, tick, tick_both,
    unlock, unlocked_state as state, PASSWORD,
};

const WITHIN: Duration = Duration::from_secs(60);

fn light(app: &App) -> Light {
    summary(state(app), &app.ctx.theme).light
}

/// The colour of the dot at the far right of the header line.
fn dot_colour(app: &App) -> Color {
    let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
    terminal.draw(|frame| app.view(frame)).unwrap();
    let buffer = terminal.backend().buffer();
    let row: String = (0..120).map(|x| buffer[(x, 0)].symbol()).collect();
    assert!(
        !row.contains("Ctrl+I") && !row.contains("unlocked"),
        "{row}"
    );
    let x = u16::try_from(
        row.chars()
            .position(|c| c.to_string() == app.ctx.theme.glyphs.on)
            .unwrap(),
    )
    .unwrap();
    buffer[(x, 0)].fg
}

fn checked_in(app: &App, outcome: CheckOutcome) -> bool {
    state(app)
        .p2p
        .as_ref()
        .and_then(|p2p| p2p.last_checkin)
        .is_some_and(|checkin| checkin.outcome == outcome)
}

fn log_text(app: &App) -> String {
    state(app)
        .p2p
        .as_ref()
        .map(|p2p| {
            p2p.log
                .lines()
                .map(|line| line.text.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

#[test]
fn the_dot_is_red_off_yellow_without_peers_and_green_after_a_check_in() {
    let off = temp_dir("pi-off");
    make_vault(&off);
    sync_off_with(&off, PASSWORD);
    let mut off = app(&off);
    unlock(&mut off, PASSWORD);
    assert_eq!(light(&off), Light::Red);
    let theme = &off.ctx.theme;
    assert_eq!(dot_colour(&off), theme.danger().fg.unwrap());

    let (mut a, mut b, _) = adopted_pair("pi-light");
    let theme = b.ctx.theme;
    assert!(
        tick_both(&mut a, &mut b, WITHIN, |_, b| checked_in(
            b,
            CheckOutcome::Synced
        )),
        "a check-in succeeded"
    );
    assert_eq!(light(&b), Light::Green);
    assert_eq!(dot_colour(&b), theme.accent().fg.unwrap());

    drop(a);
    assert!(
        tick_alone(&mut b, |b| checked_in(b, CheckOutcome::Unreachable)),
        "the peer is gone"
    );
    assert_eq!(light(&b), Light::Yellow);
    assert_eq!(dot_colour(&b), theme.warn().fg.unwrap());
}

/// Tick `b` alone until `done`: its peer is gone.
fn tick_alone(b: &mut App, done: impl Fn(&App) -> bool) -> bool {
    let until = std::time::Instant::now() + WITHIN;
    while std::time::Instant::now() < until {
        tick(b, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(50));
        if done(b) {
            return true;
        }
    }
    done(b)
}

#[test]
fn the_dialog_lists_a_peer_after_a_check_in_and_logs_the_failure_after_it_dies() {
    let (mut a, mut b, _) = adopted_pair("pi-dialog");
    assert!(tick_both(&mut a, &mut b, WITHIN, |_, b| checked_in(
        b,
        CheckOutcome::Synced
    )));
    b.on_key(&ctrl('i'));
    assert!(matches!(state(&b).dialog.as_deref(), Some(Dialog::P2p(_))));
    let address = common::address_of(&a);
    let screen = render(&b, 120, 40);
    let row = screen
        .lines()
        .find(|line| line.contains(&address))
        .unwrap_or_else(|| panic!("no peer row\n{screen}"));
    assert!(row.contains("manual") && row.contains("ok ·"), "{row}");
    assert!(screen.contains("checked in with"), "{screen}");
    press(&mut b, KeyCode::Esc);
    assert!(state(&b).dialog.is_none());

    drop(a);
    assert!(tick_alone(&mut b, |b| checked_in(
        b,
        CheckOutcome::Unreachable
    )));
    b.on_key(&ctrl('i'));
    let screen = render(&b, 120, 40);
    assert!(screen.contains("fetch failed: unreachable"), "{screen}");
    let row = screen.lines().find(|line| line.contains(&address)).unwrap();
    assert!(row.contains("unreachable ·"), "{row}");
}

#[test]
fn the_log_and_the_screens_hold_no_record_title() {
    let (mut a, mut b, _) = adopted_pair("pi-title");
    assert!(tick_both(&mut a, &mut b, WITHIN, |_, b| checked_in(
        b,
        CheckOutcome::Synced
    )));
    press(&mut b, KeyCode::Char('i'));
    for app in [&a, &b] {
        for title in ["wifi", "bank"] {
            assert!(!log_text(app).contains(title), "{}", log_text(app));
        }
    }
    let screen = render(&b, 120, 40);
    assert!(screen.contains("p2p net"), "{screen}");
    assert!(screen.contains("TCP/ZPMX:7447"), "{screen}");
    assert!(screen.contains("QUIC:off"), "{screen}");
    let dialog: Vec<&str> = screen
        .lines()
        .skip_while(|line| !line.contains("p2p net"))
        .collect();
    assert!(dialog
        .iter()
        .all(|line| !line.contains("wifi") && !line.contains("bank")));
}

#[test]
fn the_strip_and_the_dialog_rows_stay_on_one_line_at_80_columns() {
    let (mut a, mut b, _) = adopted_pair("pi-narrow");
    assert!(tick_both(&mut a, &mut b, WITHIN, |_, b| checked_in(
        b,
        CheckOutcome::Synced
    )));
    let screen = render(&b, 80, 30);
    let strips = screen.lines().filter(|line| line.contains("p2p ·")).count();
    assert_eq!(strips, 1, "{screen}");
    b.on_key(&ctrl('i'));
    let screen = render(&b, 80, 30);
    for needle in ["listen mode", "beacon", "address ", "checked in with"] {
        assert_eq!(
            screen.lines().filter(|line| line.contains(needle)).count(),
            1,
            "{needle}\n{screen}"
        );
    }
    assert!(screen.lines().all(|line| line.chars().count() <= 80));
    tick(&mut b, Duration::from_millis(50));
}

#[test]
fn the_event_log_keeps_the_newest_two_hundred_lines() {
    let mut log = EventLog::default();
    for n in 0..LOG_CAP + 50 {
        log.note(&Event::Observed(
            format!("93.184.216.34:{}", 1000 + n).parse().unwrap(),
        ));
    }
    assert_eq!(log.lines().len(), LOG_CAP);
    assert!(log
        .lines()
        .last()
        .unwrap()
        .text
        .contains(&format!("{}", 1000 + LOG_CAP + 49)));
}
