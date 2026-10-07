//! Big invitations do not fit the terminal clipboard and travel as files.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    reason = "tests may unwrap; ratatui pulls duplicate transitive crates"
)]

mod common;

use std::time::{Duration, Instant};

use tui::app::flows::share_file::invitation_text;
use tui::secure::clipboard::{Clipboard, CopyError};

#[test]
fn a_copy_over_the_limit_is_refused_and_a_small_one_goes_out() {
    let mut clipboard = Clipboard::new(true, Duration::from_secs(30));
    let now = Instant::now();
    assert_eq!(
        clipboard.copy(&vec![b'a'; 75_001], "invitation", now),
        Err(CopyError::TooLarge)
    );
    assert!(clipboard.outbox().is_empty(), "nothing half-sent");
    clipboard
        .copy(&vec![b'a'; 75_000], "invitation", now)
        .unwrap();
    assert_eq!(clipboard.outbox().len(), 1);
}

#[test]
fn a_pasted_path_stands_for_the_invitation_inside_it() {
    let dir = common::temp_dir("invite-file");
    let path = dir.join("invitation.txt");
    std::fs::write(&path, "zp-invite1:AAAA\n").unwrap();
    let shown = path.display().to_string();
    assert_eq!(invitation_text(&shown), "zp-invite1:AAAA");
    assert_eq!(invitation_text(&format!("'{shown}'")), "zp-invite1:AAAA");
    assert_eq!(invitation_text("zp-invite1:BBBB "), "zp-invite1:BBBB");
    assert_eq!(invitation_text("not a path"), "not a path");
}
