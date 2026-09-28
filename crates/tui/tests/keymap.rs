//! Every action is reachable, no binding is dead, and the help screen lists
//! every binding (it is generated from the same table).

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use crossterm::event::KeyCode;
use tui::app::action::{Action, PALETTE};
use tui::app::keymap::{in_scope, label, KEYMAP, SCOPES};

use common::{app, press, render, temp_dir};

#[test]
fn every_action_is_reachable() {
    for action in Action::ALL {
        let bound = KEYMAP.iter().any(|binding| binding.action == *action);
        let listed = PALETTE.iter().any(|(entry, _, _)| entry == action);
        assert!(
            bound || listed,
            "{action:?} has no key and no palette entry"
        );
        assert!(
            !action.describe().is_empty(),
            "{action:?} has no description"
        );
    }
}

#[test]
fn no_binding_is_shadowed() {
    for (index, binding) in KEYMAP.iter().enumerate() {
        let shadowed = KEYMAP[..index]
            .iter()
            .any(|earlier| earlier.scope == binding.scope && earlier.key == binding.key);
        assert!(
            !shadowed,
            "{:?} {:?} is bound twice",
            binding.scope, binding.key
        );
    }
    for binding in KEYMAP {
        assert!(
            SCOPES.contains(&binding.scope),
            "{:?} is missing from the help order",
            binding.scope
        );
    }
}

#[test]
fn help_lists_every_binding() {
    let base = temp_dir("help");
    let mut app = app(&base);
    press(&mut app, KeyCode::Char('?'));
    // ratatui caps a buffer at 65 535 cells; 200×200 holds the whole sheet.
    let screen = render(&app, 200, 200);
    for scope in SCOPES {
        if in_scope(scope).next().is_some() {
            assert!(
                screen.contains(scope.title()),
                "help lacks section {}",
                scope.title()
            );
        }
    }
    for binding in KEYMAP {
        assert!(
            screen.contains(binding.action.describe()),
            "help lacks {:?}",
            binding.action
        );
        assert!(
            screen.contains(label(binding.key, false).as_ref()),
            "help lacks key {:?}",
            binding.key
        );
    }
}
