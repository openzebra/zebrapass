//! Changing and removing the password needs no recovery phrase: only the
//! password wrap changes. A wrong current password changes nothing.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests may unwrap; ratatui pulls duplicate transitive crates"
)]

mod common;

use tui::vault::chip::Chips;
use tui::vault::discover::discover;
use tui::vault::open::{unlock_vault, Credential};
use tui::vault::ops::{apply, Op, Outcome};
use zeroize::Zeroizing;

use common::{make_vault, temp_dir, PASSWORD};

const NEW: &str = "a-brand-new-passphrase-99";

fn password(text: &str) -> Credential {
    Credential::Password(Zeroizing::new(text.as_bytes().to_vec()))
}

fn change(current: &str) -> Op {
    Op::ChangePassword {
        current: Zeroizing::new(current.as_bytes().to_vec()),
        new: Zeroizing::new(NEW.as_bytes().to_vec()),
    }
}

#[test]
fn password_changes_and_goes_without_the_phrase() {
    let chips = Chips::default();
    let base = temp_dir("password");
    make_vault(&base);
    let paths = discover(&base).first().unwrap().paths.clone();
    let mut vault = unlock_vault(paths.clone(), password(PASSWORD), &chips).unwrap();
    let generation = vault.session.generation();

    let refused = apply(&mut vault, change("not-it"), &chips).unwrap_err();
    assert_eq!(refused.to_string(), "the current password is not correct");
    assert_eq!(vault.session.generation(), generation);

    let outcome = apply(&mut vault, change(PASSWORD), &chips).unwrap();
    assert!(matches!(outcome, Outcome::PasswordChanged));
    assert!(unlock_vault(paths.clone(), password(PASSWORD), &chips).is_err());
    assert!(unlock_vault(paths.clone(), password(NEW), &chips).is_ok());

    let outcome = apply(&mut vault, Op::RemovePassword, &chips).unwrap();
    assert!(matches!(outcome, Outcome::FactorRemoved));
    assert!(unlock_vault(paths, password(NEW), &chips).is_err());
}
