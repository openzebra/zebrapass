//! This device's keyring factor: enrolled at create, it unlocks with no
//! typing; the unlock screen offers it first; a second device is revoked
//! without its keys (device book), and the revoked keys stop working and are
//! deleted. Uses the in-memory keyring, never the real OS keychain.

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
use record::{Document, TAG_TITLE};
use seed::SeedPhrase;
use session::{Factor, KdfProfile};
use tui::app::flows::unlock::Mode;
use tui::app::screen::Screen;
use tui::vault::chip::Chips;
use tui::vault::create::{create, Enrollment, NewVault};
use tui::vault::discover::discover;
use tui::vault::open::{unlock_vault, Credential};
use tui::vault::ops::{apply, FactorRef, Op, Outcome, Rotation};

use common::{app, pass_verify, press, temp_dir, wait};

fn device_ids(chips: &Chips, paths: &local::Paths) -> Vec<[u8; 16]> {
    let vault = unlock_vault(paths.clone(), Credential::Device, chips).unwrap();
    vault
        .directory
        .factors
        .iter()
        .filter_map(|factor| match factor {
            Factor::Device { id } => Some(*id),
            _ => None,
        })
        .collect()
}

#[test]
fn device_factor_unlocks_and_revocation_deletes_its_keys() {
    let base = temp_dir("device");
    let chips = Chips::default();
    let phrase = SeedPhrase::generate_24().unwrap();
    let words = phrase.phrase_normalized().to_owned();
    let mut vault = create(
        NewVault {
            phrase: Box::new(phrase),
            name: String::from("Personal"),
            base: base.clone(),
            profile: KdfProfile::Fast,
            factor: Enrollment::Device,
        },
        &chips,
    )
    .unwrap();
    let paths = vault.paths.clone();
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, "kept");
    let Outcome::Saved(id) = apply(
        &mut vault,
        Op::Write {
            id: None,
            doc: Box::new(doc),
        },
        &chips,
    )
    .unwrap() else {
        panic!("not saved")
    };
    drop(vault);

    let mine = device_ids(&chips, &paths);
    assert_eq!(mine.len(), 1);
    assert!(chips.keyring().owns(&mine[0]));

    // A second device, enrolled from another keyring, is revoked from this
    // one with no keys and no publics passed in: the device book has them.
    let other = Chips::default();
    let mut vault = unlock_vault(paths.clone(), Credential::Device, &chips).unwrap();
    apply(&mut vault, Op::AddDevice, &other).unwrap();
    let theirs = device_ids(&chips, &paths)
        .into_iter()
        .find(|id| *id != mine[0])
        .unwrap();
    assert!(unlock_vault(paths.clone(), Credential::Device, &other).is_ok());
    let outcome = apply(
        &mut vault,
        Op::Rotate(Box::new(Rotation {
            phrase: Box::new(common::phrase(&words)),
            current: None,
            revoke: Some(FactorRef::Device(theirs)),
        })),
        &other,
    )
    .unwrap();
    assert!(matches!(outcome, Outcome::Rotated(true)));
    assert!(!other.keyring().owns(&theirs));
    assert!(unlock_vault(paths.clone(), Credential::Device, &other).is_err());

    let reopened = unlock_vault(paths.clone(), Credential::Device, &chips).unwrap();
    let doc = session::open_record(&reopened.session, id).unwrap();
    assert_eq!(doc.text(TAG_TITLE).unwrap(), Some("kept"));
    drop(reopened);

    // Removing this device's own wrap deletes its keys too.
    let mut vault = unlock_vault(paths, Credential::Device, &chips).unwrap();
    apply(
        &mut vault,
        Op::RemoveWrap(FactorRef::Device(mine[0])),
        &chips,
    )
    .unwrap();
    assert!(!chips.keyring().owns(&mine[0]));
    assert!(chips
        .keyring()
        .keys(vault.session.vault_id())
        .unwrap()
        .is_none());
    assert_eq!(discover(&base).len(), 1);
}

#[test]
fn wizard_enrolls_this_device_and_unlock_needs_no_typing() {
    let base = temp_dir("device-ui");
    let mut app = app(&base);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Enter);
    // Ceremony: Tab to the checkbox, Space ticks it, Enter continues.
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Enter);
    pass_verify(&mut app, false);
    // Enroll: Shift-Tab from the password reaches the cards; one to the
    // right is "This device".
    press(&mut app, KeyCode::BackTab);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(app.screen.name(), "unlocked");

    press(&mut app, KeyCode::Char('L'));
    press(&mut app, KeyCode::Enter);
    let Screen::Unlock(unlock) = &app.screen else {
        panic!("not unlock: {}", app.screen.name())
    };
    assert_eq!(unlock.mode, Mode::Device);
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(app.screen.name(), "unlocked");
}
