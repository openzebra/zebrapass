//! This device's factor: a PIN-sealed key file next to the vault. It unlocks
//! with the PIN only, the unlock screen offers it first, a wrong PIN reads
//! like any failed unlock, and revoking it rotates the vault key so a copy
//! of the old key file opens nothing. Nothing touches the OS keychain.

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
use session::KdfProfile;
use tui::app::flows::unlock::Mode;
use tui::app::screen::Screen;
use tui::vault::create::{create, Enrollment, NewVault};
use tui::vault::device::owned_id;
use tui::vault::error::UnlockError;
use tui::vault::open::{unlock_vault, Credential, Vault};
use tui::vault::ops::{apply, FactorRef, Op, Outcome, Rotation};
use zeroize::Zeroizing;

use common::{app, press, temp_dir, type_text, wait, PASSWORD};

const PIN: &str = "482916";

fn secret(text: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(text.as_bytes().to_vec())
}

fn pin(text: &str) -> Credential {
    Credential::Device(secret(text))
}

/// A vault whose only everyday factor is this device, sealed with Fast.
fn device_vault(base: &std::path::Path) -> (Box<Vault>, String) {
    let phrase = SeedPhrase::generate_24().unwrap();
    let words = phrase.phrase_normalized().to_owned();
    let vault = create(NewVault {
        phrase: Box::new(phrase),
        name: String::from("Personal"),
        base: base.to_path_buf(),
        profile: KdfProfile::Fast,
        factor: Enrollment::Device(secret(PIN), KdfProfile::Fast),
    })
    .unwrap();
    (vault, words)
}

fn write(vault: &mut Vault, title: &str) -> u32 {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, title);
    let Outcome::Saved(id) = apply(
        vault,
        Op::Write {
            id: None,
            doc: Box::new(doc),
        },
    )
    .unwrap() else {
        panic!("not saved")
    };
    id
}

#[test]
fn pin_unlocks_and_a_wrong_pin_is_the_uniform_denial() {
    let base = temp_dir("device-pin");
    let (mut vault, _) = device_vault(&base);
    let id = write(&mut vault, "kept");
    let paths = vault.paths.clone();
    drop(vault);

    assert!(paths.device_key.exists());
    let reopened = unlock_vault(paths.clone(), pin(PIN)).unwrap();
    assert_eq!(owned_id(&paths), Some(reopened.session.origin_device()));
    let doc = session::open_record(&reopened.session, id).unwrap();
    assert_eq!(doc.text(TAG_TITLE).unwrap(), Some("kept"));
    drop(reopened);

    assert_eq!(
        unlock_vault(paths.clone(), pin("000000")).unwrap_err(),
        UnlockError::Denied
    );
    // A damaged key file with the right PIN reads exactly the same.
    let mut bytes = std::fs::read(&paths.device_key).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&paths.device_key, bytes).unwrap();
    assert_eq!(
        unlock_vault(paths, pin(PIN)).unwrap_err(),
        UnlockError::Denied
    );
}

#[test]
fn revoked_device_key_file_opens_nothing_and_records_survive() {
    let base = temp_dir("device-revoke");
    let (mut vault, words) = device_vault(&base);
    let id = write(&mut vault, "keep me");
    apply(
        &mut vault,
        Op::AddPassword(secret(PASSWORD), KdfProfile::Fast),
    )
    .unwrap();
    let paths = vault.paths.clone();
    let device = owned_id(&paths).unwrap();
    let stolen = std::fs::read(&paths.device_key).unwrap();

    let generation = vault.session.generation();
    let stranger = SeedPhrase::generate_24().unwrap();
    let wrong_phrase = apply(
        &mut vault,
        Op::Rotate(Box::new(Rotation {
            phrase: Box::new(stranger),
            current: Some(secret(PASSWORD)),
            revoke: Some(FactorRef::Device(device)),
        })),
    );
    assert!(wrong_phrase.is_err());
    assert_eq!(vault.session.generation(), generation, "refused: unchanged");

    let outcome = apply(
        &mut vault,
        Op::Rotate(Box::new(Rotation {
            phrase: Box::new(common::phrase(&words)),
            current: Some(secret(PASSWORD)),
            revoke: Some(FactorRef::Device(device)),
        })),
    )
    .unwrap();
    assert!(matches!(outcome, Outcome::Rotated(true)));
    assert!(!paths.device_key.exists(), "revoke deletes the key file");
    drop(vault);

    // An attacker who copied the key file and knows the PIN still gets in
    // nowhere: the wrap is gone and the vault key underneath is new.
    std::fs::write(&paths.device_key, stolen).unwrap();
    assert!(unlock_vault(paths.clone(), pin(PIN)).is_err());
    let reopened = unlock_vault(paths, Credential::Password(secret(PASSWORD))).unwrap();
    let doc = session::open_record(&reopened.session, id).unwrap();
    assert_eq!(doc.text(TAG_TITLE).unwrap(), Some("keep me"));
}

#[test]
fn removing_the_device_wrap_deletes_its_key_file() {
    let base = temp_dir("device-remove");
    let (mut vault, _) = device_vault(&base);
    apply(
        &mut vault,
        Op::AddPassword(secret(PASSWORD), KdfProfile::Fast),
    )
    .unwrap();
    let paths = vault.paths.clone();
    let device = owned_id(&paths).unwrap();
    let refused = apply(&mut vault, Op::AddDevice(secret(PIN), KdfProfile::Fast));
    assert_eq!(
        refused.unwrap_err().to_string(),
        "this device is already enrolled"
    );
    apply(&mut vault, Op::RemoveWrap(FactorRef::Device(device))).unwrap();
    assert!(!paths.device_key.exists());
    assert_eq!(owned_id(&paths), None);

    apply(
        &mut vault,
        Op::AddDevice(secret("135790"), KdfProfile::Fast),
    )
    .unwrap();
    let again = owned_id(&paths).unwrap();
    assert_ne!(again, device, "a fresh enrollment draws a fresh wrap id");
    drop(vault);
    assert!(unlock_vault(paths, pin("135790")).is_ok());
}

#[test]
fn unlock_screen_offers_the_device_pin_first() {
    let base = temp_dir("device-ui");
    let (vault, _) = device_vault(&base);
    drop(vault);
    let mut app = app(&base);
    let Screen::Unlock(unlock) = &app.screen else {
        panic!("not unlock: {}", app.screen.name())
    };
    assert_eq!(unlock.mode, Mode::Device);
    type_text(&mut app, "12345");
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.screen.name(),
        "unlock",
        "a short PIN is refused locally"
    );
    for _ in 0..5 {
        press(&mut app, KeyCode::Backspace);
    }
    type_text(&mut app, PIN);
    press(&mut app, KeyCode::Enter);
    wait(&mut app);
    assert_eq!(app.screen.name(), "unlocked");
}

#[test]
fn changing_the_pin_reseals_only_the_key_file() {
    let base = temp_dir("device-change-pin");
    let (mut vault, _) = device_vault(&base);
    let paths = vault.paths.clone();
    let generation = vault.session.generation();
    let vault_before = std::fs::read(&paths.vault_file).unwrap();

    let refused = apply(
        &mut vault,
        Op::ChangePin {
            current: secret("000000"),
            new: secret("246810"),
            profile: KdfProfile::Fast,
        },
    );
    assert_eq!(
        refused.unwrap_err().to_string(),
        "the current PIN is not correct"
    );
    let outcome = apply(
        &mut vault,
        Op::ChangePin {
            current: secret(PIN),
            new: secret("246810"),
            profile: KdfProfile::Fast,
        },
    )
    .unwrap();
    assert!(matches!(outcome, Outcome::PinChanged));
    assert_eq!(
        vault.session.generation(),
        generation,
        "the vault is untouched"
    );
    drop(vault);
    assert_eq!(std::fs::read(&paths.vault_file).unwrap(), vault_before);
    assert!(unlock_vault(paths.clone(), pin(PIN)).is_err());
    assert!(unlock_vault(paths, pin("246810")).is_ok());
}
