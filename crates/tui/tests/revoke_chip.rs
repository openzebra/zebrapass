//! Revoking the development chip rotates the vault key: the chip no longer
//! opens the vault, the password still does, and every record stays
//! readable. A wrong phrase or a wrong current password is refused before
//! the core re-seals anything.

#![cfg(feature = "dev-chip")]
#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use record::{Document, TAG_TITLE};
use session::{BodyAlg, Factor};
use tui::vault::chip::Chips;
use tui::vault::discover::discover;
use tui::vault::open::{unlock_vault, Credential};
use tui::vault::ops::{apply, FactorRef, Op, Outcome, Rotation};
use zeroize::Zeroizing;

use common::{make_vault, phrase, temp_dir, PASSWORD};

fn password() -> Credential {
    Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec()))
}

fn rotation(words: &str, current: &str, revoke: Option<FactorRef>) -> Op {
    Op::Rotate(Box::new(Rotation {
        phrase: Box::new(phrase(words)),
        current: Some(Zeroizing::new(current.as_bytes().to_vec())),
        new_password: None,
        revoke,
    }))
}

#[test]
fn revoked_chip_stops_working_and_records_survive() {
    for alg in [BodyAlg::Aegis256, BodyAlg::Frames] {
        let chips = Chips::default();
        let base = temp_dir("revoke-chip");
        let words = make_vault(&base, alg);
        let paths = discover(&base).first().unwrap().paths.clone();
        let mut vault = unlock_vault(paths.clone(), password(), &chips).unwrap();
        let mut doc = Document::new();
        doc.set_text(TAG_TITLE, "keep me");
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
        apply(&mut vault, Op::AddChip, &chips).unwrap();
        let chip_id = vault
            .directory
            .factors
            .iter()
            .find_map(|factor| match factor {
                Factor::Chip(chip) => Some(chip.publics.id),
                _ => None,
            })
            .unwrap();
        assert!(
            unlock_vault(paths.clone(), Credential::Chip, &chips).is_ok(),
            "the chip opens the vault"
        );

        let generation = vault.session.generation();
        let stranger = seed::SeedPhrase::generate_24().unwrap();
        let wrong_phrase = apply(
            &mut vault,
            Op::Rotate(Box::new(Rotation {
                phrase: Box::new(stranger),
                current: Some(Zeroizing::new(PASSWORD.as_bytes().to_vec())),
                new_password: None,
                revoke: Some(FactorRef::Chip(chip_id)),
            })),
            &chips,
        );
        assert!(wrong_phrase.is_err());
        let wrong_password = apply(
            &mut vault,
            rotation(&words, "not-it", Some(FactorRef::Chip(chip_id))),
            &chips,
        );
        assert_eq!(
            wrong_password.unwrap_err().to_string(),
            "the current password is not correct"
        );
        assert_eq!(
            vault.session.generation(),
            generation,
            "a refused rotation changes nothing"
        );

        let outcome = apply(
            &mut vault,
            rotation(&words, PASSWORD, Some(FactorRef::Chip(chip_id))),
            &chips,
        )
        .unwrap();
        assert!(matches!(outcome, Outcome::Rotated { revoked: true, .. }));
        assert!(
            unlock_vault(paths.clone(), Credential::Chip, &chips).is_err(),
            "{alg:?}: the revoked chip still opens"
        );
        let reopened = unlock_vault(paths, password(), &chips).unwrap();
        let doc = session::open_record(&reopened.session, id).unwrap();
        assert_eq!(
            doc.text(TAG_TITLE).unwrap(),
            Some("keep me"),
            "{alg:?}: records must survive rotation"
        );
    }
}
