#![allow(clippy::unwrap_used, reason = "tests may unwrap")]

use local::{Prefs, RELAYS_MAX};
use record::{Document, TAG_PREF_P2P_RELAYS};

fn hint(n: u8) -> Box<str> {
    format!("93.184.216.{n}:7447/{}", "cd".repeat(16)).into()
}

fn saved(prefs: &Prefs) -> Document {
    let mut doc = Document::new();
    prefs.write(&mut doc);
    doc
}

#[test]
fn relay_slots_survive_a_round_trip_in_order() {
    let prefs = Prefs {
        p2p_relays: vec![hint(1), hint(2), hint(3)],
        ..Prefs::default()
    };
    let read = Prefs::read(&saved(&prefs)).unwrap().unwrap();
    assert_eq!(read.p2p_relays, prefs.p2p_relays);
    assert!(Prefs::read(&saved(&Prefs::default()))
        .unwrap()
        .unwrap()
        .p2p_relays
        .is_empty());
}

#[test]
fn a_saved_relay_that_is_not_valid_is_a_load_error_not_a_default() {
    let tagged = |text: &str| {
        let mut doc = saved(&Prefs::default());
        doc.set_text(TAG_PREF_P2P_RELAYS, text);
        doc
    };
    assert!(Prefs::read(&tagged(&hint(1))).is_ok());
    for bad in [
        String::new(),
        "garbage".to_owned(),
        format!("{}\ngarbage", hint(1)),
        format!("{}\n", hint(1)),
        format!("169.254.169.254:80/{}", "cd".repeat(16)),
        format!("93.184.216.1:7447/{}", "CD".repeat(16)),
        (1..=u8::try_from(RELAYS_MAX + 1).unwrap())
            .map(|n| hint(n).to_string())
            .collect::<Vec<_>>()
            .join("\n"),
    ] {
        assert!(Prefs::read(&tagged(&bad)).is_err(), "{bad:?}");
    }
}

#[test]
fn a_vault_with_only_relays_saved_still_has_saved_preferences() {
    let mut doc = Document::new();
    doc.set_text(TAG_PREF_P2P_RELAYS, &hint(1));
    let read = Prefs::read(&doc).unwrap().unwrap();
    assert_eq!(read.p2p_relays, [hint(1)]);
    assert_eq!(read.lock_after_s, Prefs::default().lock_after_s);
}
