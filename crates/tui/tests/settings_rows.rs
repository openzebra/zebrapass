//! Unit-style invariants on the Settings table rows and sections.

use local::Prefs;
use tui::app::flows::settings::rows::{ROWS, Row, Section, changes, in_section, matching};

#[test]
fn every_section_has_rows_and_every_row_one_section() {
    for section in Section::ALL {
        assert!(in_section(section).count() > 0, "{section:?}");
    }
    for (section, row) in ROWS {
        assert_eq!(row.section(), section);
    }
}

#[test]
fn adjust_walks_steps_and_stays_in_bounds() {
    let mut draft = Prefs::default();
    Row::AutoLock.adjust(&mut draft, true);
    assert_eq!(draft.lock_after_s, 600);
    for _ in 0..20 {
        Row::AutoLock.adjust(&mut draft, false);
    }
    assert_eq!(draft.lock_after_s, 30);
    for _ in 0..40 {
        Row::ClipClear.adjust(&mut draft, true);
    }
    assert_eq!(draft.clip_clear_s, 90);
    Row::Theme.adjust(&mut draft, false);
    assert_eq!(draft.theme, 2);
    assert_eq!(
        changes(&draft, &Prefs::default()).collect::<Vec<_>>(),
        [Row::AutoLock, Row::ClipClear, Row::Theme]
    );
    Row::ClipClear.reset(&mut draft);
    assert!(!Row::ClipClear.changed(&draft, &Prefs::default()));
}

#[test]
fn search_matches_labels_and_explanations() {
    assert!(matching("PIN").any(|row| row == Row::DevicePin));
    assert!(matching("enclave").any(|row| row == Row::SecureEnclave));
    assert_eq!(matching("zzzz-nothing").count(), 0);
}
