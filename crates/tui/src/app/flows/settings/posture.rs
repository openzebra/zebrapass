//! A 0–100 security posture score for the settings meter, with the single
//! change that would raise it most. Pure: preferences and public facts in.

use kdf::KdfProfile;
use local::Prefs;

use crate::vault::factors::Presence;

/// Score and advice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Posture {
    /// 0–100.
    pub score: u8,
    /// The most valuable missing step, or a word of praise.
    pub advice: &'static str,
}

/// Public facts the score reads besides the preferences.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// Factor counts from the wrap directory.
    pub presence: Presence,
    /// Argon2id profile of this device's PIN file.
    pub pin_profile: Option<KdfProfile>,
    /// Argon2id memory of the password wrap, in KiB.
    pub password_m_kib: Option<u32>,
}

/// One check: points when met, partial points, and advice when missed.
struct Check {
    full: u8,
    partial: u8,
    advice: &'static str,
}

/// Score `prefs` against `facts`.
#[must_use]
pub fn posture(prefs: &Prefs, facts: &Facts) -> Posture {
    let found = facts.presence;
    let everyday = usize::from(found.password) + found.owned_devices + found.hw_keys;
    let checks = [
        (
            level(prefs.lock_after_s <= 300, prefs.lock_after_s <= 900),
            Check {
                full: 20,
                partial: 10,
                advice: "Auto-lock after 5 minutes or less.",
            },
        ),
        (
            level(everyday >= 2, everyday == 1),
            Check {
                full: 20,
                partial: 10,
                advice: "Enroll a second everyday factor (a password or this device).",
            },
        ),
        (
            level(prefs.clip_clear_s <= 20, prefs.clip_clear_s <= 45),
            Check {
                full: 15,
                partial: 8,
                advice: "Clear the clipboard within 20 seconds.",
            },
        ),
        (
            match facts.pin_profile {
                None | Some(KdfProfile::Strong) => Level::Full,
                Some(KdfProfile::Balanced) => Level::Partial,
                Some(KdfProfile::Fast) => Level::None,
            },
            Check {
                full: 15,
                partial: 8,
                advice: "Re-seal the device PIN with the Strong profile.",
            },
        ),
        (
            facts.password_m_kib.map_or(Level::Full, |m_kib| {
                level(m_kib >= KdfProfile::Balanced.m_kib(), false)
            }),
            Check {
                full: 15,
                partial: 0,
                advice: "Give the password a Balanced or Strong Argon2id cost.",
            },
        ),
        (
            level(prefs.focus_lock, false),
            Check {
                full: 10,
                partial: 0,
                advice: "Lock when the terminal loses focus.",
            },
        ),
        (
            level(prefs.reveal_hide_s <= 5, prefs.reveal_hide_s <= 10),
            Check {
                full: 5,
                partial: 2,
                advice: "Hide revealed secrets within 5 seconds.",
            },
        ),
    ];
    let score = checks.iter().fold(0u8, |acc, (met, check)| {
        acc.saturating_add(match met {
            Level::Full => check.full,
            Level::Partial => check.partial,
            Level::None => 0,
        })
    });
    let advice = checks
        .iter()
        .filter(|(met, _)| *met != Level::Full)
        .max_by_key(|(met, check)| {
            let earned = if *met == Level::Partial {
                check.partial
            } else {
                0
            };
            check.full.saturating_sub(earned)
        })
        .map_or(
            "Every check passes. Keep the recovery phrase offline.",
            |(_, check)| check.advice,
        );
    Posture { score, advice }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    Full,
    Partial,
    None,
}

const fn level(full: bool, partial: bool) -> Level {
    if full {
        Level::Full
    } else if partial {
        Level::Partial
    } else {
        Level::None
    }
}

#[cfg(test)]
mod tests {
    use kdf::KdfProfile;
    use local::Prefs;

    use super::{posture, Facts};
    use crate::vault::factors::Presence;

    fn strong_facts() -> Facts {
        Facts {
            presence: Presence {
                password: true,
                owned_devices: 1,
                devices: 1,
                recovery: true,
                ..Presence::default()
            },
            pin_profile: Some(KdfProfile::Strong),
            password_m_kib: Some(KdfProfile::Strong.m_kib()),
        }
    }

    #[test]
    fn a_locked_down_setup_scores_full() {
        let prefs = Prefs {
            focus_lock: true,
            ..Prefs::default()
        };
        let result = posture(&prefs, &strong_facts());
        assert_eq!(result.score, 100);
        assert!(result.advice.starts_with("Every check passes"));
    }

    #[test]
    fn the_biggest_gap_is_the_advice() {
        let lax = Prefs {
            lock_after_s: 3600,
            clip_clear_s: 90,
            focus_lock: true,
            ..Prefs::default()
        };
        let result = posture(&lax, &strong_facts());
        assert_eq!(result.score, 65);
        assert_eq!(result.advice, "Auto-lock after 5 minutes or less.");

        let one_factor = Facts {
            presence: Presence {
                recovery: true,
                ..Presence::default()
            },
            ..strong_facts()
        };
        let result = posture(&Prefs::default(), &one_factor);
        assert!(result.score < 80);
        assert_eq!(
            result.advice,
            "Enroll a second everyday factor (a password or this device)."
        );
    }
}
