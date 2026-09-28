//! The bridge between a vault's saved [`Prefs`] and the running services.

use std::time::Duration;

use local::Prefs;

use crate::app::ctx::Ctx;
use crate::cli::Flags;
use crate::ui::theme::ThemeName;

impl From<ThemeName> for u8 {
    fn from(name: ThemeName) -> Self {
        match name {
            ThemeName::StripesDark => 0,
            ThemeName::StripesLight => 1,
            ThemeName::Mono => 2,
        }
    }
}

/// The theme a saved id names; an id from a newer build is the default.
#[must_use]
pub fn theme_of(id: u8) -> ThemeName {
    ThemeName::ALL
        .into_iter()
        .find(|name| u8::from(*name) == id)
        .unwrap_or_default()
}

impl Ctx {
    /// Run with `prefs`: theme, motion, glyphs, focus lock, and timers.
    pub fn apply_prefs(&mut self, prefs: &Prefs) {
        if !self.no_color {
            self.theme.name = theme_of(prefs.theme);
        }
        self.flags = self
            .flags
            .with(Flags::ANIM, prefs.anim)
            .with(Flags::ASCII, prefs.ascii)
            .with(Flags::FOCUS_LOCK, prefs.focus_lock);
        self.retheme();
        self.idle
            .set_after(Duration::from_secs(u64::from(prefs.lock_after_s)));
        self.clipboard
            .set_clear_after(Duration::from_secs(u64::from(prefs.clip_clear_s)));
        self.reveal_after = Duration::from_secs(u64::from(prefs.reveal_hide_s));
        self.redraw();
    }
}

#[cfg(test)]
mod tests {
    use super::theme_of;
    use crate::ui::theme::ThemeName;

    #[test]
    fn theme_ids_round_trip_and_unknown_ids_fall_back() {
        for name in ThemeName::ALL {
            assert_eq!(theme_of(u8::from(name)), name);
        }
        assert_eq!(theme_of(0xFF), ThemeName::default());
    }
}
