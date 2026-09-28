//! Auto-lock timer. Any key resets it.

use std::time::{Duration, Instant};

/// Inactivity tracker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Idle {
    last: Instant,
    after: Duration,
}

impl Idle {
    /// A timer that fires `after` inactivity, starting at `now`.
    #[must_use]
    pub const fn new(now: Instant, after: Duration) -> Self {
        Self { last: now, after }
    }

    /// Activity at `now`.
    pub const fn touch(&mut self, now: Instant) {
        self.last = now;
    }

    /// The configured delay.
    #[must_use]
    pub const fn after(&self) -> Duration {
        self.after
    }

    /// Change the delay.
    pub const fn set_after(&mut self, after: Duration) {
        self.after = after;
    }

    /// Time left before auto-lock.
    #[must_use]
    pub fn remaining(&self, now: Instant) -> Duration {
        self.after
            .saturating_sub(now.saturating_duration_since(self.last))
    }

    /// Whether the timer has run out.
    #[must_use]
    pub fn expired(&self, now: Instant) -> bool {
        self.remaining(now).is_zero()
    }
}

/// `m:ss` for a countdown.
#[must_use]
pub fn clock(left: Duration) -> String {
    let secs = left.as_secs();
    format!("{}:{:02}", secs / 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{clock, Idle};

    #[test]
    fn expires_after_the_delay_and_resets_on_touch() {
        let start = Instant::now();
        let mut idle = Idle::new(start, Duration::from_secs(300));
        assert!(!idle.expired(start + Duration::from_secs(299)));
        assert!(idle.expired(start + Duration::from_secs(300)));
        idle.touch(start + Duration::from_secs(300));
        assert_eq!(
            clock(idle.remaining(start + Duration::from_secs(308))),
            "4:52"
        );
    }
}
