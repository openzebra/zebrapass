//! Services every flow shares: time, theme, worker, clipboard, notices, the
//! idle timer, and the in-flight job.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::app::idle::Idle;
use crate::app::worker::{Job, Worker};
use crate::cli::{Config, Flags};
use crate::secure::clipboard::{Clipboard, CopyError};
use crate::secure::reveal::REVEAL_TIMEOUT;
use crate::ui::theme::{Theme, ThemeName};
use crate::ui::widgets::toast::{Toasts, Tone};

/// What the terminal can do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    /// OSC 52 clipboard is likely honored.
    pub osc52: bool,
    /// Key release events are reported (kitty keyboard protocol).
    pub key_release: bool,
}

/// The kind of job the app is waiting for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    /// Unlocking, with the password factor's Argon2id cost when known.
    Unlock(Option<(u32, u32, u32)>),
    /// Creating a vault.
    Create,
    /// Restoring a vault.
    Restore,
    /// Writing a record.
    Save,
    /// Rotating the vault key.
    Rotate,
    /// Changing the factor list.
    Factor,
    /// Health analysis.
    Health,
    /// Reading another manager's export.
    Import,
}

impl Task {
    /// Progress title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Unlock(_) => "Unlocking",
            Self::Create => "Creating your vault",
            Self::Restore => "Restoring your vault",
            Self::Save => "Saving",
            Self::Rotate => "Rotating the vault key",
            Self::Factor => "Updating unlock factors",
            Self::Health => "Checking vault health",
            Self::Import => "Reading the export",
        }
    }

    /// Only jobs that do not hold the vault can be detached.
    #[must_use]
    pub const fn cancellable(self) -> bool {
        matches!(
            self,
            Self::Unlock(_) | Self::Create | Self::Restore | Self::Import
        )
    }
}

/// The job the UI waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    /// Worker ticket.
    pub ticket: u64,
    /// What it is.
    pub task: Task,
    /// When it started.
    pub since: Instant,
}

/// Shared services.
#[derive(Debug)]
pub struct Ctx {
    /// Clock for this frame.
    pub now: Instant,
    /// Animation tick counter (one per ~60 ms).
    pub tick: u64,
    /// Data directory.
    pub base: PathBuf,
    /// Explicit vault file from the command line.
    pub vault_file: Option<PathBuf>,
    /// Colors, glyphs, motion.
    pub theme: Theme,
    /// Terminal capabilities.
    pub caps: Caps,
    /// Command-line switches.
    pub flags: Flags,
    /// Notices.
    pub toasts: Toasts,
    /// Clipboard.
    pub clipboard: Clipboard,
    /// Worker thread.
    pub worker: Worker,
    /// The job the UI waits for.
    pub pending: Option<Pending>,
    /// Auto-lock timer.
    pub idle: Idle,
    /// A revealed secret hides itself after this long.
    pub reveal_after: Duration,
    /// Colors were switched off at start-up (`--no-color`, `NO_COLOR`); no
    /// saved preference turns them back on.
    pub no_color: bool,
    /// Measured time of one [`session::KdfProfile::Fast`] Argon2id run.
    pub kdf_fast: Option<Duration>,
    /// The next frame must clear the terminal first.
    pub full_redraw: bool,
    /// Terminal size `(columns, rows)`.
    pub size: (u16, u16),
    /// Where LAN beacons go and are heard; see [`crate::cli::Config::beacon`].
    pub beacon: Option<p2p_net::BeaconConfig>,
}

impl Ctx {
    /// Build the services.
    ///
    /// # Errors
    ///
    /// When the worker thread cannot start.
    pub fn new(config: &Config, base: PathBuf, caps: Caps, now: Instant) -> std::io::Result<Self> {
        Ok(Self {
            now,
            tick: 0,
            base,
            vault_file: config.vault.clone(),
            theme: Theme::new(
                config.theme,
                config.flags.has(Flags::ASCII),
                config.flags.has(Flags::ANIM),
            ),
            caps,
            flags: config.flags,
            toasts: Toasts::default(),
            clipboard: Clipboard::new(caps.osc52, config.clip_clear),
            worker: Worker::spawn()?,
            pending: None,
            idle: Idle::new(now, config.lock_after),
            reveal_after: REVEAL_TIMEOUT,
            no_color: config.theme == ThemeName::Mono,
            kdf_fast: None,
            full_redraw: false,
            size: (120, 40),
            beacon: config.beacon,
        })
    }

    /// Queue `job` and wait for it.
    pub fn start(&mut self, job: Job, task: Task) {
        let ticket = self.worker.submit(job);
        self.pending = Some(Pending {
            ticket,
            task,
            since: self.now,
        });
    }

    /// Whether a job the UI waits for is running.
    #[must_use]
    pub const fn busy(&self) -> bool {
        self.pending.is_some()
    }

    /// Show a notice.
    pub fn toast(&mut self, tone: Tone, text: impl Into<Box<str>>) {
        self.toasts.push(tone, text, self.now);
    }

    /// Copy a secret with the clear timer, and say so; `true` when copied.
    pub fn copy(&mut self, secret: &[u8], label: &'static str) -> bool {
        let result = self.clipboard.copy(secret, label, self.now);
        self.copied(result)
    }

    /// As [`Ctx::copy`], clearing after `clear_after` instead of the usual
    /// delay.
    pub fn copy_for(&mut self, secret: &[u8], label: &'static str, clear_after: Duration) -> bool {
        let result = self
            .clipboard
            .copy_for(secret, label, self.now, clear_after);
        self.copied(result)
    }

    fn copied(&mut self, result: Result<(), CopyError>) -> bool {
        match result {
            Ok(()) => true,
            Err(CopyError::Unavailable) => {
                self.toast(
                    Tone::Warn,
                    "Clipboard unavailable in this terminal. Use Space to reveal.",
                );
                false
            }
            Err(CopyError::TooLarge) => {
                self.toast(Tone::Warn, "Too large for the terminal clipboard.");
                false
            }
        }
    }

    /// Clear the terminal on the next frame (overwrites revealed cells).
    pub const fn redraw(&mut self) {
        self.full_redraw = true;
    }

    /// Rebuild the theme after a setting changed.
    pub const fn retheme(&mut self) {
        self.theme = Theme::new(
            self.theme.name,
            self.flags.has(Flags::ASCII),
            self.flags.has(Flags::ANIM),
        );
    }
}
