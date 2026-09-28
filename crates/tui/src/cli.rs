//! Command-line flags. Hand-written: the surface is a handful of switches.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use crate::ui::theme::ThemeName;

/// Auto-lock after this much inactivity unless `--lock-after` says otherwise.
pub const DEFAULT_LOCK_AFTER: Duration = Duration::from_secs(5 * 60);
/// Clipboard clear delay unless `--clip-clear` says otherwise.
pub const DEFAULT_CLIP_CLEAR: Duration = Duration::from_secs(20);
/// Accepted clipboard clear range in seconds.
pub const CLIP_CLEAR_RANGE: std::ops::RangeInclusive<u64> = 5..=90;
/// Accepted auto-lock range in seconds.
pub const LOCK_AFTER_RANGE: std::ops::RangeInclusive<u64> = 30..=3600;

/// Usage text for `--help` and argument errors.
pub const USAGE: &str = "\
usage: zebrapass [options]

  --vault <file>        open this vault file instead of the default location
  --data-dir <dir>      use <dir> instead of ~/.zebrapass
  --theme <name>        stripes-dark (default), stripes-light, or mono
  --no-color            monochrome theme (also set by NO_COLOR)
  --ascii               ASCII glyphs instead of Unicode symbols
  --no-anim             reduced motion: freeze every animation
  --no-bench            skip the Argon2id timing estimate when creating a vault
  --lock-after <secs>   auto-lock after this much inactivity (30-3600, default 300)
  --clip-clear <secs>   clear the clipboard after this long (5-90, default 20)
  --focus-lock          lock when the terminal loses focus
  --trace-events        debug builds: log key kinds (never characters) to stderr
  -h, --help            show this help
  -V, --version         show the version
";

/// Runtime configuration assembled from flags and the environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Explicit vault file to open.
    pub vault: Option<PathBuf>,
    /// Explicit data directory; `None` means `local::base_dir()`.
    pub data_dir: Option<PathBuf>,
    /// Auto-lock delay.
    pub lock_after: Duration,
    /// Clipboard clear delay.
    pub clip_clear: Duration,
    /// Color theme.
    pub theme: ThemeName,
    /// Visual and interaction switches.
    pub flags: Flags,
}

/// On/off switches, packed so the config stays small and `Copy`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags(u8);

impl Flags {
    /// Animations run.
    pub const ANIM: u8 = 1;
    /// Unicode symbols are replaced by ASCII.
    pub const ASCII: u8 = 1 << 1;
    /// The Argon2id benchmark runs when creating a vault.
    pub const BENCH: u8 = 1 << 2;
    /// Losing terminal focus locks the vault.
    pub const FOCUS_LOCK: u8 = 1 << 3;
    /// Key kinds are traced to stderr (debug builds only).
    pub const TRACE: u8 = 1 << 4;

    /// Whether `bit` is set.
    #[must_use]
    pub const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// `self` with `bit` set to `on`.
    #[must_use]
    pub const fn with(self, bit: u8, on: bool) -> Self {
        if on {
            Self(self.0 | bit)
        } else {
            Self(self.0 & !bit)
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vault: None,
            data_dir: None,
            lock_after: DEFAULT_LOCK_AFTER,
            clip_clear: DEFAULT_CLIP_CLEAR,
            theme: ThemeName::StripesDark,
            flags: Flags::default()
                .with(Flags::ANIM, true)
                .with(Flags::BENCH, true),
        }
    }
}

/// What the command line asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Start the interface.
    Run(Box<Config>),
    /// Print usage and exit successfully.
    Help,
    /// Print the version and exit successfully.
    Version,
}

/// Parse `args` (without the program name). `no_color` is the `NO_COLOR`
/// environment switch.
///
/// # Errors
///
/// A human-readable message for an unknown flag, a missing value, or a value
/// out of range.
pub fn parse(args: impl IntoIterator<Item = OsString>, no_color: bool) -> Result<Command, String> {
    let mut config = Config::default();
    if no_color {
        config.theme = ThemeName::Mono;
    }
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let flag = arg.to_str().ok_or("arguments must be valid UTF-8")?;
        match flag {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "--vault" => config.vault = Some(PathBuf::from(value(&mut args, flag)?)),
            "--data-dir" => config.data_dir = Some(PathBuf::from(value(&mut args, flag)?)),
            "--theme" => {
                config.theme = value_str(&mut args, flag)?.parse().map_err(|()| {
                    String::from("--theme: expected stripes-dark, stripes-light, or mono")
                })?;
            }
            "--no-color" => config.theme = ThemeName::Mono,
            "--ascii" => config.flags = config.flags.with(Flags::ASCII, true),
            "--no-anim" => config.flags = config.flags.with(Flags::ANIM, false),
            "--no-bench" => config.flags = config.flags.with(Flags::BENCH, false),
            "--focus-lock" => config.flags = config.flags.with(Flags::FOCUS_LOCK, true),
            "--trace-events" => {
                config.flags = config.flags.with(Flags::TRACE, cfg!(debug_assertions));
            }
            "--lock-after" => config.lock_after = seconds(&mut args, flag, LOCK_AFTER_RANGE)?,
            "--clip-clear" => config.clip_clear = seconds(&mut args, flag, CLIP_CLEAR_RANGE)?,
            other => return Err(format!("unknown option: {other}")),
        }
    }
    Ok(Command::Run(Box::new(config)))
}

fn value(args: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<OsString, String> {
    args.next().ok_or_else(|| format!("{flag}: missing value"))
}

fn value_str(args: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<String, String> {
    value(args, flag)?
        .into_string()
        .map_err(|_| format!("{flag}: value must be valid UTF-8"))
}

fn seconds(
    args: &mut impl Iterator<Item = OsString>,
    flag: &str,
    range: std::ops::RangeInclusive<u64>,
) -> Result<Duration, String> {
    let raw = value_str(args, flag)?;
    let secs: u64 = raw
        .parse()
        .map_err(|_| format!("{flag}: expected a number of seconds"))?;
    if range.contains(&secs) {
        Ok(Duration::from_secs(secs))
    } else {
        Err(format!(
            "{flag}: must be between {} and {} seconds",
            range.start(),
            range.end()
        ))
    }
}
