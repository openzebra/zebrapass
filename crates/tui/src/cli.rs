//! Command-line flags. Hand-written: the surface is a handful of switches.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use p2p_net::BeaconConfig;

use crate::ui::theme::ThemeName;

/// Auto-lock after this much inactivity unless `--lock-after` says otherwise.
pub const DEFAULT_LOCK_AFTER: Duration = Duration::from_mins(5);
/// Clipboard clear delay unless `--clip-clear` says otherwise.
pub const DEFAULT_CLIP_CLEAR: Duration = Duration::from_secs(20);
/// Accepted clipboard clear range in seconds.
pub const CLIP_CLEAR_RANGE: std::ops::RangeInclusive<u64> = 5..=90;
/// Accepted auto-lock range in seconds.
pub const LOCK_AFTER_RANGE: std::ops::RangeInclusive<u64> = 30..=3600;

/// Usage text for `--help` and argument errors.
pub const USAGE: &str = "\
usage: zebrapass [options]
       zebrapass --server --listen <ip:port> --cert <pem> --key <pem> --secret-path <slug> [options]

client options:
  --vault <file>        open this vault file instead of the default location
  --data-dir <dir>      use <dir> instead of ~/.zebrapass
  --sync-server <url>   add an HTTPS/WSS sync endpoint (repeatable)
  --proxy <url>         tunnel HTTPS/WSS sync over socks5h:// or http:// proxy
  --extra-ca <pem>      trust additional CA certificate PEM for sync servers
  --theme <name>        stripes-dark (default), stripes-light, or mono
  --no-color            monochrome theme (also set by NO_COLOR)
  --ascii               ASCII glyphs instead of Unicode symbols
  --no-anim             reduced motion: freeze every animation
  --no-bench            skip the Argon2id timing estimate when creating a vault
  --lock-after <secs>   auto-lock after this much inactivity (30-3600, default 300)
  --clip-clear <secs>   clear the clipboard after this long (5-90, default 20)
  --focus-lock          lock when the terminal loses focus
  --lan-beacon          the restore screen listens for devices announced on this network
  --trace-events        debug builds: log key kinds (never characters) to stderr

server options (with --server):
  --server              run the zero-knowledge PQ HTTPS/WSS + SplitHTTP sync relay
  --listen <ip:port>    TCP bind address (e.g. 0.0.0.0:8443)
  --cert <pem>          TLS certificate chain PEM file
  --key <pem>           TLS private key PEM file
  --secret-path <slug>  camouflage URL path prefix (>= 16 chars)
  --public-origin <url> origin string signed in requests (default: https://<listen>)
  --data-dir <dir>      mailbox storage directory (default: ~/.zebrapass/server)

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
    /// Pre-configured HTTPS/WSS sync server URLs.
    pub sync_servers: Vec<Box<str>>,
    /// Pre-configured outbound proxy (`socks5h://` or `http://`).
    pub sync_proxy: Option<Box<str>>,
    /// Optional additional CA certificate PEM path.
    pub extra_ca: Option<PathBuf>,
    /// Auto-lock delay.
    pub lock_after: Duration,
    /// Clipboard clear delay.
    pub clip_clear: Duration,
    /// Color theme.
    pub theme: ThemeName,
    /// Visual and interaction switches.
    pub flags: Flags,
    /// Where LAN beacons go and are heard.
    pub beacon: Option<BeaconConfig>,
}

/// Configuration for `zebrapass --server`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerArgs {
    /// Local TCP bind address.
    pub listen: SocketAddr,
    /// TLS certificate chain PEM path.
    pub cert: PathBuf,
    /// TLS private key PEM path.
    pub key: PathBuf,
    /// Mailbox storage directory.
    pub data_dir: Option<PathBuf>,
    /// `WebTunnel` camouflage secret slug.
    pub secret_path: Box<str>,
    /// Public HTTPS origin signed into client requests.
    pub public_origin: Option<Box<str>>,
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
            sync_servers: Vec::new(),
            sync_proxy: None,
            extra_ca: None,
            lock_after: DEFAULT_LOCK_AFTER,
            clip_clear: DEFAULT_CLIP_CLEAR,
            theme: ThemeName::StripesDark,
            flags: Flags::default()
                .with(Flags::ANIM, true)
                .with(Flags::BENCH, true),
            beacon: None,
        }
    }
}

/// What the command line asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Start the interface.
    Run(Box<Config>),
    /// Run the zero-knowledge HTTPS/WSS + `SplitHTTP` sync relay daemon.
    Server(Box<ServerArgs>),
    /// Print usage and exit successfully.
    Help,
    /// Print the version and exit successfully.
    Version,
}

#[derive(Default)]
struct ServerDraft {
    enabled: bool,
    listen: Option<SocketAddr>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    secret_path: Option<Box<str>>,
    public_origin: Option<Box<str>>,
}

impl ServerDraft {
    fn parse_flag(
        &mut self,
        flag: &str,
        args: &mut impl Iterator<Item = OsString>,
    ) -> Result<bool, String> {
        match flag {
            "--server" => self.enabled = true,
            "--listen" => {
                let raw = value_str(args, flag)?;
                self.listen = Some(raw.parse().map_err(|_| "--listen: expected ip:port")?);
            }
            "--cert" => self.cert = Some(PathBuf::from(value(args, flag)?)),
            "--key" => self.key = Some(PathBuf::from(value(args, flag)?)),
            "--secret-path" => {
                let slug = value_str(args, flag)?;
                if slug.len() < sync_https::limits::MIN_SECRET_SLUG_LEN {
                    return Err(String::from(
                        "--secret-path: must be at least 16 characters",
                    ));
                }
                self.secret_path = Some(slug.into_boxed_str());
            }
            "--public-origin" => {
                self.public_origin = Some(value_str(args, flag)?.into_boxed_str());
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> Result<ServerArgs, String> {
        Ok(ServerArgs {
            listen: self.listen.ok_or("--server requires --listen <ip:port>")?,
            cert: self.cert.ok_or("--server requires --cert <pem>")?,
            key: self.key.ok_or("--server requires --key <pem>")?,
            data_dir: self.data_dir,
            secret_path: self
                .secret_path
                .ok_or("--server requires --secret-path <slug>")?,
            public_origin: self.public_origin,
        })
    }
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
    let mut srv = ServerDraft::default();
    if no_color {
        config.theme = ThemeName::Mono;
    }
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let flag = arg.to_str().ok_or("arguments must be valid UTF-8")?;
        if srv.parse_flag(flag, &mut args)? {
            continue;
        }
        match flag {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "--vault" => config.vault = Some(PathBuf::from(value(&mut args, flag)?)),
            "--data-dir" => {
                let dir = PathBuf::from(value(&mut args, flag)?);
                srv.data_dir = Some(dir.clone());
                config.data_dir = Some(dir);
            }
            "--sync-server" => {
                let url = local::parse_sync_server_url(&value_str(&mut args, flag)?, true)
                    .map_err(str::to_owned)?;
                if config.sync_servers.len() >= local::SYNC_SERVERS_MAX {
                    return Err(String::from("--sync-server: too many endpoints"));
                }
                if !config.sync_servers.contains(&url) {
                    config.sync_servers.push(url);
                }
            }
            "--proxy" => {
                config.sync_proxy = Some(
                    local::parse_sync_proxy_url(&value_str(&mut args, flag)?)
                        .map_err(str::to_owned)?,
                );
            }
            "--extra-ca" => config.extra_ca = Some(PathBuf::from(value(&mut args, flag)?)),
            "--theme" => {
                config.theme = value_str(&mut args, flag)?.parse().map_err(|()| {
                    String::from("--theme: expected stripes-dark, stripes-light, or mono")
                })?;
            }
            "--no-color" => config.theme = ThemeName::Mono,
            "--ascii" => config.flags = config.flags.with(Flags::ASCII, true),
            "--no-anim" => config.flags = config.flags.with(Flags::ANIM, false),
            "--no-bench" => config.flags = config.flags.with(Flags::BENCH, false),
            "--lan-beacon" => config.beacon = Some(BeaconConfig::lan()),
            "--focus-lock" => config.flags = config.flags.with(Flags::FOCUS_LOCK, true),
            "--trace-events" => {
                config.flags = config.flags.with(Flags::TRACE, cfg!(debug_assertions));
            }
            "--lock-after" => config.lock_after = seconds(&mut args, flag, LOCK_AFTER_RANGE)?,
            "--clip-clear" => config.clip_clear = seconds(&mut args, flag, CLIP_CLEAR_RANGE)?,
            other => return Err(format!("unknown option: {other}")),
        }
    }
    if srv.enabled {
        return Ok(Command::Server(Box::new(srv.finish()?)));
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
