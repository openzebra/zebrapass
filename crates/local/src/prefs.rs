//! This device's preferences for one vault, stored in the encrypted
//! `local.meta` so nothing on disk can change them without the vault key.
//!
//! A vault with no preference tag has no saved preferences, so start-up
//! settings stay in force. Once saved, a missing tag means its default; a
//! present tag with a bad length or an out-of-range value is an error,
//! never a silent default.

use record::{
    Document, ValueType, TAG_PREF_CLIP_CLEAR, TAG_PREF_FLAGS, TAG_PREF_LOCK_AFTER,
    TAG_PREF_P2P_ADVERTISE, TAG_PREF_P2P_HOLD, TAG_PREF_P2P_LISTEN, TAG_PREF_P2P_RELAYS,
    TAG_PREF_REVEAL_HIDE, TAG_PREF_SERVER_ORIGIN, TAG_PREF_SERVER_PIN, TAG_PREF_SYNC_MODE,
    TAG_PREF_THEME,
};

use crate::address::{parse_advertise, parse_relay_hint};
use crate::limits::{CLIP_CLEAR_S, LOCK_AFTER_S, ORIGIN_MAX, RELAYS_MAX, REVEAL_HIDE_S};

const TAGS: [u16; 12] = [
    TAG_PREF_LOCK_AFTER,
    TAG_PREF_CLIP_CLEAR,
    TAG_PREF_REVEAL_HIDE,
    TAG_PREF_THEME,
    TAG_PREF_FLAGS,
    TAG_PREF_SYNC_MODE,
    TAG_PREF_SERVER_ORIGIN,
    TAG_PREF_SERVER_PIN,
    TAG_PREF_P2P_LISTEN,
    TAG_PREF_P2P_ADVERTISE,
    TAG_PREF_P2P_RELAYS,
    TAG_PREF_P2P_HOLD,
];

const FLAG_ANIM: u8 = 1;
const FLAG_ASCII: u8 = 1 << 1;
const FLAG_FOCUS_LOCK: u8 = 1 << 2;
const FLAGS_KNOWN: u8 = FLAG_ANIM | FLAG_ASCII | FLAG_FOCUS_LOCK;

/// When records go to the sync server.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SyncMode {
    /// Never.
    #[default]
    Off,
    /// Only when asked.
    Manual,
    /// After every change.
    Auto,
}

impl SyncMode {
    /// Every mode, in display order.
    pub const ALL: [Self; 3] = [Self::Off, Self::Manual, Self::Auto];
}

impl From<SyncMode> for u8 {
    fn from(mode: SyncMode) -> Self {
        match mode {
            SyncMode::Off => 0,
            SyncMode::Manual => 1,
            SyncMode::Auto => 2,
        }
    }
}

impl TryFrom<u8> for SyncMode {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> anyhow::Result<Self> {
        Self::ALL
            .into_iter()
            .find(|mode| u8::from(*mode) == byte)
            .ok_or_else(out_of_range)
    }
}

/// Where this device's sync node accepts connections.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Listen {
    /// Nowhere: the device only fetches from others.
    Off,
    /// On this device only (`127.0.0.1`).
    Local,
    /// On the local network (`0.0.0.0`).
    #[default]
    Lan,
    /// On the local network, and announced there by a sealed beacon that
    /// only the account's other devices can read.
    Beacon,
}

impl Listen {
    /// Every mode, in the order a toggle cycles through them.
    pub const ALL: [Self; 4] = [Self::Lan, Self::Beacon, Self::Local, Self::Off];

    /// The next mode.
    #[must_use]
    pub fn next(self) -> Self {
        let at = Self::ALL.iter().position(|mode| *mode == self).unwrap_or(0);
        Self::ALL
            .get((at + 1) % Self::ALL.len())
            .copied()
            .unwrap_or(Self::Off)
    }
}

impl From<Listen> for u8 {
    fn from(mode: Listen) -> Self {
        match mode {
            Listen::Off => 0,
            Listen::Local => 1,
            Listen::Lan => 2,
            Listen::Beacon => 3,
        }
    }
}

impl TryFrom<u8> for Listen {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> anyhow::Result<Self> {
        Self::ALL
            .into_iter()
            .find(|mode| u8::from(*mode) == byte)
            .ok_or_else(out_of_range)
    }
}

/// Preferences of this device for one vault.
#[allow(clippy::struct_excessive_bools, reason = "flags")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Prefs {
    /// Sync server origin, validated by [`parse_origin`].
    pub server_origin: Option<Box<str>>,
    /// Pinned fingerprint of the sync server's signing key.
    pub server_key_pin: Option<[u8; 32]>,
    /// Auto-lock delay in seconds, within [`LOCK_AFTER_S`].
    pub lock_after_s: u16,
    /// Clipboard clear delay in seconds, within [`CLIP_CLEAR_S`].
    pub clip_clear_s: u8,
    /// Reveal auto-hide delay in seconds, within [`REVEAL_HIDE_S`].
    pub reveal_hide_s: u8,
    /// Color theme id; the interface maps unknown ids to its default.
    pub theme: u8,
    /// Sync mode.
    pub sync_mode: SyncMode,
    /// Animations run.
    pub anim: bool,
    /// ASCII glyphs instead of Unicode symbols.
    pub ascii: bool,
    /// Losing terminal focus locks the vault.
    pub focus_lock: bool,
    /// Where the sync node accepts connections.
    pub p2p_listen: Listen,
    /// The address, as `ip:port`, this device offers other members when it
    /// sits behind a port forward; validated by [`parse_advertise`].
    pub p2p_advertise: Option<Box<str>>,
    /// Relay slots, as `ip:port/slot`, this device was told about and may
    /// dial through; each validated by [`parse_relay_hint`], at most four.
    pub p2p_relays: Vec<Box<str>>,
    /// This node holds a slot on the first saved relay and announces it; only
    /// ever on while a relay is saved.
    pub p2p_hold: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            server_origin: None,
            server_key_pin: None,
            lock_after_s: 300,
            clip_clear_s: 20,
            reveal_hide_s: 5,
            theme: 0,
            sync_mode: SyncMode::Off,
            anim: true,
            ascii: false,
            focus_lock: false,
            p2p_listen: Listen::Lan,
            p2p_advertise: None,
            p2p_relays: Vec::new(),
            p2p_hold: false,
        }
    }
}

impl Prefs {
    /// Write every preference into `doc`.
    pub fn write(&self, doc: &mut Document) {
        doc.set_data(
            TAG_PREF_LOCK_AFTER,
            ValueType::Bytes,
            &self.lock_after_s.to_le_bytes(),
        );
        doc.set_data(TAG_PREF_CLIP_CLEAR, ValueType::Bytes, &[self.clip_clear_s]);
        doc.set_data(
            TAG_PREF_REVEAL_HIDE,
            ValueType::Bytes,
            &[self.reveal_hide_s],
        );
        doc.set_data(TAG_PREF_THEME, ValueType::Bytes, &[self.theme]);
        doc.set_data(TAG_PREF_FLAGS, ValueType::Bytes, &[self.flags()]);
        doc.set_data(
            TAG_PREF_SYNC_MODE,
            ValueType::Bytes,
            &[u8::from(self.sync_mode)],
        );
        doc.set_data(
            TAG_PREF_P2P_LISTEN,
            ValueType::Bytes,
            &[u8::from(self.p2p_listen)],
        );
        if let Some(address) = self.p2p_advertise.as_deref() {
            doc.set_text(TAG_PREF_P2P_ADVERTISE, address);
        }
        if !self.p2p_relays.is_empty() {
            doc.set_text(TAG_PREF_P2P_RELAYS, &self.p2p_relays.join("\n"));
        }
        if self.p2p_hold {
            doc.set_data(TAG_PREF_P2P_HOLD, ValueType::Bytes, &[1]);
        }
        if let Some(origin) = self.server_origin.as_deref() {
            doc.set_text(TAG_PREF_SERVER_ORIGIN, origin);
        }
        if let Some(pin) = self.server_key_pin.as_ref() {
            doc.set_data(TAG_PREF_SERVER_PIN, ValueType::Bytes, pin);
        }
    }

    /// Read saved preferences from `doc`: `None` when none were ever
    /// saved, otherwise missing tags keep their default.
    ///
    /// # Errors
    ///
    /// `corrupted length` for a field of the wrong size;
    /// `preference out of range` for a value outside its bounds or an
    /// origin [`parse_origin`] refuses.
    pub fn read(doc: &Document) -> anyhow::Result<Option<Self>> {
        if TAGS.iter().all(|tag| doc.get(*tag).is_none()) {
            return Ok(None);
        }
        Self::read_saved(doc).map(Some)
    }

    fn read_saved(doc: &Document) -> anyhow::Result<Self> {
        let defaults = Self::default();
        let lock_after_s = match doc.data(TAG_PREF_LOCK_AFTER)? {
            Some(bytes) => u16::from_le_bytes(fixed(bytes)?),
            None => defaults.lock_after_s,
        };
        let clip_clear_s = byte(doc, TAG_PREF_CLIP_CLEAR)?.unwrap_or(defaults.clip_clear_s);
        let reveal_hide_s = byte(doc, TAG_PREF_REVEAL_HIDE)?.unwrap_or(defaults.reveal_hide_s);
        let flags = byte(doc, TAG_PREF_FLAGS)?.unwrap_or_else(|| defaults.flags());
        if flags & !FLAGS_KNOWN != 0
            || !LOCK_AFTER_S.contains(&lock_after_s)
            || !CLIP_CLEAR_S.contains(&clip_clear_s)
            || !REVEAL_HIDE_S.contains(&reveal_hide_s)
        {
            return Err(out_of_range());
        }
        let sync_mode =
            byte(doc, TAG_PREF_SYNC_MODE)?.map_or(Ok(defaults.sync_mode), SyncMode::try_from)?;
        let server_origin = doc
            .text(TAG_PREF_SERVER_ORIGIN)?
            .map(|origin| parse_origin(origin).map_err(|_| out_of_range()))
            .transpose()?;
        let server_key_pin = doc.data(TAG_PREF_SERVER_PIN)?.map(fixed).transpose()?;
        let p2p_advertise = doc
            .text(TAG_PREF_P2P_ADVERTISE)?
            .map(|address| parse_advertise(address).map_err(|_| out_of_range()))
            .transpose()?;
        let p2p_relays = doc
            .text(TAG_PREF_P2P_RELAYS)?
            .map(|lines| {
                lines
                    .split('\n')
                    .map(|line| parse_relay_hint(line).map_err(|_| out_of_range()))
                    .collect::<anyhow::Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        if p2p_relays.len() > RELAYS_MAX {
            return Err(out_of_range());
        }
        let p2p_hold = match byte(doc, TAG_PREF_P2P_HOLD)? {
            None | Some(0) => false,
            Some(1) if !p2p_relays.is_empty() => true,
            Some(_) => return Err(out_of_range()),
        };
        Ok(Self {
            server_origin,
            server_key_pin,
            lock_after_s,
            clip_clear_s,
            reveal_hide_s,
            theme: byte(doc, TAG_PREF_THEME)?.unwrap_or(defaults.theme),
            sync_mode,
            anim: flags & FLAG_ANIM != 0,
            ascii: flags & FLAG_ASCII != 0,
            focus_lock: flags & FLAG_FOCUS_LOCK != 0,
            p2p_listen: byte(doc, TAG_PREF_P2P_LISTEN)?
                .map_or(Ok(defaults.p2p_listen), Listen::try_from)?,
            p2p_advertise,
            p2p_relays,
            p2p_hold,
        })
    }

    const fn flags(&self) -> u8 {
        (if self.anim { FLAG_ANIM } else { 0 })
            | (if self.ascii { FLAG_ASCII } else { 0 })
            | (if self.focus_lock { FLAG_FOCUS_LOCK } else { 0 })
    }
}

/// Validate a sync server origin: `https://host[:port]`, lowercased, with
/// an optional trailing `/` dropped.
///
/// # Errors
///
/// A short reason the interface can show as is.
pub fn parse_origin(input: &str) -> Result<Box<str>, &'static str> {
    let trimmed = input.trim();
    if trimmed.len() > ORIGIN_MAX {
        return Err("That address is too long.");
    }
    let lowered = trimmed.to_ascii_lowercase();
    let rest = lowered
        .strip_prefix("https://")
        .ok_or("Use an https:// address.")?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains(['/', '?', '#', '@']) {
        return Err("Only https://host[:port]: no path, query, or user name.");
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if !valid_host(host) {
        return Err("That host name is not valid.");
    }
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err("That port is not valid.");
        }
        match port.parse::<u16>() {
            Ok(value) if value > 0 => {}
            _ => return Err("That port is not valid."),
        }
    }
    let mut origin = String::with_capacity(8 + authority.len());
    origin.push_str("https://");
    origin.push_str(authority);
    Ok(origin.into_boxed_str())
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn byte(doc: &Document, tag: u16) -> anyhow::Result<Option<u8>> {
    doc.data(tag)?
        .map(|bytes| fixed::<1>(bytes).map(|[value]| value))
        .transpose()
}

fn fixed<const N: usize>(bytes: &[u8]) -> anyhow::Result<[u8; N]> {
    <[u8; N]>::try_from(bytes).map_err(|_| anyhow::anyhow!("corrupted length"))
}

fn out_of_range() -> anyhow::Error {
    anyhow::anyhow!("preference out of range")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use record::{Document, ValueType, TAG_PREF_CLIP_CLEAR, TAG_PREF_FLAGS, TAG_PREF_LOCK_AFTER};

    use super::{parse_origin, Listen, Prefs, SyncMode};

    fn custom() -> Prefs {
        Prefs {
            server_origin: Some("https://sync.example.com:8443".into()),
            server_key_pin: Some([7; 32]),
            lock_after_s: 120,
            clip_clear_s: 10,
            reveal_hide_s: 3,
            theme: 2,
            sync_mode: SyncMode::Manual,
            anim: false,
            ascii: true,
            focus_lock: true,
            p2p_listen: Listen::Off,
            p2p_advertise: Some("93.184.216.34:7447".into()),
            p2p_relays: vec![format!("93.184.216.35:7447/{}", "ab".repeat(16)).into()],
            p2p_hold: true,
        }
    }

    #[test]
    fn a_saved_advertised_address_that_does_not_validate_is_an_error() {
        let mut doc = written(&custom());
        doc.set_text(record::TAG_PREF_P2P_ADVERTISE, "localhost:7447");
        assert!(Prefs::read(&doc).is_err());
    }

    fn written(prefs: &Prefs) -> Document {
        let mut doc = Document::new();
        prefs.write(&mut doc);
        doc
    }

    #[test]
    fn round_trip_and_missing_tags_are_defaults() {
        assert_eq!(Prefs::read(&written(&custom())).unwrap(), Some(custom()));
        assert_eq!(Prefs::read(&Document::new()).unwrap(), None);
        let mut one = Document::new();
        one.set_data(TAG_PREF_CLIP_CLEAR, ValueType::Bytes, &[30]);
        let partial = Prefs {
            clip_clear_s: 30,
            ..Prefs::default()
        };
        assert_eq!(Prefs::read(&one).unwrap(), Some(partial));
    }

    #[test]
    fn out_of_range_and_bad_lengths_are_errors() {
        let cases: [(u16, &[u8], &str); 5] = [
            (
                TAG_PREF_LOCK_AFTER,
                &29u16.to_le_bytes(),
                "preference out of range",
            ),
            (TAG_PREF_LOCK_AFTER, &[1], "corrupted length"),
            (TAG_PREF_CLIP_CLEAR, &[91], "preference out of range"),
            (TAG_PREF_CLIP_CLEAR, &[5, 5], "corrupted length"),
            (TAG_PREF_FLAGS, &[0x80], "preference out of range"),
        ];
        for (tag, value, message) in cases {
            let mut doc = written(&Prefs::default());
            doc.set_data(tag, ValueType::Bytes, value);
            assert_eq!(Prefs::read(&doc).unwrap_err().to_string(), message);
        }
        let mut doc = written(&Prefs::default());
        doc.set_data(record::TAG_PREF_SYNC_MODE, ValueType::Bytes, &[3]);
        assert!(Prefs::read(&doc).is_err());
        let mut doc = written(&Prefs::default());
        doc.set_text(record::TAG_PREF_SERVER_ORIGIN, "http://plain.example");
        assert!(Prefs::read(&doc).is_err());
    }

    #[test]
    fn origins_are_https_host_and_port_only() {
        assert_eq!(
            parse_origin("  HTTPS://Sync.Example.com:8443/ ")
                .unwrap()
                .as_ref(),
            "https://sync.example.com:8443"
        );
        assert_eq!(
            parse_origin("https://vault.example").unwrap().as_ref(),
            "https://vault.example"
        );
        let long = format!("https://{}.example", "a".repeat(300));
        for bad in [
            "",
            "http://sync.example",
            "sync.example",
            "https://",
            "https://user@sync.example",
            "https://sync.example/path",
            "https://sync.example?q=1",
            "https://sync.example#x",
            "https://-bad.example",
            "https://bad..example",
            "https://sync.example:0",
            "https://sync.example:70000",
            "https://sync.example:",
            "https://sync.example:8a",
            "https://sync_example.com",
            long.as_str(),
        ] {
            assert!(parse_origin(bad).is_err(), "{bad}");
        }
    }
}
