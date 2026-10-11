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
    TAG_PREF_REVEAL_HIDE, TAG_PREF_THEME,
};

use crate::address::{parse_advertise, parse_relay_hint};
use crate::limits::{CLIP_CLEAR_S, LOCK_AFTER_S, RELAYS_MAX, REVEAL_HIDE_S};
use crate::listen::Listen;

const TAGS: [u16; 9] = [
    TAG_PREF_LOCK_AFTER,
    TAG_PREF_CLIP_CLEAR,
    TAG_PREF_REVEAL_HIDE,
    TAG_PREF_THEME,
    TAG_PREF_FLAGS,
    TAG_PREF_P2P_LISTEN,
    TAG_PREF_P2P_ADVERTISE,
    TAG_PREF_P2P_RELAYS,
    TAG_PREF_P2P_HOLD,
];

const FLAG_ANIM: u8 = 1;
const FLAG_ASCII: u8 = 1 << 1;
const FLAG_FOCUS_LOCK: u8 = 1 << 2;
const FLAGS_KNOWN: u8 = FLAG_ANIM | FLAG_ASCII | FLAG_FOCUS_LOCK;

/// Preferences of this device for one vault.
#[allow(clippy::struct_excessive_bools, reason = "flags")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Prefs {
    /// Auto-lock delay in seconds, within [`LOCK_AFTER_S`].
    pub lock_after_s: u16,
    /// Clipboard clear delay in seconds, within [`CLIP_CLEAR_S`].
    pub clip_clear_s: u8,
    /// Reveal auto-hide delay in seconds, within [`REVEAL_HIDE_S`].
    pub reveal_hide_s: u8,
    /// Color theme id; the interface maps unknown ids to its default.
    pub theme: u8,
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
            lock_after_s: 300,
            clip_clear_s: 20,
            reveal_hide_s: 5,
            theme: 0,
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
    }

    /// Read saved preferences from `doc`: `None` when none were ever
    /// saved, otherwise missing tags keep their default.
    ///
    /// # Errors
    ///
    /// `corrupted length` for a field of the wrong size;
    /// `preference out of range` for a value outside its bounds. Tags of
    /// retired preferences are ignored.
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
        let p2p_listen =
            byte(doc, TAG_PREF_P2P_LISTEN)?.map_or(Ok(defaults.p2p_listen), Listen::try_from)?;
        let fetch_only = p2p_listen == Listen::Fetch;
        let p2p_hold = match byte(doc, TAG_PREF_P2P_HOLD)? {
            None | Some(0) => false,
            Some(1) if !p2p_relays.is_empty() && !fetch_only => true,
            Some(_) => return Err(out_of_range()),
        };
        Ok(Self {
            lock_after_s,
            clip_clear_s,
            reveal_hide_s,
            theme: byte(doc, TAG_PREF_THEME)?.unwrap_or(defaults.theme),
            anim: flags & FLAG_ANIM != 0,
            ascii: flags & FLAG_ASCII != 0,
            focus_lock: flags & FLAG_FOCUS_LOCK != 0,
            p2p_listen,
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

    use super::{Listen, Prefs};

    fn custom() -> Prefs {
        Prefs {
            lock_after_s: 120,
            clip_clear_s: 10,
            reveal_hide_s: 3,
            theme: 2,
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
    }

    #[test]
    fn retired_tags_are_ignored_and_not_written_back() {
        let mut doc = written(&custom());
        doc.set_data(record::TAG_PREF_SYNC_MODE, ValueType::Bytes, &[3]);
        doc.set_text(record::TAG_PREF_SERVER_ORIGIN, "http://plain.example");
        doc.set_data(record::TAG_PREF_SERVER_PIN, ValueType::Bytes, &[1]);
        let read = Prefs::read(&doc).unwrap();
        assert_eq!(read, Some(custom()));
        let rewritten = written(&read.unwrap());
        for tag in [
            record::TAG_PREF_SYNC_MODE,
            record::TAG_PREF_SERVER_ORIGIN,
            record::TAG_PREF_SERVER_PIN,
        ] {
            assert!(rewritten.get(tag).is_none());
        }
        let mut only = Document::new();
        only.set_data(record::TAG_PREF_SYNC_MODE, ValueType::Bytes, &[2]);
        assert_eq!(Prefs::read(&only).unwrap(), None);
    }
}
