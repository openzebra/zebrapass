//! The protocol a member speaks to a relay before the relay joins it to
//! another member, and how a relay address appears in a peer record.
//!
//! A connection opens with the magic and a version, once, from the client.
//! Every message after that is a frame: type, a `u16` payload length, the
//! payload. The length is checked against the limit of its type and sender
//! before anything is read. Once the relay answers `SPLICE`, the stream is no
//! longer this protocol: it is the unchanged handshake of two members.

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::{anyhow, Result};

use crate::limits::{
    RELAY_CHALLENGE_LEN, RELAY_CLAIM_LEN, RELAY_HEADER_LEN, RELAY_MAX_DIFFICULTY, RELAY_OPEN_LEN,
    RELAY_RESERVED_LEN, RELAY_SLOT_DIGITS,
};
use crate::mux_body::Ping;
use crate::reader::Reader;

/// First four bytes of a relay connection.
pub const RELAY_MAGIC: [u8; 4] = *b"ZPRY";
/// Current relay wire version.
pub const RELAY_WIRE_VERSION: u16 = 1;

fn invalid() -> anyhow::Error {
    anyhow!("invalid sync object")
}

/// What a client sends first.
#[must_use]
pub const fn encode_open() -> [u8; RELAY_OPEN_LEN] {
    let [v0, v1] = RELAY_WIRE_VERSION.to_be_bytes();
    let [m0, m1, m2, m3] = RELAY_MAGIC;
    [m0, m1, m2, m3, v0, v1]
}

/// Check what a client sent first.
///
/// # Errors
///
/// A wrong magic or version.
pub fn decode_open(bytes: &[u8; RELAY_OPEN_LEN]) -> Result<()> {
    let mut reader = Reader::new(bytes);
    if reader.array::<4>()? != RELAY_MAGIC || reader.u16()? != RELAY_WIRE_VERSION {
        return Err(invalid());
    }
    reader.finish()
}

/// Who sends a frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    /// A member connecting to a relay.
    Client,
    /// A relay answering.
    Relay,
}

/// Every relay frame type. The table is fixed; an unknown type closes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelayType {
    /// Client: hold a slot open.
    Reserve = 0x01,
    /// Client: ask to be joined to the member holding a slot.
    Connect = 0x02,
    /// Client: take a pending connection named by the relay.
    Accept = 0x03,
    /// Client: keepalive.
    Ping = 0x04,
    /// Relay: the puzzle to solve before a claim.
    Challenge = 0x10,
    /// Relay: a slot is held, and under what limits.
    Reserved = 0x11,
    /// Relay: someone wants the slot; take connection `conn_id`.
    Incoming = 0x12,
    /// Relay: from here the stream is the two members'.
    Splice = 0x13,
    /// Relay: keepalive answer.
    Pong = 0x14,
    /// Relay: at capacity; not the client's fault.
    Busy = 0x1E,
    /// Relay: no, whatever the reason.
    Refused = 0x1F,
}

impl TryFrom<u8> for RelayType {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> Result<Self> {
        Ok(match byte {
            0x01 => Self::Reserve,
            0x02 => Self::Connect,
            0x03 => Self::Accept,
            0x04 => Self::Ping,
            0x10 => Self::Challenge,
            0x11 => Self::Reserved,
            0x12 => Self::Incoming,
            0x13 => Self::Splice,
            0x14 => Self::Pong,
            0x1E => Self::Busy,
            0x1F => Self::Refused,
            _ => return Err(invalid()),
        })
    }
}

impl RelayType {
    /// Largest payload of this type from `from`, or `None` when `from` may
    /// not send it.
    #[must_use]
    pub const fn max_payload(self, from: Side) -> Option<usize> {
        match from {
            Side::Client => match self {
                Self::Reserve | Self::Connect | Self::Accept => Some(RELAY_CLAIM_LEN),
                Self::Ping => Some(Ping::LEN),
                Self::Challenge
                | Self::Reserved
                | Self::Incoming
                | Self::Splice
                | Self::Pong
                | Self::Busy
                | Self::Refused => None,
            },
            Side::Relay => match self {
                Self::Challenge => Some(RELAY_CHALLENGE_LEN),
                Self::Reserved => Some(RELAY_RESERVED_LEN),
                Self::Incoming => Some(16),
                Self::Pong => Some(Ping::LEN),
                Self::Splice | Self::Busy | Self::Refused => Some(0),
                Self::Reserve | Self::Connect | Self::Accept | Self::Ping => None,
            },
        }
    }
}

/// A decoded frame header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayHeader {
    /// What the payload is.
    pub ty: RelayType,
    /// The payload length, already within the limit of the type.
    pub len: u16,
}

impl RelayHeader {
    /// A header for a payload of `len` bytes sent by `from`.
    ///
    /// # Errors
    ///
    /// The type is not one `from` sends, or `len` is over its limit.
    pub fn new(ty: RelayType, len: usize, from: Side) -> Result<Self> {
        if ty.max_payload(from).is_none_or(|max| len > max) {
            return Err(invalid());
        }
        Ok(Self {
            ty,
            len: u16::try_from(len)?,
        })
    }

    /// The three header bytes.
    #[must_use]
    pub const fn encode(&self) -> [u8; RELAY_HEADER_LEN] {
        let [len0, len1] = self.len.to_be_bytes();
        [self.ty as u8, len0, len1]
    }

    /// Parse a header received from `from`; nothing is allocated yet.
    ///
    /// # Errors
    ///
    /// An unknown type, one `from` may not send, or a length over the limit.
    pub fn decode(bytes: &[u8; RELAY_HEADER_LEN], from: Side) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let ty = RelayType::try_from(reader.array::<1>()?[0])?;
        let len = reader.u16()?;
        reader.finish()?;
        let max = ty.max_payload(from).ok_or_else(invalid)?;
        if usize::from(len) > max {
            return Err(invalid());
        }
        Ok(Self { ty, len })
    }
}

/// A request naming a slot (`Reserve`, `Connect`) or a pending connection
/// (`Accept`), with the solution to the puzzle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Claim {
    /// The slot or connection id.
    pub id: [u8; 16],
    /// The puzzle solution.
    pub nonce: u64,
}

impl Claim {
    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        [&self.id[..], &self.nonce.to_be_bytes()].concat()
    }
}

impl TryFrom<&[u8]> for Claim {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let claim = Self {
            id: reader.array()?,
            nonce: reader.u64()?,
        };
        reader.finish()?;
        Ok(claim)
    }
}

/// The puzzle a relay sets: leading zero bits wanted, a salt that is a MAC of
/// the window, and the window it is good for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Challenge {
    /// The salt.
    pub salt: [u8; 16],
    /// The window the salt belongs to.
    pub window: u64,
    /// Leading zero bits wanted, at most [`RELAY_MAX_DIFFICULTY`].
    pub difficulty: u8,
}

impl Challenge {
    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        [
            &[self.difficulty][..],
            &self.salt,
            &self.window.to_be_bytes(),
        ]
        .concat()
    }
}

impl TryFrom<&[u8]> for Challenge {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let difficulty = reader.array::<1>()?[0];
        let challenge = Self {
            salt: reader.array()?,
            window: reader.u64()?,
            difficulty,
        };
        reader.finish()?;
        if difficulty > RELAY_MAX_DIFFICULTY {
            return Err(invalid());
        }
        Ok(challenge)
    }
}

/// What a relay grants a reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reserved {
    /// Seconds the slot lasts without a keepalive.
    pub ttl_s: u32,
    /// Splices that may run at once on the slot.
    pub max_splices: u8,
    /// Mebibytes one splice may carry.
    pub splice_mib: u16,
}

impl Reserved {
    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        [
            &self.ttl_s.to_be_bytes()[..],
            &[self.max_splices],
            &self.splice_mib.to_be_bytes(),
        ]
        .concat()
    }
}

impl TryFrom<&[u8]> for Reserved {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let granted = Self {
            ttl_s: reader.u32()?,
            max_splices: reader.array::<1>()?[0],
            splice_mib: reader.u16()?,
        };
        reader.finish()?;
        if granted.ttl_s == 0 || granted.max_splices == 0 || granted.splice_mib == 0 {
            return Err(invalid());
        }
        Ok(granted)
    }
}

/// Which connection of the relay to take.
#[must_use]
pub fn encode_incoming(conn_id: &[u8; 16]) -> Vec<u8> {
    conn_id.to_vec()
}

/// Read the connection a relay offers.
///
/// # Errors
///
/// A wrong length.
pub fn decode_incoming(bytes: &[u8]) -> Result<[u8; 16]> {
    let mut reader = Reader::new(bytes);
    let conn_id = reader.array()?;
    reader.finish()?;
    Ok(conn_id)
}

/// A relayed member's address in a peer record: where the relay is and the
/// slot to ask it for, written `ip:port/slot` with the slot as 32 lowercase
/// hex digits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayHint {
    /// The relay.
    pub relay: SocketAddr,
    /// The slot.
    pub slot: [u8; 16],
}

impl fmt::Display for RelayHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/", self.relay)?;
        self.slot
            .iter()
            .try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl FromStr for RelayHint {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let (relay, digits) = text.split_once('/').ok_or_else(invalid)?;
        if digits.len() != RELAY_SLOT_DIGITS
            || !digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid());
        }
        let mut slot = [0u8; 16];
        for (byte, pair) in slot.iter_mut().zip(digits.as_bytes().chunks_exact(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Ok(Self {
            relay: relay.parse().map_err(|_| invalid())?,
            slot,
        })
    }
}
