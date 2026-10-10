//! The message layer inside a sealed channel.
//!
//! A message is a nine-byte header (type, request number, payload length)
//! then the payload. The payload length is checked against the limit of its
//! type and direction before anything is allocated, and a type that is not
//! allowed in a direction is an error, so the caller closes the connection.

use anyhow::{anyhow, Result};

use crate::limits::{
    CHUNK_LEN, MAX_BUNDLE, MAX_FRONTIER_PAYLOAD, MAX_PEERS_PAYLOAD, MUX_HEADER_LEN, REKEY_LEN,
};
use crate::mux_body::{Chunk, ChunkRequest, Extent, Ping, Want, WhoAmI};
use crate::ANNOUNCE_WIRE_LEN;

/// Every message type. There is no negotiation: the table is fixed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MsgType {
    /// The vault file a device holds.
    Announce = 1,
    /// Size and identity of the member log.
    LogHead = 2,
    /// A piece of the member log.
    LogChunk = 3,
    /// The winning revision of every record.
    Frontier = 4,
    /// Ask for one revision.
    Want = 5,
    /// One revision: the answer to a want, or a push.
    Bundle = 6,
    /// Ask for a piece of the vault file.
    SnapReq = 7,
    /// A piece of the vault file.
    SnapChunk = 8,
    /// The seed of a new generation.
    Rekey = 9,
    /// Signed peer addresses, traded both ways.
    Peers = 10,
    /// The address the responder sees the peer at.
    WhoAmI = 11,
    /// Keepalive.
    Ping = 12,
    /// Keepalive answer.
    Pong = 13,
    /// The node is serving as much as it will; not a failure of the peer.
    Busy = 14,
    /// The request is turned away, whatever the reason.
    Refused = 15,
    /// The request names something that has moved on.
    Stale = 16,
}

/// Who sends a message: the dialing side asks, the answering side replies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Initiator to responder.
    Request,
    /// Responder to initiator.
    Response,
}

impl TryFrom<u8> for MsgType {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> Result<Self> {
        Ok(match byte {
            1 => Self::Announce,
            2 => Self::LogHead,
            3 => Self::LogChunk,
            4 => Self::Frontier,
            5 => Self::Want,
            6 => Self::Bundle,
            7 => Self::SnapReq,
            8 => Self::SnapChunk,
            9 => Self::Rekey,
            10 => Self::Peers,
            11 => Self::WhoAmI,
            12 => Self::Ping,
            13 => Self::Pong,
            14 => Self::Busy,
            15 => Self::Refused,
            16 => Self::Stale,
            _ => return Err(invalid()),
        })
    }
}

impl MsgType {
    /// Largest payload this type may carry in `direction`, or `None` when
    /// the type is not allowed in that direction.
    #[must_use]
    pub const fn max_payload(self, direction: Direction) -> Option<usize> {
        match direction {
            Direction::Request => match self {
                Self::Announce | Self::LogHead | Self::Frontier | Self::Rekey | Self::WhoAmI => {
                    Some(0)
                }
                Self::LogChunk | Self::SnapReq => Some(ChunkRequest::LEN),
                Self::Want => Some(Want::LEN),
                Self::Bundle => Some(MAX_BUNDLE),
                Self::Peers => Some(MAX_PEERS_PAYLOAD),
                Self::Ping => Some(Ping::LEN),
                Self::SnapChunk | Self::Pong | Self::Busy | Self::Refused | Self::Stale => None,
            },
            Direction::Response => match self {
                Self::Announce => Some(ANNOUNCE_WIRE_LEN),
                Self::LogHead => Some(Extent::LEN),
                Self::LogChunk | Self::SnapChunk => Some(Chunk::HEADER_LEN + CHUNK_LEN),
                Self::Frontier => Some(MAX_FRONTIER_PAYLOAD),
                Self::Bundle => Some(MAX_BUNDLE),
                Self::Rekey => Some(REKEY_LEN),
                Self::Peers => Some(MAX_PEERS_PAYLOAD),
                Self::WhoAmI => Some(WhoAmI::MAX_LEN),
                Self::Pong => Some(Ping::LEN),
                Self::Busy | Self::Refused | Self::Stale => Some(0),
                Self::Want | Self::SnapReq | Self::Ping => None,
            },
        }
    }
}

/// A decoded message header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    /// The payload length, already within the limit of the type.
    pub len: u32,
    /// Correlates a reply with its request.
    pub req_id: u32,
    /// What the payload is.
    pub ty: MsgType,
}

impl Header {
    /// A header for a payload of `len` bytes.
    ///
    /// # Errors
    ///
    /// The type is not allowed in `direction`, or `len` is over its limit.
    pub fn new(ty: MsgType, req_id: u32, len: usize, direction: Direction) -> Result<Self> {
        if ty.max_payload(direction).is_none_or(|max| len > max) {
            return Err(invalid());
        }
        Ok(Self {
            len: u32::try_from(len).map_err(|_| invalid())?,
            req_id,
            ty,
        })
    }

    /// The nine header bytes.
    #[must_use]
    pub const fn encode(&self) -> [u8; MUX_HEADER_LEN] {
        let [id0, id1, id2, id3] = self.req_id.to_be_bytes();
        let [len0, len1, len2, len3] = self.len.to_be_bytes();
        [self.ty as u8, id0, id1, id2, id3, len0, len1, len2, len3]
    }

    /// Parse a header received from the peer. Nothing is allocated yet; the
    /// caller reads exactly `len` bytes next.
    ///
    /// # Errors
    ///
    /// An unknown type, a type not allowed in `direction`, or a length over
    /// the limit of the type.
    pub fn decode(bytes: &[u8; MUX_HEADER_LEN], direction: Direction) -> Result<Self> {
        let mut reader = crate::reader::Reader::new(bytes);
        let ty = MsgType::try_from(reader.array::<1>()?[0])?;
        let req_id = reader.u32()?;
        let len = reader.u32()?;
        reader.finish()?;
        let max = ty.max_payload(direction).ok_or_else(invalid)?;
        if usize::try_from(len).map_or(true, |len| len > max) {
            return Err(invalid());
        }
        Ok(Self { len, req_id, ty })
    }
}

pub(crate) fn invalid() -> anyhow::Error {
    anyhow!("invalid sync object")
}
