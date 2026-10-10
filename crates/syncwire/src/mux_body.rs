//! Payloads of the mux messages that are not an existing sync object. Each
//! decodes with an exact length and rejects trailing bytes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Result;

use crate::limits::{CHUNK_LEN, MAX_LOG_LEN, MAX_SNAPSHOT_LEN};
use crate::mux::invalid;
use crate::reader::Reader;

/// Ask for the revision of a record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Want {
    /// The revision wanted.
    pub revision: u64,
    /// The record.
    pub record_id: u32,
}

impl Want {
    /// Exact encoded length.
    pub const LEN: usize = 4 + 8;

    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        [
            &self.record_id.to_be_bytes()[..],
            &self.revision.to_be_bytes(),
        ]
        .concat()
    }
}

impl TryFrom<&[u8]> for Want {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let record_id = reader.u32()?;
        let revision = reader.u64()?;
        reader.finish()?;
        Ok(Self {
            revision,
            record_id,
        })
    }
}

/// How big a served blob is and which one it is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extent {
    /// Names the blob; a chunk of another blob is stale.
    pub id: [u8; 32],
    /// Total length in bytes.
    pub total: u64,
}

impl Extent {
    /// Exact encoded length.
    pub const LEN: usize = 32 + 8;

    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        [&self.id[..], &self.total.to_be_bytes()].concat()
    }
}

impl TryFrom<&[u8]> for Extent {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let extent = Self {
            id: reader.array()?,
            total: reader.u64()?,
        };
        reader.finish()?;
        if extent.total > MAX_SNAPSHOT_LEN {
            return Err(invalid());
        }
        Ok(extent)
    }
}

/// Ask for the chunk at `offset` of the blob `id`; an all-zero `id` means
/// whichever blob is current.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkRequest {
    /// Names the blob.
    pub id: [u8; 32],
    /// Where the chunk starts.
    pub offset: u64,
}

impl ChunkRequest {
    /// Exact encoded length.
    pub const LEN: usize = 32 + 8;

    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        [&self.id[..], &self.offset.to_be_bytes()].concat()
    }
}

impl TryFrom<&[u8]> for ChunkRequest {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let request = Self {
            id: reader.array()?,
            offset: reader.u64()?,
        };
        reader.finish()?;
        Ok(request)
    }
}

/// One piece of a blob.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Chunk {
    /// The piece, at most [`CHUNK_LEN`] bytes.
    pub data: Box<[u8]>,
    /// Names the blob.
    pub id: [u8; 32],
    /// Where the piece starts.
    pub offset: u64,
    /// Total length of the blob.
    pub total: u64,
}

impl Chunk {
    /// Length of the fields before the data.
    pub const HEADER_LEN: usize = 32 + 8 + 8 + 4;

    /// The wire form.
    ///
    /// # Errors
    ///
    /// The piece is longer than [`CHUNK_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.data.len() > CHUNK_LEN {
            return Err(invalid());
        }
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.data.len());
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.total.to_be_bytes());
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(&u32::try_from(self.data.len())?.to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    /// Decode a chunk of a blob of at most `max_total` bytes. The piece must
    /// lie inside the blob and be non-empty unless the blob is.
    ///
    /// # Errors
    ///
    /// A wrong length, a piece over the bound or outside the blob.
    pub fn decode(bytes: &[u8], max_total: u64) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let id = reader.array()?;
        let total = reader.u64()?;
        let offset = reader.u64()?;
        let data = reader.bytes_u32(CHUNK_LEN)?;
        reader.finish()?;
        let end = offset
            .checked_add(u64::try_from(data.len())?)
            .ok_or_else(invalid)?;
        if total > max_total || end > total || (data.is_empty() && offset != total) {
            return Err(invalid());
        }
        Ok(Self {
            data: data.into(),
            id,
            offset,
            total,
        })
    }

    /// Decode a chunk of the member log.
    ///
    /// # Errors
    ///
    /// As [`Chunk::decode`], with the log bound.
    pub fn decode_log(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes, MAX_LOG_LEN)
    }

    /// Decode a chunk of the vault file.
    ///
    /// # Errors
    ///
    /// As [`Chunk::decode`], with the snapshot bound.
    pub fn decode_snapshot(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes, MAX_SNAPSHOT_LEN)
    }
}

/// Keepalive token, echoed back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ping(pub u64);

impl Ping {
    /// Exact encoded length.
    pub const LEN: usize = 8;

    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

impl TryFrom<&[u8]> for Ping {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let token = reader.u64()?;
        reader.finish()?;
        Ok(Self(token))
    }
}

/// The address the responder sees the peer at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WhoAmI(pub SocketAddr);

impl WhoAmI {
    /// Longest encoded form: family, an IPv6 address and a port.
    pub const MAX_LEN: usize = 1 + 16 + 2;

    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::MAX_LEN);
        match self.0.ip() {
            IpAddr::V4(ip) => {
                out.push(4);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(6);
                out.extend_from_slice(&ip.octets());
            }
        }
        out.extend_from_slice(&self.0.port().to_be_bytes());
        out
    }
}

impl TryFrom<&[u8]> for WhoAmI {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let ip = match reader.array::<1>()? {
            [4] => IpAddr::V4(Ipv4Addr::from(reader.array::<4>()?)),
            [6] => IpAddr::V6(Ipv6Addr::from(reader.array::<16>()?)),
            _ => return Err(invalid()),
        };
        let port = reader.u16()?;
        reader.finish()?;
        Ok(Self(SocketAddr::new(ip, port)))
    }
}
