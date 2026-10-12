//! What a device sends another device of the same account about its personal
//! vault: an announcement of the vault file it holds, and one sealed record
//! frame. The vault file itself travels in a snapshot with no attestations,
//! and the frontier is the one the shared vaults use.

use anyhow::{anyhow, Result};

use crate::limits::MAX_FRAME;
use crate::reader::Reader;

/// First four bytes of an encoded announcement.
pub const ANNOUNCE_MAGIC: [u8; 4] = *b"ZPPA";
/// Current announcement wire version.
pub const ANNOUNCE_WIRE_VERSION: u16 = 1;
/// Exact length of an encoded announcement.
pub const ANNOUNCE_WIRE_LEN: usize = 4 + 2 + 16 + 8 + 32;

/// First four bytes of an encoded personal frame.
pub const PERSONAL_FRAME_MAGIC: [u8; 4] = *b"ZPPF";
/// Current personal frame wire version.
pub const PERSONAL_FRAME_WIRE_VERSION: u16 = 1;

/// The vault file a device holds, as it names it: both values are public
/// fields of the file, so a receiver can check the file it got against them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Announce {
    /// The vault's number.
    pub vault_id: [u8; 16],
    /// Generation of the file.
    pub generation: u64,
    /// Commit tag of the file.
    pub commit_tag: [u8; 32],
}

fn invalid() -> anyhow::Error {
    anyhow!("invalid sync object")
}

/// Encode `announce`.
#[must_use]
pub fn encode_announce(announce: &Announce) -> Vec<u8> {
    let mut out = Vec::with_capacity(ANNOUNCE_WIRE_LEN);
    out.extend_from_slice(&ANNOUNCE_MAGIC);
    out.extend_from_slice(&ANNOUNCE_WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&announce.vault_id);
    out.extend_from_slice(&announce.generation.to_be_bytes());
    out.extend_from_slice(&announce.commit_tag);
    out
}

/// Decode an announcement.
///
/// # Errors
///
/// A wrong length, magic or version.
pub fn decode_announce(bytes: &[u8]) -> Result<Announce> {
    if bytes.len() != ANNOUNCE_WIRE_LEN {
        return Err(invalid());
    }
    let mut reader = Reader::new(bytes);
    if reader.array::<4>()? != ANNOUNCE_MAGIC || reader.u16()? != ANNOUNCE_WIRE_VERSION {
        return Err(invalid());
    }
    let announce = Announce {
        vault_id: reader.array()?,
        generation: reader.u64()?,
        commit_tag: reader.array()?,
    };
    reader.finish()?;
    Ok(announce)
}

/// Encode one sealed record frame for a device of the same account.
///
/// # Errors
///
/// A frame whose header does not parse or that is over the frame bound.
pub fn encode_personal_frame(frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() > MAX_FRAME {
        return Err(invalid());
    }
    ::frame::parse(frame).map_err(|_| invalid())?;
    let mut out = Vec::with_capacity(4 + 2 + 4 + frame.len());
    out.extend_from_slice(&PERSONAL_FRAME_MAGIC);
    out.extend_from_slice(&PERSONAL_FRAME_WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&u32::try_from(frame.len())?.to_be_bytes());
    out.extend_from_slice(frame);
    Ok(out)
}

/// Decode a personal frame. The length is checked against the frame bound
/// before anything is allocated, and the frame header must parse; whether
/// the frame opens is for the receiving session to decide.
///
/// # Errors
///
/// A wrong magic or version, a length over the bound, a header that does
/// not parse, or trailing bytes.
pub fn decode_personal_frame(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Reader::new(bytes);
    if reader.array::<4>()? != PERSONAL_FRAME_MAGIC || reader.u16()? != PERSONAL_FRAME_WIRE_VERSION
    {
        return Err(invalid());
    }
    let frame = reader.bytes_u32(MAX_FRAME)?;
    reader.finish()?;
    ::frame::parse(frame).map_err(|_| invalid())?;
    Ok(frame.to_vec())
}
