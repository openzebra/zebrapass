//! What a device announces on its local network: the port it accepts
//! connections on and the ids of the vaults it serves. Nothing else; the
//! announcement is sealed by its sender and grants nothing to its readers.

use anyhow::{anyhow, Result};

use crate::reader::Reader;

/// First four bytes of an encoded beacon.
pub const BEACON_MAGIC: [u8; 4] = *b"ZPBC";
/// Current beacon wire version.
pub const BEACON_WIRE_VERSION: u16 = 1;
/// Most vault ids one beacon names.
pub const MAX_BEACON_VAULTS: usize = 16;
/// Longest encoded beacon.
pub const BEACON_WIRE_MAX: usize = 4 + 2 + 2 + 1 + MAX_BEACON_VAULTS * 16;

/// An announcement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Beacon {
    /// Ids of the vaults the sender serves.
    pub vaults: Vec<[u8; 16]>,
    /// The port the sender accepts connections on.
    pub port: u16,
}

fn invalid() -> anyhow::Error {
    anyhow!("invalid sync object")
}

/// Encode `beacon`.
///
/// # Errors
///
/// No port, no vault, or more than [`MAX_BEACON_VAULTS`].
pub fn encode_beacon(beacon: &Beacon) -> Result<Vec<u8>> {
    if beacon.port == 0 || beacon.vaults.is_empty() || beacon.vaults.len() > MAX_BEACON_VAULTS {
        return Err(invalid());
    }
    let mut out = Vec::with_capacity(4 + 2 + 2 + 1 + beacon.vaults.len() * 16);
    out.extend_from_slice(&BEACON_MAGIC);
    out.extend_from_slice(&BEACON_WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&beacon.port.to_be_bytes());
    out.push(u8::try_from(beacon.vaults.len())?);
    for vault in &beacon.vaults {
        out.extend_from_slice(vault);
    }
    Ok(out)
}

/// Decode a beacon, strictly.
///
/// # Errors
///
/// A wrong magic or version, no port, a count of zero or over the bound,
/// truncation or trailing bytes.
pub fn decode_beacon(bytes: &[u8]) -> Result<Beacon> {
    let mut reader = Reader::new(bytes);
    if reader.array::<4>()? != BEACON_MAGIC || reader.u16()? != BEACON_WIRE_VERSION {
        return Err(invalid());
    }
    let port = reader.u16()?;
    let count = usize::from(reader.array::<1>()?[0]);
    if port == 0 || count == 0 || count > MAX_BEACON_VAULTS {
        return Err(invalid());
    }
    let vaults = (0..count)
        .map(|_| reader.array())
        .collect::<Result<Vec<[u8; 16]>>>()?;
    reader.finish()?;
    Ok(Beacon { vaults, port })
}
