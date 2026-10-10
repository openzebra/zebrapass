//! What a device announces on its local network: the port it accepts
//! connections on, the ids of the vaults it serves, and up to two relay
//! slots it can be reached through. Nothing else; the announcement is sealed
//! by its sender under an account key and grants nothing to its readers.

use anyhow::{anyhow, Result};
use session::MAX_HINT_LEN;

use crate::reader::Reader;
use crate::relay::RelayHint;

/// First four bytes of an encoded beacon.
pub const BEACON_MAGIC: [u8; 4] = *b"ZPBC";
/// Current beacon wire version.
pub const BEACON_WIRE_VERSION: u16 = 2;
/// Most vault ids one beacon names.
pub const MAX_BEACON_VAULTS: usize = 16;
/// Most relay slots one beacon names.
pub const MAX_BEACON_RELAYS: usize = 2;
/// Longest encoded beacon.
pub const BEACON_WIRE_MAX: usize =
    4 + 2 + 2 + 1 + MAX_BEACON_VAULTS * 16 + 1 + MAX_BEACON_RELAYS * (1 + MAX_HINT_LEN);

/// An announcement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Beacon {
    /// Ids of the vaults the sender serves.
    pub vaults: Vec<[u8; 16]>,
    /// Relay slots the sender holds, as they are written in a peer record.
    pub relays: Vec<RelayHint>,
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
/// No port, no vault, or more vaults or relays than the bounds.
pub fn encode_beacon(beacon: &Beacon) -> Result<Vec<u8>> {
    if beacon.port == 0
        || beacon.vaults.is_empty()
        || beacon.vaults.len() > MAX_BEACON_VAULTS
        || beacon.relays.len() > MAX_BEACON_RELAYS
    {
        return Err(invalid());
    }
    let mut out = Vec::with_capacity(BEACON_WIRE_MAX);
    out.extend_from_slice(&BEACON_MAGIC);
    out.extend_from_slice(&BEACON_WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&beacon.port.to_be_bytes());
    out.push(u8::try_from(beacon.vaults.len())?);
    for vault in &beacon.vaults {
        out.extend_from_slice(vault);
    }
    out.push(u8::try_from(beacon.relays.len())?);
    for relay in &beacon.relays {
        let text = relay.to_string();
        out.push(u8::try_from(text.len()).map_err(|_| invalid())?);
        out.extend_from_slice(text.as_bytes());
    }
    Ok(out)
}

/// Decode a beacon, strictly. A relay hint must be written exactly as the
/// encoder writes it.
///
/// # Errors
///
/// A wrong magic or version, no port, a count of zero vaults or over a
/// bound, a relay hint that is not canonical, truncation or trailing bytes.
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
    let relay_count = usize::from(reader.array::<1>()?[0]);
    if relay_count > MAX_BEACON_RELAYS {
        return Err(invalid());
    }
    let relays = (0..relay_count)
        .map(|_| {
            let text =
                std::str::from_utf8(reader.bytes_u8(MAX_HINT_LEN)?).map_err(|_| invalid())?;
            let relay: RelayHint = text.parse()?;
            if relay.to_string() == text {
                Ok(relay)
            } else {
                Err(invalid())
            }
        })
        .collect::<Result<Vec<_>>>()?;
    reader.finish()?;
    Ok(Beacon {
        vaults,
        relays,
        port,
    })
}
