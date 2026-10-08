//! The addresses of an account's other devices, kept next to the personal
//! vault so a later session finds them without the address being typed again.
//!
//! Addresses are hints, not authority: a device that loads them dials each
//! one under the usual policy and the handshake decides who answers. The file
//! is one sealed frame under a key from the vault key; a missing, tampered or
//! malformed file only means the search starts again from what the user types.

use std::path::Path;

use frame::{open, seal, FrameMeta, ALG_CASCADE, KIND_REVISION};
use secret::Secret;
use syncwire::reader::Reader;

use crate::limits::{PERSONAL_PEERS_MAX, PERSONAL_PEER_MAX_LEN};
use crate::parse_peer_address;

const _: () = assert!(PERSONAL_PEER_MAX_LEN <= u8::MAX as usize);

fn corrupted() -> anyhow::Error {
    anyhow::anyhow!("corrupted length")
}

/// Write `addresses`, at most [`PERSONAL_PEERS_MAX`] of them, newest first.
///
/// # Errors
///
/// An address over [`PERSONAL_PEER_MAX_LEN`] bytes, sealing or write failure.
pub fn save_personal_peers(
    path: &Path,
    key: &Secret<[u8; 32]>,
    addresses: &[Box<str>],
) -> anyhow::Result<()> {
    let kept = addresses.iter().take(PERSONAL_PEERS_MAX);
    let mut plain = Vec::with_capacity(2 + PERSONAL_PEERS_MAX * (1 + PERSONAL_PEER_MAX_LEN));
    plain.extend_from_slice(&u16::try_from(kept.len())?.to_be_bytes());
    for address in kept {
        if address.len() > PERSONAL_PEER_MAX_LEN {
            return Err(corrupted());
        }
        plain.push(u8::try_from(address.len())?);
        plain.extend_from_slice(address.as_bytes());
    }
    let meta = FrameMeta {
        kind: KIND_REVISION,
        record_id: 0,
        revision: 1,
        origin_device: [1u8; 16],
        timestamp_ms: 0,
        alg: ALG_CASCADE,
    };
    crate::write_atomic(path, &seal(key, &meta, &plain)?)
}

/// Read the stored addresses. Each is checked again as an address to dial
/// (`allow_loopback` as for [`parse_peer_address`]), and one that fails drops
/// out on its own.
///
/// # Errors
///
/// `peer store unreadable` when the file cannot be read; frame
/// authentication failure; a count or length over the bound.
pub fn load_personal_peers(
    path: &Path,
    key: &Secret<[u8; 32]>,
    allow_loopback: bool,
) -> anyhow::Result<Vec<Box<str>>> {
    let bytes = std::fs::read(path).map_err(|_| anyhow::anyhow!("peer store unreadable"))?;
    let plain = open(key, &bytes)?;
    let mut reader = Reader::new(plain.expose());
    let count = usize::from(reader.u16()?);
    if count > PERSONAL_PEERS_MAX {
        return Err(corrupted());
    }
    let mut found = Vec::with_capacity(count);
    for _ in 0..count {
        let text = std::str::from_utf8(reader.bytes_u8(PERSONAL_PEER_MAX_LEN)?)
            .map_err(|_| corrupted())?;
        found.extend(parse_peer_address(text, allow_loopback).ok());
    }
    reader.finish()?;
    Ok(found)
}

/// Put `address` first among the stored ones, dropping a copy further down and
/// the oldest beyond the bound. An unreadable file is replaced.
///
/// # Errors
///
/// As [`save_personal_peers`].
pub fn remember_personal_peer(
    path: &Path,
    key: &Secret<[u8; 32]>,
    address: &str,
    allow_loopback: bool,
) -> anyhow::Result<()> {
    let first: Box<str> = Box::from(address);
    let mut all = vec![first.clone()];
    all.extend(
        load_personal_peers(path, key, allow_loopback)
            .unwrap_or_default()
            .into_iter()
            .filter(|known| *known != first),
    );
    all.truncate(PERSONAL_PEERS_MAX);
    save_personal_peers(path, key, &all)
}
