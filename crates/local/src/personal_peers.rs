//! The addresses of an account's other devices, kept next to the personal
//! vault so a later session finds them without the address being typed again.
//!
//! Addresses are hints, not authority: a device that loads them dials each
//! one under the usual policy and the handshake decides who answers. The file
//! is one sealed frame under a key from the vault key; a missing, tampered or
//! malformed file only means the search starts again from what the user types.
//!
//! An entry is either learned (beacon, adoption) or manual: typed by the
//! owner in Settings. Manual entries never age out and are removed only by the
//! owner. The plaintext is `u16 BE count ‖ entries`; format 1 entries are
//! `u8 len ‖ address`, format 2 (high bit of the count) entries are
//! `u8 flags ‖ u8 len ‖ address`. Format 1 files still load, every entry
//! learned.

use std::path::Path;

use frame::{open, seal, FrameMeta, ALG_CASCADE, KIND_REVISION};
use secret::Secret;
use syncwire::reader::Reader;

use crate::limits::{PERSONAL_PEERS_MAX, PERSONAL_PEER_MAX_LEN};
use crate::parse_peer_address;

const FORMAT_2: u16 = 0x8000;
const FLAG_MANUAL: u8 = 1;
const REVISION_2: u64 = 2;
const FULL: &str = "Up to 8 addresses.";
const DUPLICATE: &str = "Already added.";

const _: () = assert!(PERSONAL_PEER_MAX_LEN <= u8::MAX as usize);

fn corrupted() -> anyhow::Error {
    anyhow::anyhow!("corrupted length")
}

/// A stored device address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalPeer {
    /// Canonical `ip:port`.
    pub address: Box<str>,
    /// Typed by the owner: never aged out, removed only by the owner.
    pub manual: bool,
}

/// Write `entries`, manual ones first, at most [`PERSONAL_PEERS_MAX`] of
/// them; learned ones give way to manual ones.
///
/// # Errors
///
/// An address over [`PERSONAL_PEER_MAX_LEN`] bytes, sealing or write failure.
pub fn save_personal_entries(
    path: &Path,
    key: &Secret<[u8; 32]>,
    entries: &[PersonalPeer],
) -> anyhow::Result<()> {
    let ordered: Vec<&PersonalPeer> = entries
        .iter()
        .filter(|entry| entry.manual)
        .chain(entries.iter().filter(|entry| !entry.manual))
        .take(PERSONAL_PEERS_MAX)
        .collect();
    let mut plain = Vec::with_capacity(2 + PERSONAL_PEERS_MAX * (2 + PERSONAL_PEER_MAX_LEN));
    plain.extend_from_slice(&(FORMAT_2 | u16::try_from(ordered.len())?).to_be_bytes());
    for entry in ordered {
        if entry.address.len() > PERSONAL_PEER_MAX_LEN {
            return Err(corrupted());
        }
        plain.push(if entry.manual { FLAG_MANUAL } else { 0 });
        plain.push(u8::try_from(entry.address.len())?);
        plain.extend_from_slice(entry.address.as_bytes());
    }
    let meta = FrameMeta {
        kind: KIND_REVISION,
        record_id: 0,
        revision: REVISION_2,
        origin_device: [1u8; 16],
        timestamp_ms: 0,
        alg: ALG_CASCADE,
    };
    crate::write_atomic(path, &seal(key, &meta, &plain)?)
}

/// Write learned `addresses`, newest first, keeping the manual entries
/// already stored.
///
/// # Errors
///
/// As [`save_personal_entries`].
pub fn save_personal_peers(
    path: &Path,
    key: &Secret<[u8; 32]>,
    addresses: &[Box<str>],
) -> anyhow::Result<()> {
    let mut entries = manual_entries(path, key);
    entries.extend(addresses.iter().map(|address| PersonalPeer {
        address: address.clone(),
        manual: false,
    }));
    save_personal_entries(path, key, &entries)
}

fn manual_entries(path: &Path, key: &Secret<[u8; 32]>) -> Vec<PersonalPeer> {
    load_personal_entries(path, key, true)
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| entry.manual)
        .collect()
}

/// Read the stored entries, manual first. Each is checked again as an address
/// to dial (`allow_loopback` as for [`parse_peer_address`]), and one that
/// fails drops out on its own.
///
/// # Errors
///
/// `peer store unreadable` when the file cannot be read; frame
/// authentication failure; a count or length over the bound.
pub fn load_personal_entries(
    path: &Path,
    key: &Secret<[u8; 32]>,
    allow_loopback: bool,
) -> anyhow::Result<Vec<PersonalPeer>> {
    let bytes = std::fs::read(path).map_err(|_| anyhow::anyhow!("peer store unreadable"))?;
    let plain = open(key, &bytes)?;
    let mut reader = Reader::new(plain.expose());
    let head = reader.u16()?;
    let flagged = head & FORMAT_2 != 0;
    let count = usize::from(head & !FORMAT_2);
    if count > PERSONAL_PEERS_MAX {
        return Err(corrupted());
    }
    let mut found = Vec::with_capacity(count);
    for _ in 0..count {
        let manual = if flagged {
            reader.array::<1>()?[0] & FLAG_MANUAL != 0
        } else {
            false
        };
        let text = std::str::from_utf8(reader.bytes_u8(PERSONAL_PEER_MAX_LEN)?)
            .map_err(|_| corrupted())?;
        found.extend(
            parse_peer_address(text, allow_loopback)
                .ok()
                .map(|address| PersonalPeer { address, manual }),
        );
    }
    reader.finish()?;
    found.sort_by_key(|entry| !entry.manual);
    Ok(found)
}

/// The stored addresses, manual first, then learned ones newest first.
///
/// # Errors
///
/// As [`load_personal_entries`].
pub fn load_personal_peers(
    path: &Path,
    key: &Secret<[u8; 32]>,
    allow_loopback: bool,
) -> anyhow::Result<Vec<Box<str>>> {
    Ok(load_personal_entries(path, key, allow_loopback)?
        .into_iter()
        .map(|entry| entry.address)
        .collect())
}

/// Put `address` first among the learned entries.
///
/// A copy further down and the oldest learned entries beyond the bound are
/// dropped; a manual entry for the same address stays manual. An unreadable
/// file is replaced.
///
/// # Errors
///
/// As [`save_personal_entries`].
pub fn remember_personal_peer(
    path: &Path,
    key: &Secret<[u8; 32]>,
    address: &str,
) -> anyhow::Result<()> {
    let stored = load_personal_entries(path, key, true).unwrap_or_default();
    if stored
        .iter()
        .any(|entry| entry.manual && &*entry.address == address)
    {
        return Ok(());
    }
    let mut all = vec![PersonalPeer {
        address: Box::from(address),
        manual: false,
    }];
    all.extend(
        stored
            .into_iter()
            .filter(|entry| &*entry.address != address),
    );
    save_personal_entries(path, key, &all)
}

/// Store `input`, typed by the owner, as a manual entry. A learned entry for
/// the same address becomes manual; learned entries give way when the list is
/// full of manual ones only.
///
/// # Errors
///
/// The reason `input` cannot be dialed, `Already added.`, `Up to 8
/// addresses.`, or a store failure.
pub fn add_manual_peer(
    path: &Path,
    key: &Secret<[u8; 32]>,
    input: &str,
    allow_loopback: bool,
) -> anyhow::Result<Box<str>> {
    let address = parse_peer_address(input, allow_loopback).map_err(|why| anyhow::anyhow!(why))?;
    let stored = load_personal_entries(path, key, true).unwrap_or_default();
    if stored
        .iter()
        .any(|entry| entry.manual && entry.address == address)
    {
        anyhow::bail!(DUPLICATE);
    }
    if stored.iter().filter(|entry| entry.manual).count() >= PERSONAL_PEERS_MAX {
        anyhow::bail!(FULL);
    }
    let mut all = vec![PersonalPeer {
        address: address.clone(),
        manual: true,
    }];
    all.extend(stored.into_iter().filter(|entry| entry.address != address));
    save_personal_entries(path, key, &all)?;
    Ok(address)
}

/// Remove the entry for `address`, if there is one.
///
/// # Errors
///
/// As [`save_personal_entries`].
pub fn remove_personal_peer(
    path: &Path,
    key: &Secret<[u8; 32]>,
    address: &str,
) -> anyhow::Result<()> {
    let kept: Vec<PersonalPeer> = load_personal_entries(path, key, true)?
        .into_iter()
        .filter(|entry| &*entry.address != address)
        .collect();
    save_personal_entries(path, key, &kept)
}
