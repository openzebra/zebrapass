//! Sealing and opening LAN beacons, with no I/O.
//!
//! A beacon is one cascade frame under a key only devices of the account
//! derive. The frame header, which carries the sender and the time, is
//! authenticated data, so a beacon cannot be re-attributed, and one that is
//! too old or too far ahead is not opened.

use anyhow::{anyhow, Result};
use frame::{
    open, parse, seal, FrameMeta, ALG_CASCADE, CASCADE_OVERHEAD, HEADER_LEN, KIND_REVISION, TAG_LEN,
};
use secret::Secret;
use syncwire::BEACON_WIRE_MAX;

/// How far a beacon's time may be from this device's clock.
pub const BEACON_WINDOW_MS: u64 = 120_000;

/// Longest sealed beacon.
pub const MAX_BEACON: usize = HEADER_LEN + BEACON_WIRE_MAX + CASCADE_OVERHEAD + TAG_LEN;

/// Frame record id that marks a frame as a beacon.
const BEACON_RECORD: u32 = 0x5A42_4300;

fn rejected() -> anyhow::Error {
    anyhow!("beacon rejected")
}

/// Seal `payload` as a beacon from `device_id` at `now_ms`.
///
/// # Errors
///
/// A payload over the beacon bound; entropy failure.
pub fn seal_beacon(
    key: &Secret<[u8; 32]>,
    device_id: [u8; 16],
    now_ms: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > BEACON_WIRE_MAX {
        return Err(rejected());
    }
    let meta = FrameMeta {
        kind: KIND_REVISION,
        record_id: BEACON_RECORD,
        revision: 0,
        origin_device: device_id,
        timestamp_ms: now_ms,
        alg: ALG_CASCADE,
    };
    seal(key, &meta, payload)
}

/// Open a beacon: the sender and the payload.
///
/// # Errors
///
/// `beacon rejected` for anything that is not a fresh beacon sealed under
/// `key`, whatever the reason.
pub fn open_beacon(
    key: &Secret<[u8; 32]>,
    wire: &[u8],
    now_ms: u64,
) -> Result<([u8; 16], Secret<Vec<u8>>)> {
    if wire.len() > MAX_BEACON {
        return Err(rejected());
    }
    let header = parse(wire).map_err(|_| rejected())?;
    if header.alg != ALG_CASCADE
        || header.kind != KIND_REVISION
        || header.record_id != BEACON_RECORD
        || header.revision != 0
        || header.origin_device == [0; 16]
        || header.timestamp_ms.abs_diff(now_ms) > BEACON_WINDOW_MS
    {
        return Err(rejected());
    }
    let payload = open(key, wire).map_err(|_| rejected())?;
    Ok((header.origin_device, payload))
}
