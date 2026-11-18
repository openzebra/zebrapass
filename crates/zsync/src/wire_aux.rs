//! Auxiliary bounded binary codecs for `zsync` watch, relay, and mesh RPCs.

use anyhow::anyhow;
use pq::{SYNC_SIG_LEN, SYNC_VK_LEN};
use syncwire::reader::Reader;

use crate::limits::{MAX_MESH_REPOS, MAX_SMALL_FRAME, MAX_WATCH_REPOS};
use crate::wire::{RelayMsg, RepoDigest, RepoKind, StorageId, WatchEvent, WatchSub};
use crate::wire_codec::{
    bad_wire, push_bytes, push_opt, read_bytes, read_opt, read_u8, read_u16_count,
};

/// Encode [`WatchSub`].
///
/// # Errors
///
/// Exceeded count/length limits.
pub fn encode_watch_sub(w: &WatchSub) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&w.device_id);
    out.extend_from_slice(&w.timestamp_s.to_be_bytes());
    out.extend_from_slice(&w.nonce);
    let count = u16::try_from(w.repos.len()).map_err(|_| bad_wire())?;
    out.extend_from_slice(&count.to_be_bytes());
    for (kind, sid) in &w.repos {
        out.push(*kind as u8);
        out.extend_from_slice(sid);
    }
    push_bytes(&mut out, &w.cert_wire)?;
    push_opt(&mut out, w.root_vk.as_deref(), |o, vk| {
        o.extend_from_slice(vk);
        Ok(())
    })?;
    out.extend_from_slice(&*w.signature);
    Ok(out)
}

/// Decode [`WatchSub`].
///
/// # Errors
///
/// Malformed or over-limit payload.
pub fn decode_watch_sub(bytes: &[u8]) -> anyhow::Result<WatchSub> {
    let mut r = Reader::new(bytes);
    let device_id = r.array::<16>()?;
    let timestamp_s = r.u64()?;
    let nonce = r.array::<16>()?;
    let count = read_u16_count(&mut r, MAX_WATCH_REPOS)?;
    let mut repos = Vec::with_capacity(count);
    for _ in 0..count {
        repos.push((RepoKind::try_from(read_u8(&mut r)?)?, r.array::<64>()?));
    }
    let cert_wire = read_bytes(&mut r, MAX_SMALL_FRAME)?.to_vec();
    let root_vk = read_opt(&mut r, |rd| rd.array::<SYNC_VK_LEN>().map(Box::new))?;
    let signature = Box::new(r.array::<SYNC_SIG_LEN>()?);
    r.finish()?;
    Ok(WatchSub {
        device_id,
        timestamp_s,
        nonce,
        repos,
        cert_wire,
        root_vk,
        signature,
    })
}

/// Encode [`WatchEvent`].
#[must_use]
pub fn encode_watch_event(ev: WatchEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    out.push(ev.kind as u8);
    out.extend_from_slice(&ev.storage_id);
    out
}

/// Decode [`WatchEvent`].
///
/// # Errors
///
/// Malformed payload.
pub fn decode_watch_event(bytes: &[u8]) -> anyhow::Result<WatchEvent> {
    let mut r = Reader::new(bytes);
    let kind = RepoKind::try_from(read_u8(&mut r)?)?;
    let storage_id = r.array::<64>()?;
    r.finish()?;
    Ok(WatchEvent { kind, storage_id })
}

/// Encode [`RelayMsg`].
///
/// # Errors
///
/// Observed address longer than `MAX_SMALL_FRAME`.
pub fn encode_relay(msg: &RelayMsg) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32);
    match msg {
        RelayMsg::Reserve { slot } => {
            out.push(1);
            out.extend_from_slice(slot);
        }
        RelayMsg::Connect { slot } => {
            out.push(2);
            out.extend_from_slice(slot);
        }
        RelayMsg::Accept { conn_id } => {
            out.push(3);
            out.extend_from_slice(conn_id);
        }
        RelayMsg::Ping(tok) => {
            out.push(4);
            out.extend_from_slice(&tok.to_be_bytes());
        }
        RelayMsg::Reserved { ttl_s, observed } => {
            out.push(5);
            out.extend_from_slice(&ttl_s.to_be_bytes());
            push_bytes(&mut out, observed.as_bytes())?;
        }
        RelayMsg::Incoming { conn_id } => {
            out.push(6);
            out.extend_from_slice(conn_id);
        }
        RelayMsg::SpliceOk => out.push(7),
        RelayMsg::Offline => out.push(8),
        RelayMsg::Pong(tok) => {
            out.push(9);
            out.extend_from_slice(&tok.to_be_bytes());
        }
    }
    Ok(out)
}

/// Decode [`RelayMsg`].
///
/// # Errors
///
/// Unknown message kind or trailing bytes.
pub fn decode_relay(bytes: &[u8]) -> anyhow::Result<RelayMsg> {
    let mut r = Reader::new(bytes);
    let msg = match read_u8(&mut r)? {
        1 => RelayMsg::Reserve {
            slot: r.array::<16>()?,
        },
        2 => RelayMsg::Connect {
            slot: r.array::<16>()?,
        },
        3 => RelayMsg::Accept {
            conn_id: r.array::<16>()?,
        },
        4 => RelayMsg::Ping(r.u64()?),
        5 => {
            let ttl_s = r.u16()?;
            let obs_bytes = read_bytes(&mut r, 256)?;
            let observed = std::str::from_utf8(obs_bytes)
                .map_err(|_| anyhow!("invalid utf8 in observed address"))?
                .to_owned();
            RelayMsg::Reserved { ttl_s, observed }
        }
        6 => RelayMsg::Incoming {
            conn_id: r.array::<16>()?,
        },
        7 => RelayMsg::SpliceOk,
        8 => RelayMsg::Offline,
        9 => RelayMsg::Pong(r.u64()?),
        _ => return Err(bad_wire()),
    };
    r.finish()?;
    Ok(msg)
}

/// Encode mesh repository digest list.
///
/// # Errors
///
/// Too many repos for `u32` count.
pub fn encode_digests(digests: &[RepoDigest]) -> anyhow::Result<Vec<u8>> {
    let count = u32::try_from(digests.len()).map_err(|_| bad_wire())?;
    let mut out = Vec::with_capacity(4 + digests.len() * 97);
    out.extend_from_slice(&count.to_be_bytes());
    for d in digests {
        out.push(d.kind as u8);
        out.extend_from_slice(&d.storage_id);
        out.extend_from_slice(&d.digest);
    }
    Ok(out)
}

/// Decode mesh repository digest list.
///
/// # Errors
///
/// Over-limit or malformed payload.
pub fn decode_digests(bytes: &[u8]) -> anyhow::Result<Vec<RepoDigest>> {
    let mut r = Reader::new(bytes);
    let count = usize::try_from(r.u32()?).map_err(|_| bad_wire())?;
    if count > MAX_MESH_REPOS {
        return Err(bad_wire());
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(RepoDigest {
            kind: RepoKind::try_from(read_u8(&mut r)?)?,
            storage_id: r.array::<64>()?,
            digest: r.array::<32>()?,
        });
    }
    r.finish()?;
    Ok(out)
}

/// Encode list of `(RepoKind, StorageId)` needing mesh reconciliation.
///
/// # Errors
///
/// Too many items.
pub fn encode_repo_ids(ids: &[(RepoKind, StorageId)]) -> anyhow::Result<Vec<u8>> {
    let count = u32::try_from(ids.len()).map_err(|_| bad_wire())?;
    let mut out = Vec::with_capacity(4 + ids.len() * 65);
    out.extend_from_slice(&count.to_be_bytes());
    for (kind, sid) in ids {
        out.push(*kind as u8);
        out.extend_from_slice(sid);
    }
    Ok(out)
}

/// Decode list of `(RepoKind, StorageId)`.
///
/// # Errors
///
/// Over-limit or malformed payload.
pub fn decode_repo_ids(bytes: &[u8]) -> anyhow::Result<Vec<(RepoKind, StorageId)>> {
    let mut r = Reader::new(bytes);
    let count = usize::try_from(r.u32()?).map_err(|_| bad_wire())?;
    if count > MAX_MESH_REPOS {
        return Err(bad_wire());
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push((RepoKind::try_from(read_u8(&mut r)?)?, r.array::<64>()?));
    }
    r.finish()?;
    Ok(out)
}
