//! Auxiliary bounded binary codecs for `zsync` watch, relay, and paginated mesh RPCs.

use anyhow::anyhow;
use pq::{SYNC_SIG_LEN, SYNC_VK_LEN};
use syncwire::reader::Reader;

use crate::limits::{MAX_MESH_PAGE, MAX_SMALL_FRAME, MAX_WATCH_REPOS};
use crate::wire::{RelayMsg, RepoDigest, RepoKind, StorageId, WatchEvent, WatchSub};
use crate::wire_codec::{
    bad_wire, push_bytes, push_opt, read_blob_vec, read_bytes, read_opt, read_u8, read_u16_count,
    write_blob_vec,
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
    push_opt(&mut out, w.personal_anchor.as_deref(), push_bytes)?;
    push_opt(&mut out, w.root_vk.as_deref(), |o, vk| {
        o.extend_from_slice(vk);
        Ok(())
    })?;
    write_blob_vec(&mut out, &w.shared_proofs)?;
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
    let personal_anchor = read_opt(&mut r, |rd| {
        read_bytes(rd, MAX_SMALL_FRAME).map(<[u8]>::to_vec)
    })?;
    let root_vk = read_opt(&mut r, |rd| rd.array::<SYNC_VK_LEN>().map(Box::new))?;
    let shared_proofs = read_blob_vec(&mut r, MAX_WATCH_REPOS, MAX_SMALL_FRAME)?;
    let signature = Box::new(r.array::<SYNC_SIG_LEN>()?);
    r.finish()?;
    Ok(WatchSub {
        timestamp_s,
        device_id,
        nonce,
        repos,
        cert_wire,
        personal_anchor,
        root_vk,
        shared_proofs,
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
        RelayMsg::Reserve {
            slot,
            timestamp_s,
            nonce,
            slot_vk,
            signature,
        } => {
            out.push(1);
            out.extend_from_slice(slot);
            out.extend_from_slice(&timestamp_s.to_be_bytes());
            out.extend_from_slice(nonce);
            out.extend_from_slice(slot_vk.as_slice());
            out.extend_from_slice(signature.as_slice());
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
        RelayMsg::Reserved { observed, ttl_s } => {
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
            timestamp_s: r.u64()?,
            nonce: r.array::<16>()?,
            slot_vk: Box::new(r.array::<SYNC_VK_LEN>()?),
            signature: Box::new(r.array::<SYNC_SIG_LEN>()?),
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
            RelayMsg::Reserved { observed, ttl_s }
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

/// Encode optional cursor `(RepoKind, StorageId)` for paginated mesh digest sync.
#[must_use]
pub fn encode_digest_cursor(cursor: Option<(RepoKind, StorageId)>) -> Vec<u8> {
    let mut out = Vec::with_capacity(66);
    match cursor {
        Some((kind, sid)) => {
            out.push(1);
            out.push(kind as u8);
            out.extend_from_slice(&sid);
        }
        None => out.push(0),
    }
    out
}

/// Decode optional cursor `(RepoKind, StorageId)`.
///
/// # Errors
///
/// Malformed cursor payload.
pub fn decode_digest_cursor(bytes: &[u8]) -> anyhow::Result<Option<(RepoKind, StorageId)>> {
    let mut r = Reader::new(bytes);
    let cursor = read_opt(&mut r, |rd| {
        Ok((RepoKind::try_from(read_u8(rd)?)?, rd.array::<64>()?))
    })?;
    r.finish()?;
    Ok(cursor)
}

/// Encode one bounded page of mesh repository digests plus optional next cursor.
///
/// # Errors
///
/// Page exceeds [`MAX_MESH_PAGE`].
pub fn encode_digest_page(
    digests: &[RepoDigest],
    next: Option<(RepoKind, StorageId)>,
) -> anyhow::Result<Vec<u8>> {
    if digests.len() > MAX_MESH_PAGE {
        return Err(bad_wire());
    }
    let count = u16::try_from(digests.len()).map_err(|_| bad_wire())?;
    let mut out = Vec::with_capacity(2 + digests.len() * 97 + 66);
    out.extend_from_slice(&count.to_be_bytes());
    for d in digests {
        out.push(d.kind as u8);
        out.extend_from_slice(&d.storage_id);
        out.extend_from_slice(&d.digest);
    }
    push_opt(&mut out, next.as_ref(), |o, (k, sid)| {
        o.push(*k as u8);
        o.extend_from_slice(sid);
        Ok(())
    })?;
    Ok(out)
}

/// Cursor key `(kind, storage_id)` for paginated mesh digest scanning.
pub type DigestCursor = (RepoKind, StorageId);

/// Decode one bounded page of mesh repository digests plus optional next cursor.
///
/// # Errors
///
/// Over-limit or malformed payload.
pub fn decode_digest_page(bytes: &[u8]) -> anyhow::Result<(Vec<RepoDigest>, Option<DigestCursor>)> {
    let mut r = Reader::new(bytes);
    let count = read_u16_count(&mut r, MAX_MESH_PAGE)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(RepoDigest {
            kind: RepoKind::try_from(read_u8(&mut r)?)?,
            storage_id: r.array::<64>()?,
            digest: r.array::<32>()?,
        });
    }
    let next = read_opt(&mut r, |rd| {
        Ok((RepoKind::try_from(read_u8(rd)?)?, rd.array::<64>()?))
    })?;
    r.finish()?;
    Ok((out, next))
}
