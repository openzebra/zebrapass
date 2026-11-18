//! Strict bounded binary codecs for `zsync` wire messages.

use anyhow::anyhow;
use pq::{SYNC_SIG_LEN, SYNC_VK_LEN};
use syncwire::reader::Reader;

use crate::limits::{
    MAX_CERTS_PER_REPO, MAX_ENVELOPE_BYTES, MAX_MEMBERS_PER_REPO, MAX_RECORDS_PER_MSG,
    MAX_REKEYS_PER_REPO, MAX_REVS_PER_REPO, MAX_SMALL_FRAME,
};
use crate::wire::{
    FrontierAuth, HeadVer, RecordCommit, RecordVer, RepoFrontier, RepoKind, SignedHead,
    SignedRekey, SyncDelta, Wanted,
};
pub use crate::wire_aux::{
    decode_digests, decode_relay, decode_repo_ids, decode_watch_event, decode_watch_sub,
    encode_digests, encode_relay, encode_repo_ids, encode_watch_event, encode_watch_sub,
};

pub fn bad_wire() -> anyhow::Error {
    anyhow!("malformed zsync wire payload")
}

pub fn push_bytes(out: &mut Vec<u8>, data: &[u8]) -> anyhow::Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| bad_wire())?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

pub fn read_bytes<'a>(r: &mut Reader<'a>, max_len: usize) -> anyhow::Result<&'a [u8]> {
    let len = usize::try_from(r.u32()?).map_err(|_| bad_wire())?;
    if len > max_len {
        return Err(bad_wire());
    }
    r.take(len)
}

pub fn read_u16_count(r: &mut Reader<'_>, max_count: usize) -> anyhow::Result<usize> {
    let count = usize::from(r.u16()?);
    if count > max_count {
        return Err(bad_wire());
    }
    Ok(count)
}

pub fn read_u8(r: &mut Reader<'_>) -> anyhow::Result<u8> {
    r.array::<1>().map(|[b]| b)
}

pub fn push_opt<T>(
    out: &mut Vec<u8>,
    val: Option<&T>,
    f: impl FnOnce(&mut Vec<u8>, &T) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    match val {
        Some(v) => {
            out.push(1);
            f(out, v)?;
        }
        None => out.push(0),
    }
    Ok(())
}

pub fn read_opt<'a, T>(
    r: &mut Reader<'a>,
    f: impl FnOnce(&mut Reader<'a>) -> anyhow::Result<T>,
) -> anyhow::Result<Option<T>> {
    match read_u8(r)? {
        0 => Ok(None),
        1 => f(r).map(Some),
        _ => Err(bad_wire()),
    }
}

fn write_head_ver(out: &mut Vec<u8>, v: &HeadVer) {
    out.extend_from_slice(&v.generation.to_be_bytes());
    out.extend_from_slice(&v.commit_tag);
    out.extend_from_slice(&v.origin_device);
}

fn read_head_ver(r: &mut Reader<'_>) -> anyhow::Result<HeadVer> {
    Ok(HeadVer {
        generation: r.u64()?,
        commit_tag: r.array::<32>()?,
        origin_device: r.array::<16>()?,
    })
}

fn write_rec_ver(out: &mut Vec<u8>, v: &RecordVer) {
    out.extend_from_slice(&v.record_id.to_be_bytes());
    out.extend_from_slice(&v.revision.to_be_bytes());
    out.extend_from_slice(&v.origin_device);
    out.extend_from_slice(&v.frame_hash);
}

fn read_rec_ver(r: &mut Reader<'_>) -> anyhow::Result<RecordVer> {
    let record_id = r.u32()?;
    let revision = r.u64()?;
    let origin_device = r.array::<16>()?;
    let frame_hash = r.array::<32>()?;
    Ok(RecordVer {
        revision,
        origin_device,
        frame_hash,
        record_id,
    })
}

/// Encode [`RepoFrontier`].
///
/// # Errors
///
/// Exceeded count/length limits.
pub fn encode_frontier(f: &RepoFrontier) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    out.push(f.kind as u8);
    out.extend_from_slice(&f.storage_id);
    push_opt(&mut out, f.root_vk.as_deref(), |o, vk| {
        o.extend_from_slice(vk);
        Ok(())
    })?;
    push_opt(&mut out, f.shared_init.as_ref(), |o, (vid, anc)| {
        o.extend_from_slice(vid);
        o.extend_from_slice(anc);
        Ok(())
    })?;
    push_opt(&mut out, f.auth.as_ref(), |o, a| {
        o.extend_from_slice(&a.timestamp_s.to_be_bytes());
        o.extend_from_slice(&a.nonce);
        push_bytes(o, &a.cert_wire)?;
        o.extend_from_slice(&*a.signature);
        Ok(())
    })?;
    let c_len = u16::try_from(f.certs.len()).map_err(|_| bad_wire())?;
    out.extend_from_slice(&c_len.to_be_bytes());
    for id in &f.certs {
        out.extend_from_slice(id);
    }
    out.extend_from_slice(&f.rev_count.to_be_bytes());
    out.extend_from_slice(&f.member_count.to_be_bytes());
    push_opt(&mut out, f.head.as_ref(), |o, h| {
        write_head_ver(o, h);
        Ok(())
    })?;
    let r_len = u16::try_from(f.records.len()).map_err(|_| bad_wire())?;
    out.extend_from_slice(&r_len.to_be_bytes());
    for rec in &f.records {
        write_rec_ver(&mut out, rec);
    }
    Ok(out)
}

/// Decode [`RepoFrontier`].
///
/// # Errors
///
/// Malformed or over-limit payload.
pub fn decode_frontier(bytes: &[u8]) -> anyhow::Result<RepoFrontier> {
    let mut r = Reader::new(bytes);
    let kind = RepoKind::try_from(read_u8(&mut r)?)?;
    let storage_id = r.array::<64>()?;
    let root_vk = read_opt(&mut r, |rd| rd.array::<SYNC_VK_LEN>().map(Box::new))?;
    let shared_init = read_opt(&mut r, |rd| Ok((rd.array::<16>()?, rd.array::<32>()?)))?;
    let auth = read_opt(&mut r, |rd| {
        Ok(FrontierAuth {
            timestamp_s: rd.u64()?,
            nonce: rd.array::<16>()?,
            cert_wire: read_bytes(rd, MAX_SMALL_FRAME)?.to_vec(),
            signature: Box::new(rd.array::<SYNC_SIG_LEN>()?),
        })
    })?;
    let c_count = read_u16_count(&mut r, MAX_CERTS_PER_REPO)?;
    let mut certs = Vec::with_capacity(c_count);
    for _ in 0..c_count {
        certs.push(r.array::<16>()?);
    }
    let rev_count = r.u32()?;
    let member_count = r.u32()?;
    let head = read_opt(&mut r, read_head_ver)?;
    let r_count = read_u16_count(&mut r, MAX_RECORDS_PER_MSG)?;
    let mut records = Vec::with_capacity(r_count);
    for _ in 0..r_count {
        records.push(read_rec_ver(&mut r)?);
    }
    r.finish()?;
    Ok(RepoFrontier {
        kind,
        storage_id,
        root_vk,
        shared_init,
        auth,
        certs,
        rev_count,
        member_count,
        head,
        records,
    })
}

/// Encode `(SyncDelta, Wanted)` reply to a frontier.
///
/// # Errors
///
/// Exceeded count/length limits.
pub fn encode_diff(pull: &SyncDelta, wanted: &Wanted) -> anyhow::Result<Vec<u8>> {
    let mut out = encode_delta(pull)?;
    out.push(u8::from(wanted.need_head));
    out.push(u8::from(wanted.need_members));
    out.push(u8::from(wanted.need_revs));
    let len = u16::try_from(wanted.record_ids.len()).map_err(|_| bad_wire())?;
    out.extend_from_slice(&len.to_be_bytes());
    for id in &wanted.record_ids {
        out.extend_from_slice(&id.to_be_bytes());
    }
    Ok(out)
}

/// Decode `(SyncDelta, Wanted)` diff reply.
///
/// # Errors
///
/// Malformed or over-limit payload.
pub fn decode_diff(bytes: &[u8]) -> anyhow::Result<(SyncDelta, Wanted)> {
    let mut r = Reader::new(bytes);
    let delta = read_delta(&mut r)?;
    let need_head = match read_u8(&mut r)? {
        0 => false,
        1 => true,
        _ => return Err(bad_wire()),
    };
    let need_members = match read_u8(&mut r)? {
        0 => false,
        1 => true,
        _ => return Err(bad_wire()),
    };
    let need_revs = match read_u8(&mut r)? {
        0 => false,
        1 => true,
        _ => return Err(bad_wire()),
    };
    let count = read_u16_count(&mut r, MAX_RECORDS_PER_MSG)?;
    let mut record_ids = Vec::with_capacity(count);
    for _ in 0..count {
        record_ids.push(r.u32()?);
    }
    r.finish()?;
    Ok((
        delta,
        Wanted {
            need_head,
            need_members,
            need_revs,
            record_ids,
        },
    ))
}

/// Encode [`SyncDelta`].
///
/// # Errors
///
/// Exceeded count/length limits.
pub fn encode_delta(d: &SyncDelta) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    out.push(d.kind as u8);
    out.extend_from_slice(&d.storage_id);
    push_opt(&mut out, d.root_vk.as_deref(), |o, vk| {
        o.extend_from_slice(vk);
        Ok(())
    })?;
    push_opt(&mut out, d.shared_init.as_ref(), |o, (vid, anc)| {
        o.extend_from_slice(vid);
        o.extend_from_slice(anc);
        Ok(())
    })?;
    write_blob_vec(&mut out, &d.certs)?;
    write_blob_vec(&mut out, &d.revocations)?;
    write_blob_vec(&mut out, &d.member_entries)?;
    push_opt(&mut out, d.head.as_ref(), |o, h| {
        write_head_ver(o, &h.ver);
        push_bytes(o, &h.head_meta)?;
        push_bytes(o, &h.snapshot_env)?;
        o.extend_from_slice(&*h.signature);
        Ok(())
    })?;
    let rk_len = u16::try_from(d.rekeys.len()).map_err(|_| bad_wire())?;
    out.extend_from_slice(&rk_len.to_be_bytes());
    for rk in &d.rekeys {
        out.extend_from_slice(&rk.generation.to_be_bytes());
        out.extend_from_slice(&rk.origin_device);
        out.extend_from_slice(&rk.target_device);
        push_bytes(&mut out, &rk.envelope)?;
        out.extend_from_slice(&*rk.signature);
    }
    let rec_len = u16::try_from(d.records.len()).map_err(|_| bad_wire())?;
    out.extend_from_slice(&rec_len.to_be_bytes());
    for rec in &d.records {
        write_rec_ver(&mut out, &rec.ver);
        out.extend_from_slice(&rec.key_generation.to_be_bytes());
        out.extend_from_slice(&rec.signer_device);
        push_bytes(&mut out, &rec.envelope)?;
        out.extend_from_slice(&*rec.signature);
    }
    Ok(out)
}

/// Decode [`SyncDelta`].
///
/// # Errors
///
/// Malformed or over-limit payload.
pub fn decode_delta(bytes: &[u8]) -> anyhow::Result<SyncDelta> {
    let mut r = Reader::new(bytes);
    let delta = read_delta(&mut r)?;
    r.finish()?;
    Ok(delta)
}

fn read_delta(r: &mut Reader<'_>) -> anyhow::Result<SyncDelta> {
    let kind = RepoKind::try_from(read_u8(r)?)?;
    let storage_id = r.array::<64>()?;
    let root_vk = read_opt(r, |rd| rd.array::<SYNC_VK_LEN>().map(Box::new))?;
    let shared_init = read_opt(r, |rd| Ok((rd.array::<16>()?, rd.array::<32>()?)))?;
    let certs = read_blob_vec(r, MAX_CERTS_PER_REPO, MAX_SMALL_FRAME)?;
    let revocations = read_blob_vec(r, MAX_REVS_PER_REPO, MAX_SMALL_FRAME)?;
    let member_entries = read_blob_vec(r, MAX_MEMBERS_PER_REPO, MAX_SMALL_FRAME)?;
    let head = read_opt(r, |rd| {
        Ok(SignedHead {
            ver: read_head_ver(rd)?,
            head_meta: read_bytes(rd, MAX_SMALL_FRAME)?.to_vec(),
            snapshot_env: read_bytes(rd, MAX_ENVELOPE_BYTES)?.to_vec(),
            signature: Box::new(rd.array::<SYNC_SIG_LEN>()?),
        })
    })?;
    let rk_count = read_u16_count(r, MAX_REKEYS_PER_REPO)?;
    let mut rekeys = Vec::with_capacity(rk_count);
    for _ in 0..rk_count {
        rekeys.push(SignedRekey {
            generation: r.u64()?,
            origin_device: r.array::<16>()?,
            target_device: r.array::<16>()?,
            envelope: read_bytes(r, MAX_SMALL_FRAME)?.to_vec(),
            signature: Box::new(r.array::<SYNC_SIG_LEN>()?),
        });
    }
    let rec_count = read_u16_count(r, MAX_RECORDS_PER_MSG)?;
    let mut records = Vec::with_capacity(rec_count);
    for _ in 0..rec_count {
        records.push(RecordCommit {
            ver: read_rec_ver(r)?,
            key_generation: r.u64()?,
            signer_device: r.array::<16>()?,
            envelope: read_bytes(r, MAX_ENVELOPE_BYTES)?.to_vec(),
            signature: Box::new(r.array::<SYNC_SIG_LEN>()?),
        });
    }
    Ok(SyncDelta {
        kind,
        storage_id,
        root_vk,
        shared_init,
        certs,
        revocations,
        member_entries,
        head,
        rekeys,
        records,
    })
}

fn write_blob_vec(out: &mut Vec<u8>, items: &[Vec<u8>]) -> anyhow::Result<()> {
    let count = u16::try_from(items.len()).map_err(|_| bad_wire())?;
    out.extend_from_slice(&count.to_be_bytes());
    for item in items {
        push_bytes(out, item)?;
    }
    Ok(())
}

fn read_blob_vec(
    r: &mut Reader<'_>,
    max_items: usize,
    max_item_len: usize,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let count = read_u16_count(r, max_items)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(read_bytes(r, max_item_len)?.to_vec());
    }
    Ok(out)
}
