//! Parallel non-blocking server-to-server mesh replication and independent
//! bidirectional anti-entropy loops.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, watch};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream as ServerTlsStream;

use crate::limits::{IO_TIMEOUT, MAX_SMALL_FRAME, MAX_WIRE_FRAME};
use crate::repo::RepoState;
use crate::repo_disk::RepoStore;
use crate::tls::{Endpoint, connect_tls};
use crate::wire::{
    RepoDigest, RepoFrontier, RepoKind, StorageId, StreamRole, SyncDelta, TAG_ACK, TAG_DELTA,
    TAG_DIFF, TAG_MESH_DELTA, TAG_MESH_DIGESTS, TAG_MESH_FRONTIER, TAG_MESH_NEED, Wanted,
    WatchEvent, read_wire, write_wire,
};
use crate::wire_codec::{
    decode_delta, decode_diff, decode_digests, decode_frontier, decode_repo_ids, encode_delta,
    encode_diff, encode_digests, encode_frontier, encode_repo_ids,
};

/// Peer servers configured for parallel mesh replication.
#[derive(Clone, Debug)]
pub struct MeshPeers {
    pub endpoints: Vec<Endpoint>,
    pub tls_cfg: Arc<rustls::ClientConfig>,
}

/// Immediately replicate `delta` to every peer server in parallel without
/// blocking the client or letting one slow/offline server stall the others.
pub fn fanout_accepted(peers: &MeshPeers, delta: &SyncDelta) {
    if peers.endpoints.is_empty() || delta.is_empty() {
        return;
    }
    let Ok(encoded) = encode_delta(delta) else {
        return;
    };
    let shared_bytes = Arc::new(encoded);
    for ep in &peers.endpoints {
        let ep = ep.clone();
        let cfg = Arc::clone(&peers.tls_cfg);
        let bytes = Arc::clone(&shared_bytes);
        tokio::spawn(async move {
            if let Ok((mut tls, _)) = connect_tls(&ep, &cfg).await
                && timeout(IO_TIMEOUT, tls.write_all(&[StreamRole::PeerMesh as u8]))
                    .await
                    .is_ok_and(|res| res.is_ok())
                && timeout(IO_TIMEOUT, write_wire(&mut tls, TAG_MESH_DELTA, &bytes))
                    .await
                    .is_ok_and(|res| res.is_ok())
            {
                let _ = timeout(IO_TIMEOUT, read_wire(&mut tls, MAX_SMALL_FRAME)).await;
            }
        });
    }
}

/// Spawn one independent bidirectional anti-entropy task per peer server so
/// servers converge in both directions concurrently without interfering.
pub fn spawn_mesh_loops(
    peers: MeshPeers,
    store: &Arc<RepoStore>,
    watch_tx: &broadcast::Sender<WatchEvent>,
    interval: Duration,
    shutdown: &watch::Receiver<bool>,
) {
    let period = interval.max(Duration::from_millis(100));
    for ep in peers.endpoints {
        let cfg = Arc::clone(&peers.tls_cfg);
        let st = Arc::clone(store);
        let wtx = watch_tx.clone();
        let mut halt = shutdown.clone();
        tokio::spawn(async move {
            while !*halt.borrow() {
                let _ = sync_with_peer(&ep, &cfg, &st, &wtx).await;
                if timeout(period, halt.changed()).await.is_ok() && *halt.borrow() {
                    break;
                }
            }
        });
    }
}

async fn sync_with_peer(
    ep: &Endpoint,
    tls_cfg: &Arc<rustls::ClientConfig>,
    store: &Arc<RepoStore>,
    watch_tx: &broadcast::Sender<WatchEvent>,
) -> anyhow::Result<()> {
    let (mut tls, _) = connect_tls(ep, tls_cfg).await?;
    timeout(IO_TIMEOUT, tls.write_all(&[StreamRole::PeerMesh as u8])).await??;

    let local_digests = store.all_digests().await;
    timeout(
        IO_TIMEOUT,
        write_wire(&mut tls, TAG_MESH_DIGESTS, &encode_digests(&local_digests)?),
    )
    .await??;

    let (tag, body) = timeout(IO_TIMEOUT, read_wire(&mut tls, MAX_WIRE_FRAME)).await??;
    if tag != TAG_MESH_NEED {
        anyhow::bail!("unexpected mesh digest reply");
    }
    let differing = decode_repo_ids(&body)?;
    for (kind, sid) in differing {
        reconcile_one_repo(&mut tls, store, watch_tx, kind, sid).await?;
    }
    Ok(())
}

async fn reconcile_one_repo<S>(
    tls: &mut S,
    store: &Arc<RepoStore>,
    watch_tx: &broadcast::Sender<WatchEvent>,
    kind: RepoKind,
    sid: StorageId,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let frontier = match store.get(kind, sid) {
        Some(handle) => handle.read().await.to_frontier(),
        None => empty_frontier(kind, sid),
    };
    timeout(
        IO_TIMEOUT,
        write_wire(tls, TAG_MESH_FRONTIER, &encode_frontier(&frontier)?),
    )
    .await??;

    let (tag, body) = timeout(IO_TIMEOUT, read_wire(tls, MAX_WIRE_FRAME)).await??;
    if tag != TAG_DIFF {
        anyhow::bail!("unexpected mesh diff reply");
    }
    let (pull, wanted) = decode_diff(&body)?;
    if !pull.is_empty() {
        let (_, changed) = store.apply_and_save(&pull).await?;
        if changed {
            let _ = watch_tx.send(WatchEvent {
                kind,
                storage_id: sid,
            });
        }
    }
    let push = if wanted.is_empty() {
        SyncDelta::empty(kind, sid)
    } else if let Some(handle) = store.get(kind, sid) {
        let repo = handle.read().await;
        build_wanted_delta(&repo, &wanted)
    } else {
        SyncDelta::empty(kind, sid)
    };
    timeout(
        IO_TIMEOUT,
        write_wire(tls, TAG_DELTA, &encode_delta(&push)?),
    )
    .await??;
    let _ = timeout(IO_TIMEOUT, read_wire(tls, MAX_SMALL_FRAME)).await??;
    Ok(())
}

/// Serve incoming `StreamRole::PeerMesh` connections from peer Zebra servers.
pub async fn serve_peer_mesh(
    store: Arc<RepoStore>,
    watch_tx: broadcast::Sender<WatchEvent>,
    mut tls: ServerTlsStream<TcpStream>,
) -> anyhow::Result<()> {
    loop {
        let Ok((tag, body)) = timeout(IO_TIMEOUT, read_wire(&mut tls, MAX_WIRE_FRAME)).await?
        else {
            return Ok(());
        };
        match tag {
            TAG_MESH_DELTA => {
                let delta = decode_delta(&body)?;
                let (_, changed) = store.apply_and_save(&delta).await?;
                if changed {
                    let _ = watch_tx.send(WatchEvent {
                        kind: delta.kind,
                        storage_id: delta.storage_id,
                    });
                }
                timeout(IO_TIMEOUT, write_wire(&mut tls, TAG_ACK, &[])).await??;
            }
            TAG_MESH_DIGESTS => {
                let remote = decode_digests(&body)?;
                let local = store.all_digests().await;
                let diff = differing_repos(&local, &remote);
                timeout(
                    IO_TIMEOUT,
                    write_wire(&mut tls, TAG_MESH_NEED, &encode_repo_ids(&diff)?),
                )
                .await??;
            }
            TAG_MESH_FRONTIER => {
                let peer_f = decode_frontier(&body)?;
                let (pull, wanted) = match store.get(peer_f.kind, peer_f.storage_id) {
                    Some(handle) => handle.read().await.diff_frontier(&peer_f),
                    None => (
                        SyncDelta::empty(peer_f.kind, peer_f.storage_id),
                        Wanted {
                            need_head: peer_f.head.is_some(),
                            need_members: peer_f.kind == RepoKind::Shared
                                && peer_f.member_count > 0,
                            need_revs: peer_f.rev_count > 0,
                            record_ids: peer_f.records.iter().map(|r| r.record_id).collect(),
                        },
                    ),
                };
                timeout(
                    IO_TIMEOUT,
                    write_wire(&mut tls, TAG_DIFF, &encode_diff(&pull, &wanted)?),
                )
                .await??;
                let (dtag, dbody) =
                    timeout(IO_TIMEOUT, read_wire(&mut tls, MAX_WIRE_FRAME)).await??;
                if dtag != TAG_DELTA {
                    anyhow::bail!("expected mesh delta");
                }
                let push = decode_delta(&dbody)?;
                if !push.is_empty() {
                    let (_, changed) = store.apply_and_save(&push).await?;
                    if changed {
                        let _ = watch_tx.send(WatchEvent {
                            kind: push.kind,
                            storage_id: push.storage_id,
                        });
                    }
                }
                timeout(IO_TIMEOUT, write_wire(&mut tls, TAG_ACK, &[])).await??;
            }
            _ => anyhow::bail!("unexpected peer mesh tag"),
        }
    }
}

fn differing_repos(local: &[RepoDigest], remote: &[RepoDigest]) -> Vec<(RepoKind, StorageId)> {
    let mut map: BTreeMap<(RepoKind, StorageId), [u8; 32]> = BTreeMap::new();
    for d in local {
        map.insert((d.kind, d.storage_id), d.digest);
    }
    let mut out = Vec::new();
    for r in remote {
        match map.remove(&(r.kind, r.storage_id)) {
            Some(ld) if ld == r.digest => {}
            _ => out.push((r.kind, r.storage_id)),
        }
    }
    for key in map.into_keys() {
        out.push(key);
    }
    out
}

const fn empty_frontier(kind: RepoKind, storage_id: StorageId) -> RepoFrontier {
    RepoFrontier {
        kind,
        storage_id,
        root_vk: None,
        shared_init: None,
        auth: None,
        certs: Vec::new(),
        rev_count: 0,
        member_count: 0,
        head: None,
        records: Vec::new(),
    }
}

fn build_wanted_delta(repo: &RepoState, wanted: &Wanted) -> SyncDelta {
    let mut out = SyncDelta::empty(repo.kind, repo.storage_id);
    out.root_vk.clone_from(&repo.root_vk);
    out.shared_init = repo.shared_init;
    for cert in repo.devices.values() {
        if let Ok(enc) = syncwire::encode_cert(cert) {
            out.certs.push(enc);
        }
    }
    if wanted.need_revs {
        for rev in &repo.revocations {
            if let Ok(enc) = syncwire::encode_revocation(rev) {
                out.revocations.push(enc);
            }
        }
    }
    if wanted.need_members {
        for entry in &repo.member_entries {
            if let Ok(enc) = entry.encode() {
                out.member_entries.push(enc);
            }
        }
    }
    if wanted.need_head {
        out.head.clone_from(&repo.head);
    }
    for rk in repo.rekeys.values() {
        out.rekeys.push(rk.clone());
    }
    for id in &wanted.record_ids {
        if let Some(rec) = repo.records.get(id) {
            out.records.push(rec.clone());
        }
    }
    out
}
