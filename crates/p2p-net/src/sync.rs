//! Keeping an open vault in step with its members: merge the member log,
//! take over a new seed when one is offered, then trade the revisions each
//! side lacks, record by record.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use http::StatusCode;
use memberlog::{ENTRY_WIRE_LEN, MAX_ENTRIES};
use session::{reconcile, FrontierEntry};
use syncwire::decode_frontier;

use crate::client::{Conn, FetchError};
use crate::server::{MAX_BUNDLE, MAX_PEERS_BODY};
use crate::service::{Event, Service};
use crate::view::{Provider, VaultView};

/// Revisions moved in each direction in one check-in; the rest wait for the
/// next one.
pub const MAX_MOVED: usize = 512;

/// Addresses one check-in dials at most, however many it learns on the way.
pub const MAX_DIALED: usize = 8;

const MAX_LOG: usize = ENTRY_WIRE_LEN * MAX_ENTRIES;
pub const MAX_FRONTIER_BODY: usize = syncwire::MAX_FRONTIER * 32 + 8;
const MAX_SNAPSHOT: usize = 512 << 20;

/// What one check-in did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Moved {
    /// Revisions kept from peers.
    pub pulled: usize,
    /// Revisions peers kept from this device.
    pub pushed: usize,
    /// Revisions a side turned away because of a role or a signature.
    pub refused: usize,
}

impl Moved {
    const fn add(&mut self, other: Self) {
        self.pulled += other.pulled;
        self.pushed += other.pushed;
        self.refused += other.refused;
    }
}

enum Step {
    Synced(Moved),
    Snapshot(Event),
}

fn frontier_of(bytes: &[u8]) -> Result<Vec<FrontierEntry>, FetchError> {
    decode_frontier(bytes).map_err(|_| FetchError::Failed)
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, FetchError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| FetchError::Failed)
}

/// Swap address lists with a member. A failure here never fails the sync:
/// the addresses are a convenience on top of it.
async fn exchange_peers<P: Provider>(provider: &Arc<P>, conn: &mut Conn, vault_id: [u8; 16]) {
    if let Ok(Some(list)) = conn.get("/v1/peers", MAX_PEERS_BODY, true).await {
        let provider = Arc::clone(provider);
        let _ = blocking(move || provider.accept_peers(&vault_id, &list)).await;
    }
    let provider = Arc::clone(provider);
    if let Ok(Some(own)) = blocking(move || provider.peers(&vault_id)).await {
        let _ = conn.post("/v1/peers", own).await;
    }
}

async fn talk<P: Provider>(
    provider: &Arc<P>,
    view: &VaultView,
    hint: &str,
) -> Result<Step, FetchError> {
    let vault_id = view.vault_id;
    let mut conn = Conn::connect(view, hint).await?;
    let log = conn
        .get("/v1/log", MAX_LOG, false)
        .await?
        .ok_or(FetchError::Failed)?;
    let merged = {
        let (provider, log) = (Arc::clone(provider), log.clone());
        blocking(move || provider.merge_log(&vault_id, &log)).await?
    };
    if !merged {
        return Err(FetchError::Failed);
    }
    exchange_peers(provider, &mut conn, vault_id).await;
    let rekey = conn.get("/v1/rekey", 128, true).await?;
    let needs = {
        let (provider, rekey) = (Arc::clone(provider), rekey.clone());
        blocking(move || provider.needs_snapshot(&vault_id, rekey.as_deref())).await?
    };
    if needs {
        let snapshot = conn
            .get("/v1/snapshot", MAX_SNAPSHOT, false)
            .await?
            .ok_or(FetchError::Failed)?;
        return Ok(Step::Snapshot(Event::Fetched {
            vault_id,
            log,
            snapshot,
            rekey: rekey.map(zeroize::Zeroizing::new),
        }));
    }
    let theirs = frontier_of(
        &conn
            .get("/v1/frontier", MAX_FRONTIER_BODY, false)
            .await?
            .ok_or(FetchError::Failed)?,
    )?;
    let mine = {
        let provider = Arc::clone(provider);
        blocking(move || provider.frontier(&vault_id))
            .await?
            .ok_or(FetchError::Failed)?
    };
    let plan = reconcile(&frontier_of(&mine)?, &theirs);
    let mut moved = Moved::default();
    let account = conn.peer.client_id;
    for id in plan.pull.into_iter().take(MAX_MOVED) {
        let Some(bundle) = conn
            .get(&format!("/v1/revision/{id}"), MAX_BUNDLE, true)
            .await?
        else {
            continue;
        };
        let provider = Arc::clone(provider);
        match blocking(move || provider.accept_revision(&vault_id, &account, &bundle)).await? {
            local::Verdict::Applied => moved.pulled += 1,
            local::Verdict::Stale => {}
            local::Verdict::Refused | local::Verdict::Invalid => moved.refused += 1,
        }
    }
    for id in plan.push.into_iter().take(MAX_MOVED) {
        let provider = Arc::clone(provider);
        let Some(bundle) = blocking(move || provider.revision(&vault_id, id)).await? else {
            continue;
        };
        match conn.post("/v1/revision", bundle).await? {
            StatusCode::OK => moved.pushed += 1,
            StatusCode::CONFLICT => {}
            _ => moved.refused += 1,
        }
    }
    Ok(Step::Synced(moved))
}

impl Service {
    /// Sync one open vault with every member address in `hints` that answers,
    /// and report one event: [`Event::Synced`], [`Event::Fetched`] when a new
    /// seed or file is due, or [`Event::FetchFailed`] when nobody could be
    /// reached or trusted.
    pub fn check_in<P: Provider>(&self, provider: Arc<P>, vault_id: [u8; 16], hints: Vec<String>) {
        let Some(runtime) = self.runtime.as_ref() else {
            return;
        };
        let (shared, sender) = (Arc::clone(&self.shared), self.sender.clone());
        shared.fetching.fetch_add(1, Ordering::Relaxed);
        runtime.spawn(async move {
            let mut reason = FetchError::Unreachable;
            let mut total = Moved::default();
            let mut reached = false;
            let mut outcome = None;
            let mut queue = hints;
            let remembered = {
                let provider = Arc::clone(&provider);
                blocking(move || provider.peer_hints(&vault_id))
                    .await
                    .unwrap_or_default()
            };
            for found in remembered {
                if !queue.contains(&found) {
                    queue.push(found);
                }
            }
            let mut tried = 0;
            while let Some(hint) = queue.get(tried).cloned() {
                if tried >= MAX_DIALED {
                    break;
                }
                tried += 1;
                let views = {
                    let provider = Arc::clone(&provider);
                    blocking(move || provider.views()).await.unwrap_or_default()
                };
                let Some(view) = views.iter().find(|view| view.vault_id == vault_id) else {
                    reason = FetchError::Failed;
                    break;
                };
                match talk(&provider, view, &hint).await {
                    Ok(Step::Synced(moved)) => {
                        reached = true;
                        total.add(moved);
                    }
                    Ok(Step::Snapshot(event)) => {
                        outcome = Some(event);
                        break;
                    }
                    Err(error) => reason = error,
                }
                let learned = {
                    let provider = Arc::clone(&provider);
                    blocking(move || provider.peer_hints(&vault_id))
                        .await
                        .unwrap_or_default()
                };
                for found in learned {
                    if !queue.contains(&found) {
                        queue.push(found);
                    }
                }
            }
            shared.fetching.fetch_sub(1, Ordering::Relaxed);
            let _ = sender.send(outcome.unwrap_or(if reached || tried == 0 {
                Event::Synced {
                    vault_id,
                    pulled: total.pulled,
                    pushed: total.pushed,
                    refused: total.refused,
                }
            } else {
                Event::FetchFailed { vault_id, reason }
            }));
        });
    }
}
