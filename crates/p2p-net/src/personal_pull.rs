//! Keeping the personal vault in step with the account's other devices: ask
//! one for its frontier and bring back the frames this device lacks.
//!
//! The frames are not applied here. The device that owns the open vault
//! applies them itself, so the vault is only ever written by one party.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use session::{reconcile, FrontierEntry};
use syncwire::limits::PIPELINE_DEPTH;
use syncwire::{decode_frontier, decode_personal_frame};

use crate::client::{Conn, FetchError};
use crate::client_calls::Push;
use crate::personal::PersonalServe;
use crate::service::{Event, Service};
use crate::sync::{MAX_DIALED, MAX_MOVED};
use crate::view::VaultView;

/// Send the peer the frames of `ids` that win here.
async fn push_to(
    conn: &mut Conn,
    serve: &Arc<PersonalServe>,
    ids: &[u32],
) -> Result<(), FetchError> {
    for batch in ids.chunks(PIPELINE_DEPTH) {
        let mut frames = Vec::with_capacity(batch.len());
        for id in batch.iter().copied() {
            let serve = Arc::clone(serve);
            let frame = tokio::task::spawn_blocking(move || serve.revision(id))
                .await
                .map_err(|_| FetchError::Failed)?;
            frames.extend(frame);
        }
        for verdict in conn.push(frames).await? {
            if verdict == Push::Refused {
                return Err(FetchError::Failed);
            }
        }
    }
    Ok(())
}

/// The frontier of the peer against `mine`, the frames it holds that win,
/// and, when `serve` is given, the frames this device holds that win.
async fn pull_from(
    view: &VaultView,
    address: &str,
    mine: &[FrontierEntry],
    serve: Option<&Arc<PersonalServe>>,
) -> Result<Vec<Vec<u8>>, FetchError> {
    let mut conn = Conn::connect(view, address).await?;
    let theirs = decode_frontier(&conn.frontier().await?).map_err(|_| FetchError::Failed)?;
    let plan = reconcile(mine, &theirs);
    let wanted: Vec<(u32, u64)> = plan
        .pull
        .into_iter()
        .take(MAX_MOVED)
        .map(|id| {
            let revision = theirs
                .iter()
                .find(|entry| entry.record_id == id)
                .map_or(0, |entry| entry.revision);
            (id, revision)
        })
        .collect();
    let mut frames = Vec::with_capacity(wanted.len());
    for batch in wanted.chunks(PIPELINE_DEPTH) {
        for body in conn.revisions(batch).await?.into_iter().flatten() {
            frames.push(decode_personal_frame(&body).map_err(|_| FetchError::Failed)?);
        }
    }
    if let Some(serve) = serve {
        let ids: Vec<u32> = plan.push.into_iter().take(MAX_MOVED).collect();
        push_to(&mut conn, serve, &ids).await?;
    }
    Ok(frames)
}

impl Service {
    /// Check in with another device of this account at the first of
    /// `addresses` that answers, and report [`Event::PersonalPulled`] with the
    /// frames this device lacks, or [`Event::FetchFailed`] under the
    /// personal vault's handshake id when none could be reached or trusted.
    /// `mine` is the frontier of the open vault; with `serve`, the frames
    /// this device holds that the peer lacks are pushed to it as well.
    pub fn pull_personal(
        &self,
        view: VaultView,
        addresses: Vec<String>,
        mine: Vec<FrontierEntry>,
        serve: Option<Arc<PersonalServe>>,
    ) {
        let Some(runtime) = self.runtime.as_ref() else {
            return;
        };
        let (shared, sender) = (Arc::clone(&self.shared), self.sender.clone());
        shared.fetching.fetch_add(1, Ordering::Relaxed);
        runtime.spawn(async move {
            let mut reason = FetchError::Unreachable;
            let mut outcome = None;
            let mut done: Vec<String> = Vec::with_capacity(MAX_DIALED);
            while done.len() < MAX_DIALED {
                let Some(address) = view.dialing.next_hint(&addresses, &done).cloned() else {
                    break;
                };
                done.push(address.clone());
                match pull_from(&view, &address, &mine, serve.as_ref()).await {
                    Ok(frames) => {
                        outcome = Some(Event::PersonalPulled { address, frames });
                        break;
                    }
                    Err(error) => reason = error,
                }
            }
            shared.fetching.fetch_sub(1, Ordering::Relaxed);
            let _ = sender.send(outcome.unwrap_or(Event::FetchFailed {
                vault_id: view.vault_id,
                reason,
            }));
        });
    }
}
