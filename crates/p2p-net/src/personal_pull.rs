//! Keeping the personal vault in step with the account's other devices: ask
//! one for its frontier and bring back the frames this device lacks.
//!
//! The frames are not applied here. The device that owns the open vault
//! applies them itself, so the vault is only ever written by one party.

use std::sync::atomic::Ordering;

use session::{reconcile, FrontierEntry};
use syncwire::{decode_frontier, decode_personal_frame};

use crate::client::{Conn, FetchError};
use crate::server::MAX_BUNDLE;
use crate::service::{Event, Service};
use crate::sync::{MAX_DIALED, MAX_FRONTIER_BODY, MAX_MOVED};
use crate::view::VaultView;

/// The frontier of the peer against `mine`, and the frames it holds that win.
async fn pull_from(
    view: &VaultView,
    address: &str,
    mine: &[FrontierEntry],
) -> Result<Vec<Vec<u8>>, FetchError> {
    let mut conn = Conn::connect(view, address).await?;
    let theirs = conn
        .get("/v1/frontier", MAX_FRONTIER_BODY, false)
        .await?
        .ok_or(FetchError::Failed)?;
    let theirs = decode_frontier(&theirs).map_err(|_| FetchError::Failed)?;
    let mut frames = Vec::new();
    for id in reconcile(mine, &theirs).pull.into_iter().take(MAX_MOVED) {
        let Some(body) = conn
            .get(&format!("/v1/revision/{id}"), MAX_BUNDLE, true)
            .await?
        else {
            continue;
        };
        frames.push(decode_personal_frame(&body).map_err(|_| FetchError::Failed)?);
    }
    Ok(frames)
}

impl Service {
    /// Check in with another device of this account at the first of
    /// `addresses` that answers, and report [`Event::PersonalPulled`] with the
    /// frames this device lacks, or [`Event::FetchFailed`] under the
    /// personal vault's handshake id when none could be reached or trusted.
    /// `mine` is the frontier of the open vault.
    pub fn pull_personal(&self, view: VaultView, addresses: Vec<String>, mine: Vec<FrontierEntry>) {
        let Some(runtime) = self.runtime.as_ref() else {
            return;
        };
        let (shared, sender) = (std::sync::Arc::clone(&self.shared), self.sender.clone());
        shared.fetching.fetch_add(1, Ordering::Relaxed);
        runtime.spawn(async move {
            let mut reason = FetchError::Unreachable;
            let mut outcome = None;
            for address in addresses.into_iter().take(MAX_DIALED) {
                match pull_from(&view, &address, &mine).await {
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
