//! Answering one request for one authenticated peer.
//!
//! Only authenticated devices of an account the vault trusts reach this
//! point, so what a request may see needs no further check here; what it may
//! change is decided by the provider. Every refusal is the same empty
//! message, whatever the reason.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use local::Verdict;
use p2p_core::Outcome;
use syncwire::limits::{CHUNK_LEN, MAX_LOG_LEN};
use syncwire::{Chunk, ChunkRequest, Extent, MsgType, Ping, SnapHead, Want, WhoAmI};
use tokio::sync::OwnedSemaphorePermit;
use zeroize::Zeroizing;

use crate::blob::Blob;
use crate::limits::Tickets;
use crate::view::Provider;

/// What goes back for one request.
pub struct Answer {
    /// The reply, which may hold a seed.
    pub body: Zeroizing<Vec<u8>>,
    /// The type of the reply.
    pub ty: MsgType,
    /// How it counts against the peer.
    pub outcome: Outcome,
}

impl Answer {
    fn ok(ty: MsgType, body: Vec<u8>) -> Self {
        Self::of(ty, body, Outcome::Served)
    }

    fn status(ty: MsgType, outcome: Outcome) -> Self {
        Self::of(ty, Vec::new(), outcome)
    }

    fn of(ty: MsgType, body: Vec<u8>, outcome: Outcome) -> Self {
        Self {
            body: Zeroizing::new(body),
            ty,
            outcome,
        }
    }

    /// Turned away.
    #[must_use]
    pub fn refused() -> Self {
        Self::status(MsgType::Refused, Outcome::Refused)
    }

    fn stale() -> Self {
        Self::status(MsgType::Stale, Outcome::Stale)
    }

    fn busy() -> Self {
        Self::status(MsgType::Busy, Outcome::Busy)
    }
}

struct Transfer {
    blob: Blob,
    permit: Mutex<Option<OwnedSemaphorePermit>>,
    served: AtomicU64,
    started: Instant,
}

impl Transfer {
    /// Count what went out; the place among the node's snapshot tickets is
    /// given back once every byte has.
    fn sent(&self, len: usize) {
        let total = self
            .served
            .fetch_add(u64::try_from(len).unwrap_or(u64::MAX), Ordering::Relaxed)
            .saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        if total >= self.blob.total() {
            if let Ok(mut permit) = self.permit.lock() {
                permit.take();
            }
        }
    }
}

/// The answering side of one connection.
pub struct Serve<P> {
    provider: Arc<P>,
    tickets: Arc<Tickets>,
    log: Mutex<Option<Arc<Blob>>>,
    snapshot: Mutex<Option<Arc<Transfer>>>,
    peer: SocketAddr,
    account: [u8; 64],
    vault_id: [u8; 16],
}

impl<P: Provider> Serve<P> {
    /// Serve `vault_id` to the device of `account` seen at `peer`.
    #[must_use]
    pub const fn new(
        provider: Arc<P>,
        tickets: Arc<Tickets>,
        peer: SocketAddr,
        account: [u8; 64],
        vault_id: [u8; 16],
    ) -> Self {
        Self {
            provider,
            tickets,
            log: Mutex::new(None),
            snapshot: Mutex::new(None),
            peer,
            account,
            vault_id,
        }
    }

    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(&P, &[u8; 16]) -> T + Send + 'static,
    ) -> Option<T> {
        let (provider, vault_id) = (Arc::clone(&self.provider), self.vault_id);
        tokio::task::spawn_blocking(move || work(&provider, &vault_id))
            .await
            .ok()
    }

    async fn bytes(
        &self,
        ty: MsgType,
        work: impl FnOnce(&P, &[u8; 16]) -> Option<Vec<u8>> + Send + 'static,
    ) -> Answer {
        self.blocking(work)
            .await
            .flatten()
            .map_or_else(Answer::refused, |body| Answer::ok(ty, body))
    }

    /// Answer a request of type `ty` with `payload`.
    pub async fn answer(&self, ty: MsgType, payload: &[u8]) -> Answer {
        match ty {
            MsgType::Announce => self.bytes(ty, P::announce).await,
            MsgType::Frontier => self.bytes(ty, P::frontier).await,
            MsgType::LogHead => self.log_head().await,
            MsgType::LogChunk => self.log_chunk(payload).await,
            MsgType::Want => match Want::try_from(payload) {
                Ok(want) => {
                    self.bytes(MsgType::Bundle, move |p, v| p.revision(v, want.record_id))
                        .await
                }
                Err(_) => Answer::refused(),
            },
            MsgType::Bundle => self.push(payload).await,
            MsgType::SnapReq => self.snapshot(payload).await,
            MsgType::Rekey => {
                let account = self.account;
                self.blocking(move |p, v| p.rekey(v, &account))
                    .await
                    .flatten()
                    .map_or_else(Answer::refused, |seed| Answer {
                        body: seed,
                        ty,
                        outcome: Outcome::Served,
                    })
            }
            MsgType::Peers => {
                let list = payload.to_vec();
                self.bytes(ty, move |p, v| {
                    p.accept_peers(v, &list);
                    p.peers(v)
                })
                .await
            }
            MsgType::WhoAmI => Answer::ok(ty, WhoAmI(self.peer).encode()),
            MsgType::Ping => Ping::try_from(payload).map_or_else(
                |_| Answer::refused(),
                |ping| Answer::ok(MsgType::Pong, ping.encode()),
            ),
            MsgType::SnapChunk
            | MsgType::SnapHead
            | MsgType::Pong
            | MsgType::Busy
            | MsgType::Refused
            | MsgType::Stale => Answer::refused(),
        }
    }

    async fn push(&self, bundle: &[u8]) -> Answer {
        let (account, bundle) = (self.account, bundle.to_vec());
        match self
            .blocking(move |p, v| p.accept_revision(v, &account, &bundle))
            .await
        {
            Some(Verdict::Applied) => Answer::ok(MsgType::Bundle, Vec::new()),
            Some(Verdict::Stale) => Answer::stale(),
            Some(Verdict::Refused | Verdict::Invalid) | None => Answer::refused(),
        }
    }

    async fn log_head(&self) -> Answer {
        let Some(log) = self.blocking(P::log).await.flatten() else {
            return Answer::refused();
        };
        let blob = Blob::memory(log);
        if blob.total() > MAX_LOG_LEN {
            return Answer::refused();
        }
        let extent = Extent {
            id: *blob.id(),
            total: blob.total(),
        };
        if let Ok(mut slot) = self.log.lock() {
            *slot = Some(Arc::new(blob));
        }
        Answer::ok(MsgType::LogHead, extent.encode())
    }

    async fn log_chunk(&self, payload: &[u8]) -> Answer {
        let Ok(request) = ChunkRequest::try_from(payload) else {
            return Answer::refused();
        };
        let blob = self.log.lock().ok().and_then(|slot| slot.clone());
        let Some(blob) = blob.filter(|blob| blob.id() == &request.id) else {
            return Answer::stale();
        };
        let Some(data) = blob.chunk(request.offset) else {
            return Answer::refused();
        };
        let end = request
            .offset
            .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        if end >= blob.total() {
            let account = self.account;
            self.blocking(move |p, v| p.log_served(v, &account)).await;
        }
        chunk_answer(MsgType::LogChunk, &blob, request.offset, data)
    }

    fn current(&self) -> Option<Arc<Transfer>> {
        self.snapshot.lock().ok()?.clone()
    }

    async fn begin(&self) -> Result<Arc<Transfer>, Answer> {
        if let Ok(mut slot) = self.snapshot.lock() {
            slot.take();
        }
        let permit = self.tickets.try_snapshot().ok_or_else(Answer::busy)?;
        let source = self
            .blocking(P::snapshot_source)
            .await
            .flatten()
            .ok_or_else(Answer::refused)?;
        let blob = tokio::task::spawn_blocking(move || Blob::snapshot(source))
            .await
            .ok()
            .and_then(Result::ok)
            .ok_or_else(Answer::refused)?;
        let transfer = Arc::new(Transfer {
            blob,
            permit: Mutex::new(Some(permit)),
            served: AtomicU64::new(0),
            started: Instant::now(),
        });
        if let Ok(mut slot) = self.snapshot.lock() {
            *slot = Some(Arc::clone(&transfer));
        }
        Ok(transfer)
    }

    async fn snapshot(&self, payload: &[u8]) -> Answer {
        if payload.is_empty() {
            return self.snapshot_head().await;
        }
        let Ok(request) = ChunkRequest::try_from(payload) else {
            return Answer::refused();
        };
        let Some(transfer) = self.current().filter(|transfer| {
            transfer.blob.id() == &request.id
                && transfer.started.elapsed() <= self.tickets.limits().transfer
        }) else {
            return Answer::stale();
        };
        if request.offset % u64::try_from(CHUNK_LEN).unwrap_or(u64::MAX) != 0 {
            return Answer::refused();
        }
        let reader = Arc::clone(&transfer);
        let data = tokio::task::spawn_blocking(move || reader.blob.chunk(request.offset))
            .await
            .ok()
            .flatten();
        let Some(data) = data else {
            return Answer::refused();
        };
        transfer.sent(data.len());
        chunk_answer(MsgType::SnapChunk, &transfer.blob, request.offset, data)
    }

    async fn snapshot_head(&self) -> Answer {
        let transfer = match self.begin().await {
            Ok(transfer) => transfer,
            Err(answer) => return answer,
        };
        SnapHead::new(*transfer.blob.id(), transfer.blob.total()).map_or_else(
            |_| {
                if let Ok(mut slot) = self.snapshot.lock() {
                    slot.take();
                }
                Answer::refused()
            },
            |head| Answer::ok(MsgType::SnapHead, head.encode()),
        )
    }
}

fn chunk_answer(ty: MsgType, blob: &Blob, offset: u64, data: Vec<u8>) -> Answer {
    debug_assert!(data.len() <= CHUNK_LEN);
    Chunk {
        data: data.into_boxed_slice(),
        id: *blob.id(),
        offset,
        total: blob.total(),
    }
    .encode()
    .map_or_else(|_| Answer::refused(), |body| Answer::ok(ty, body))
}
