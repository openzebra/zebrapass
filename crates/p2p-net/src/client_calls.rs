//! The requests a device makes of a peer, one function each.

use std::net::SocketAddr;

use p2p_core::Reply;
use syncwire::limits::{CHUNK_LEN, MAX_LOG_LEN, PIPELINE_DEPTH};
use syncwire::{Chunk, ChunkRequest, Extent, MsgType, Ping, SnapHead, Want, WhoAmI};
use zeroize::Zeroizing;

use crate::client::{Conn, FetchError, Fetched};
use crate::view::VaultView;

type Outcome<T> = Result<T, FetchError>;

/// How a peer took a pushed revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Push {
    /// Kept.
    Applied,
    /// The peer holds a newer one, or was too busy to look.
    Stale,
    /// Turned away: a role or a signature.
    Refused,
}

fn body(reply: Reply) -> Outcome<Vec<u8>> {
    match reply {
        Reply::Payload(bytes) => Ok(bytes.expose().clone()),
        Reply::Busy | Reply::Refused | Reply::Stale => Err(FetchError::Failed),
    }
}

impl Conn {
    /// The vault file a peer holds, as it announces it.
    ///
    /// # Errors
    ///
    /// [`FetchError::Failed`] unless the peer answers.
    pub async fn announce(&mut self) -> Outcome<Vec<u8>> {
        body(self.call(MsgType::Announce, Vec::new()).await?)
    }

    /// The frontier of the peer's vault.
    ///
    /// # Errors
    ///
    /// [`FetchError::Failed`] unless the peer answers.
    pub async fn frontier(&mut self) -> Outcome<Vec<u8>> {
        body(self.call(MsgType::Frontier, Vec::new()).await?)
    }

    /// The peer's seed and epoch, if it offers them.
    ///
    /// # Errors
    ///
    /// [`FetchError::Failed`] for a broken connection.
    pub async fn rekey(&mut self) -> Outcome<Option<Zeroizing<Vec<u8>>>> {
        Ok(match self.call(MsgType::Rekey, Vec::new()).await? {
            Reply::Payload(seed) => Some(Zeroizing::new(seed.expose().clone())),
            Reply::Busy | Reply::Refused | Reply::Stale => None,
        })
    }

    /// Trade address lists: send `own`, get the peer's.
    ///
    /// # Errors
    ///
    /// [`FetchError::Failed`] unless the peer answers.
    pub async fn peers(&mut self, own: Vec<u8>) -> Outcome<Vec<u8>> {
        body(self.call(MsgType::Peers, own).await?)
    }

    /// The revisions named by `wanted` (record, revision), at most
    /// [`PIPELINE_DEPTH`] asked for at once; `None` for one the peer does not
    /// give. The peer answers with its winning revision of the record.
    ///
    /// # Errors
    ///
    /// [`FetchError::Failed`] for a broken connection or more ids than the
    /// pipeline holds.
    pub async fn revisions(&mut self, wanted: &[(u32, u64)]) -> Outcome<Vec<Option<Vec<u8>>>> {
        if wanted.len() > PIPELINE_DEPTH {
            return Err(FetchError::Failed);
        }
        let requests = wanted.iter().map(|(record_id, revision)| {
            let want = Want {
                revision: *revision,
                record_id: *record_id,
            };
            (MsgType::Want, want.encode())
        });
        let mut found = Vec::with_capacity(wanted.len());
        self.pipeline(requests, |reply| {
            found.push(match reply {
                Reply::Payload(bundle) => Some(bundle.expose().clone()),
                Reply::Busy | Reply::Refused | Reply::Stale => None,
            });
            Ok(())
        })
        .await?;
        Ok(found)
    }

    /// Push `bundles`, at most [`PIPELINE_DEPTH`] at once.
    ///
    /// # Errors
    ///
    /// [`FetchError::Failed`] for a broken connection or more bundles than
    /// the pipeline holds.
    pub async fn push(&mut self, bundles: Vec<Vec<u8>>) -> Outcome<Vec<Push>> {
        if bundles.len() > PIPELINE_DEPTH {
            return Err(FetchError::Failed);
        }
        let mut verdicts = Vec::with_capacity(bundles.len());
        self.pipeline(
            bundles.into_iter().map(|bundle| (MsgType::Bundle, bundle)),
            |reply| {
                verdicts.push(match reply {
                    Reply::Payload(_) => Push::Applied,
                    Reply::Stale | Reply::Busy => Push::Stale,
                    Reply::Refused => Push::Refused,
                });
                Ok(())
            },
        )
        .await?;
        Ok(verdicts)
    }

    /// The address the peer sees this device at.
    ///
    /// # Errors
    ///
    /// [`FetchError::Failed`] unless the peer answers with an address.
    pub async fn whoami(&mut self) -> Outcome<SocketAddr> {
        let seen = body(self.call(MsgType::WhoAmI, Vec::new()).await?)?;
        WhoAmI::try_from(&seen[..])
            .map(|seen| seen.0)
            .map_err(|_| FetchError::Failed)
    }

    /// Check that the peer is still there.
    ///
    /// # Errors
    ///
    /// [`FetchError::Failed`] unless the peer echoes the token.
    pub async fn ping(&mut self, token: u64) -> Outcome<()> {
        let echoed = body(self.call(MsgType::Ping, Ping(token).encode()).await?)?;
        (Ping::try_from(&echoed[..]).map_err(|_| FetchError::Failed)? == Ping(token))
            .then_some(())
            .ok_or(FetchError::Failed)
    }

    /// The peer's member log.
    ///
    /// # Errors
    ///
    /// [`FetchError::Failed`] for a refusal, a log that changes while it is
    /// read, or a broken connection.
    pub async fn log(&mut self) -> Outcome<Vec<u8>> {
        let head = body(self.call(MsgType::LogHead, Vec::new()).await?)?;
        let head = Extent::try_from(&head[..]).map_err(|_| FetchError::Failed)?;
        if head.total > MAX_LOG_LEN {
            return Err(FetchError::Failed);
        }
        let mut log = Vec::new();
        self.pull(
            MsgType::LogChunk,
            head.id,
            head.total,
            &mut log,
            Chunk::decode_log,
        )
        .await?;
        Ok(log)
    }

    /// The peer's vault file with its attestations.
    ///
    /// # Errors
    ///
    /// [`FetchError::Failed`] for a refusal, a busy peer, a head that is not
    /// sound, a file that changes while it is read, or a broken connection.
    pub async fn snapshot(&mut self) -> Outcome<Vec<u8>> {
        let head = body(self.call(MsgType::SnapReq, Vec::new()).await?)?;
        let head = SnapHead::try_from(&head[..]).map_err(|_| FetchError::Failed)?;
        if head.chunk_size != u32::try_from(CHUNK_LEN).map_err(|_| FetchError::Failed)? {
            return Err(FetchError::Failed);
        }
        let mut file =
            Vec::with_capacity(usize::try_from(head.size).map_err(|_| FetchError::Failed)?);
        self.pull(
            MsgType::SnapReq,
            head.id,
            head.size,
            &mut file,
            Chunk::decode_snapshot,
        )
        .await?;
        Ok(file)
    }

    async fn pull(
        &mut self,
        ty: MsgType,
        id: [u8; 32],
        total: u64,
        out: &mut Vec<u8>,
        decode: fn(&[u8]) -> anyhow::Result<Chunk>,
    ) -> Outcome<()> {
        let start = u64::try_from(out.len()).map_err(|_| FetchError::Failed)?;
        let requests = (start..total)
            .step_by(CHUNK_LEN)
            .map(|offset| (ty, ChunkRequest { id, offset }.encode()));
        self.pipeline(requests, |reply| {
            let Reply::Payload(bytes) = reply else {
                return Err(FetchError::Failed);
            };
            let chunk = decode(bytes.expose()).map_err(|_| FetchError::Failed)?;
            let at = u64::try_from(out.len()).map_err(|_| FetchError::Failed)?;
            let want = (total - at).min(u64::try_from(CHUNK_LEN).unwrap_or(u64::MAX));
            if chunk.id != id
                || chunk.total != total
                || chunk.offset != at
                || u64::try_from(chunk.data.len()).ok() != Some(want)
            {
                return Err(FetchError::Failed);
            }
            out.extend_from_slice(&chunk.data);
            Ok(())
        })
        .await
    }
}

/// Connect to `addr`, authenticate for `view`'s vault, and fetch the member
/// log, the vault file and the peer's seed if it offers one.
///
/// # Errors
///
/// As [`Conn::connect`], [`Conn::log`] and [`Conn::snapshot`].
pub async fn fetch(view: &VaultView, addr: &str) -> Outcome<Fetched> {
    let mut conn = Conn::connect(view, addr).await?;
    let log = conn.log().await?;
    let snapshot = conn.snapshot().await?;
    let rekey = conn.rekey().await?;
    Ok(Fetched {
        peer: conn.peer,
        log,
        snapshot,
        rekey,
    })
}
