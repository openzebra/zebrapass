//! A device that holds only the account's phrase asks another device of the
//! same account for the personal vault.
//!
//! The phrase never travels. What the dialing device brings is its own
//! certificate, which chains to the account's root, and a gate key derived
//! from the phrase. What comes back is the vault file and what the peer
//! announced about it; deciding whether that file is the vault, is current
//! and opens under the phrase is the caller's job, with the phrase in hand.

use std::net::SocketAddr;
use std::time::Duration;

use local::SyncIdentity;
use session::DeviceCert;
use syncwire::{decode_announce, decode_snapshot, Announce};
use tokio::runtime::Builder;
use tokio::time::timeout;

use crate::client::{Conn, FetchError};
use crate::dialable::{Dialing, Policy};
use crate::personal::personal_view;

/// How long the whole exchange may take, however the peer paces it.
const DEADLINE: Duration = Duration::from_secs(120);

/// What a peer sent for a restore.
#[derive(Debug)]
pub struct PersonalFetch {
    /// The vault file the peer says it holds.
    pub announce: Announce,
    /// The vault file as it arrived.
    pub file: Vec<u8>,
    /// The peer's verified certificate.
    pub peer: DeviceCert,
}

/// Dial `address`, authenticate as a device of `identity`'s account, and
/// fetch the personal vault.
///
/// Blocks until it is done, so call it from a worker thread. `loopback` lets a typed-in loopback address be dialed; the
/// address itself is the only one trusted, so a private network is reachable
/// only when that is where it points.
///
/// # Errors
///
/// [`FetchError::Unreachable`] when nobody answers or the address may not be
/// dialed, [`FetchError::Refused`] when the peer turns this device away or its
/// answer does not verify, [`FetchError::Failed`] otherwise, including an
/// identity without an account gate and a snapshot that carries attestations.
pub fn fetch_personal(
    identity: &SyncIdentity,
    address: &str,
    loopback: bool,
) -> Result<PersonalFetch, FetchError> {
    let target: SocketAddr = address.parse().map_err(|_| FetchError::Unreachable)?;
    let dialing = Dialing {
        policy: Policy { loopback },
        trusted: vec![target],
    };
    let view = personal_view(identity, dialing).ok_or(FetchError::Failed)?;
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| FetchError::Failed)?;
    runtime.block_on(async {
        timeout(DEADLINE, async {
            let mut conn = Conn::connect(&view, address).await?;
            let announce =
                decode_announce(&conn.announce().await?).map_err(|_| FetchError::Failed)?;
            let snapshot = conn.snapshot().await?;
            let (file, attestations) = decode_snapshot(snapshot).map_err(|_| FetchError::Failed)?;
            if !attestations.is_empty() {
                return Err(FetchError::Failed);
            }
            Ok(PersonalFetch {
                announce,
                file,
                peer: conn.peer,
            })
        })
        .await
        .unwrap_or(Err(FetchError::Failed))
    })
}
