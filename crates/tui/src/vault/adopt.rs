//! Replace a placeholder with the account's vault.
//!
//! A device restored without a vault file holds an empty vault of its own;
//! when another device of the account is found, the file it serves takes
//! its place.
//!
//! The phrase is gone by then. The password this device enrolled opens the
//! other device's file when both use the same one, so the person never types
//! anything again.
//!
//! The phrase never leaves a device. This device's identity, derived from it
//! at restore, certifies it to the peer; what crosses the network is that
//! identity's certificate, public keys and the sealed vault file.
//!
//! The trust anchor is the vault file's own integrity commitment, checked by
//! `session::unlock` before anything is decrypted, over a channel whose peer
//! proved a certificate chaining to this account's root; the file must also
//! be the very vault the peer announced and must not be older than what this
//! device already holds.

use std::sync::Arc;

use local::{load_local_meta, paths_for, remember_personal_peer, Paths, SyncIdentity};
use p2p_net::{fetch_personal, PersonalFetch};
use session::{check_seen, unlock, Seen, Session, UnlockCreds, VaultFile};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::vault::create::{land, Enrollment};
use crate::vault::error::UnlockError;
use crate::vault::open::{read_vault_file, Vault};

/// File in a placeholder's directory that says it is one.
const MARKER: &str = "placeholder";

/// Whether the vault at `paths` is an empty stand-in waiting for the real one.
#[must_use]
pub fn is_placeholder(paths: &Paths) -> bool {
    paths.vault_dir().join(MARKER).is_file()
}

/// Mark the vault at `paths` as a placeholder.
///
/// # Errors
///
/// Storage failure.
pub fn mark_placeholder(paths: &Paths) -> anyhow::Result<()> {
    local::write_atomic(&paths.vault_dir().join(MARKER), b"")
}

/// A password kept for the session, wiped on drop, never printed.
pub struct Held(Zeroizing<Vec<u8>>);

impl Held {
    /// Keep a copy of `password`.
    #[must_use]
    pub fn new(password: &[u8]) -> Self {
        Self(Zeroizing::new(password.to_vec()))
    }

    /// A copy for a job that outlives the borrow.
    #[must_use]
    pub fn copy(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_vec())
    }
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Held([REDACTED])")
    }
}

/// What it takes to fetch the account's vault and replace a placeholder.
pub struct AdoptRequest {
    /// Where the placeholder lives.
    pub placeholder: Paths,
    /// This device's identity, enrolled at restore.
    pub identity: Arc<SyncIdentity>,
    /// Derived from the phrase at restore; kept on this device's metadata.
    pub client_id: [u8; 64],
    /// Display name on this device.
    pub name: String,
    /// The password this device enrolled, which should open the peer's file.
    pub password: Zeroizing<Vec<u8>>,
    /// Addresses to try, newest last.
    pub addresses: Vec<String>,
    /// Addresses on this machine may be dialed.
    pub loopback: bool,
}

impl std::fmt::Debug for AdoptRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdoptRequest([REDACTED])")
    }
}

/// Ask the devices at `addresses` for the account's vault and make the first
/// answer this device's vault, removing the placeholder.
///
/// # Errors
///
/// [`UnlockError::Peer`] when no device answers, [`UnlockError::WrongVault`]
/// for a file that is not the announced vault, [`UnlockError::Denied`] when
/// the password does not open it, [`UnlockError::Rollback`] and
/// [`UnlockError::Conflict`] when this device already holds a newer or
/// different copy, [`UnlockError::Io`] for storage failures.
pub fn adopt(request: &AdoptRequest) -> Result<Box<Vault>, UnlockError> {
    let mut last = UnlockError::Peer(p2p_net::FetchError::Unreachable);
    for address in request.addresses.iter().rev() {
        match fetch_personal(&request.identity, address, request.loopback) {
            Ok(fetched) => return adopt_fetched(request, fetched, address),
            Err(reason) => last = UnlockError::Peer(reason),
        }
    }
    Err(last)
}

/// Check what a peer sent and make it this device's vault.
///
/// Nothing is written until every check has passed, so a refused file leaves
/// no trace on disk.
///
/// # Errors
///
/// As [`adopt`], for everything after the fetch.
pub fn adopt_fetched(
    request: &AdoptRequest,
    fetched: PersonalFetch,
    address: &str,
) -> Result<Box<Vault>, UnlockError> {
    let device_id = request.identity.device_id().ok_or(UnlockError::Io)?;
    let file = VaultFile::new(fetched.file);
    let announced = {
        let parsed = file.parse().map_err(|_| UnlockError::NotAVault)?;
        let announce = &fetched.announce;
        bool::from(parsed.header.vault_id.ct_eq(&announce.vault_id))
            && bool::from(parsed.commit.ct_eq(&announce.commit_tag))
            && parsed.generation == announce.generation
    };
    if !announced {
        return Err(UnlockError::WrongVault);
    }
    let creds = UnlockCreds::default().with_human(&request.password);
    let mut session = unlock(&file, &creds, None).map_err(|_| UnlockError::Denied)?;
    let paths = paths_for(&request.placeholder.base, session.vault_id());
    if paths.vault_dir() == request.placeholder.vault_dir() {
        return Err(UnlockError::WrongVault);
    }
    refuse_older(&paths, &session)?;
    session
        .set_origin_device(device_id)
        .map_err(|_| UnlockError::Io)?;
    request
        .identity
        .save(
            &paths.sync_identity(),
            &session.sync_identity_key().map_err(|_| UnlockError::Io)?,
        )
        .map_err(|_| UnlockError::Io)?;
    remember_peer(&paths, &session, address);
    let vault = land(
        (session, file, paths),
        (request.client_id, request.name.clone()),
        session::KdfProfile::Balanced,
        Enrollment::KeepExisting,
    )?;
    drop(std::fs::remove_dir_all(request.placeholder.vault_dir()));
    Ok(vault)
}

/// A hint cache: failing to write it costs the next session a search.
fn remember_peer(paths: &Paths, session: &Session, address: &str) {
    let _ = session
        .personal_peers_key()
        .and_then(|key| remember_personal_peer(&paths.peers_store(), &key, address, true));
}

/// Refuse a file older than the vault this device already holds, or one that
/// disagrees with it at the same generation. The file on disk answers this
/// without any key, since its generation and commit tag are public; the
/// rollback cursor in `local.meta` answers it too when it opens under this
/// file's key.
fn refuse_older(paths: &Paths, session: &Session) -> Result<(), UnlockError> {
    if let Ok(held) = read_vault_file(&paths.vault_file) {
        if let Ok(parsed) = held.parse() {
            let same_tag = bool::from(parsed.commit.ct_eq(session.commit_tag()));
            if session.generation() < parsed.generation {
                return Err(UnlockError::Rollback {
                    seen: parsed.generation,
                    disk: session.generation(),
                });
            }
            if session.generation() == parsed.generation && !same_tag {
                return Err(UnlockError::Conflict {
                    generation: parsed.generation,
                });
            }
        }
    }
    let Ok(key) = session.local_meta_key() else {
        return Err(UnlockError::Io);
    };
    if let Ok(meta) = load_local_meta(&paths.local_meta, &key) {
        let seen = meta.seen.map(|cursor| Seen {
            generation: cursor.generation,
            commit_tag: cursor.commit_tag,
        });
        check_seen(session, seen).map_err(|error| match UnlockError::from(&error) {
            UnlockError::Rollback { .. } => UnlockError::Rollback {
                seen: seen.map_or(0, |cursor| cursor.generation),
                disk: session.generation(),
            },
            UnlockError::Conflict { .. } => UnlockError::Conflict {
                generation: session.generation(),
            },
            other => other,
        })?;
    }
    Ok(())
}
