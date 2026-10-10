//! Restore with the phrase alone: another device of the same account sends
//! the vault file over the peer-to-peer transport.
//!
//! TODO(seed-beacon): the address is typed in. Devices in the LAN beacon mode
//! announce themselves (see `p2p_net::BeaconConfig`), sealed under a key from
//! the account's gate secret, but this screen does not listen for them yet.
//!
//! The phrase never leaves this device. It derives this device's identity and
//! the gate key that lets the first message through; what crosses the network
//! is that identity's certificate, public keys and the sealed vault file.
//!
//! Personal records carry no writer attestations, so the shared-vault rules
//! that check them (`local::attested_store`, called from `adopt_shared_file`)
//! do not apply here. The trust anchor is the vault file's own integrity
//! commitment, checked by `session::unlock` before anything is decrypted,
//! over a channel whose peer proved a certificate chaining to this account's
//! root; the file must also be the very vault the peer announced and must not
//! be older than what this device already holds.

use local::{load_local_meta, paths_for, remember_personal_peer, Paths, SyncIdentity};
use p2p_net::{fetch_personal, PersonalFetch};
use session::{
    check_seen, fresh_device_id, unlock, wrap_directory, Seen, Session, UnlockCreds, VaultFile,
};
use subtle::ConstantTimeEq;

use crate::vault::create::{land, Enrollment, RestoreSource, RestoreVault};
use crate::vault::error::UnlockError;
use crate::vault::factors::presence;
use crate::vault::open::{read_vault_file, Vault};

/// Restore over the network: enroll this device's identity while the phrase
/// is in scope, dial `address`, and adopt the file that comes back.
///
/// # Errors
///
/// [`UnlockError::Peer`] when the device cannot be reached or turns this one
/// away, [`UnlockError::WrongVault`] for a file that is not the announced
/// vault or does not open with the phrase, [`UnlockError::Rollback`] and
/// [`UnlockError::Conflict`] when this device already holds a newer or
/// different copy, [`UnlockError::Io`] for storage failures.
pub fn restore_over_network(
    request: RestoreVault,
    address: &str,
) -> Result<Box<Vault>, UnlockError> {
    let client_id = kdf::client_id(request.phrase.seed()).map_err(|_| UnlockError::Io)?;
    let device_id = fresh_device_id().map_err(|_| UnlockError::Io)?;
    let identity = SyncIdentity::enroll(request.phrase.seed(), &client_id, device_id, u64::MAX)
        .map_err(|_| UnlockError::Io)?;
    let fetched = fetch_personal(&identity, address, true).map_err(UnlockError::Peer)?;
    adopt_fetched(request, &identity, fetched)
}

/// Check what a peer sent and make it this device's vault.
///
/// Nothing is written until every check has passed, so a refused file leaves
/// no trace on disk.
///
/// # Errors
///
/// As [`restore_over_network`], for everything after the fetch.
pub fn adopt_fetched(
    request: RestoreVault,
    identity: &SyncIdentity,
    fetched: PersonalFetch,
) -> Result<Box<Vault>, UnlockError> {
    let RestoreVault {
        phrase,
        name,
        base,
        source,
        profile,
        factor,
    } = request;
    let device_id = identity.device_id().ok_or(UnlockError::Io)?;
    let client_id = kdf::client_id(phrase.seed()).map_err(|_| UnlockError::Io)?;
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
    let mut session = unlock(&file, &UnlockCreds::master(phrase.seed()), None)
        .map_err(|_| UnlockError::WrongVault)?;
    drop(phrase);
    let paths = paths_for(&base, session.vault_id());
    refuse_older(&paths, &session)?;
    session
        .set_origin_device(device_id)
        .map_err(|_| UnlockError::Io)?;
    identity
        .save(
            &paths.sync_identity(),
            &session.sync_identity_key().map_err(|_| UnlockError::Io)?,
        )
        .map_err(|_| UnlockError::Io)?;
    if let RestoreSource::Network(address) = &source {
        remember_peer(&paths, &session, address);
    }
    let factor = match factor {
        Enrollment::Password(password)
            if wrap_directory(&file).is_ok_and(|dir| presence(&dir, None).password) =>
        {
            Enrollment::ReplacePassword(password)
        }
        other => other,
    };
    land((session, file, paths), (client_id, name), profile, factor)
}

/// A hint cache: failing to write it costs the next session a typed address.
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
