//! Serving the personal vault to the other devices of the same account.
//!
//! Authorization is one rule and no more: a connection that got past the gate
//! and the handshake is a device whose certificate chains to this account's
//! root, so it may read everything of this personal vault. There is no member
//! log and no role check; the account is the only principal. The vault file
//! is opened afresh from disk for each request that needs its records, with
//! the vault key the node was given, and nothing is cached between requests.
//! Nothing here writes, and the vault file is replaced atomically by its
//! owner, so these reads take no node lock.

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use local::SyncIdentity;
use p2p_core::Account;
use secret::Secret;
use session::{frontier, latest_frame, unlock_with_key, VaultFile};
use syncwire::{
    encode_announce, encode_frontier, encode_personal_frame, encode_snapshot, Announce,
};

use crate::dialable::Dialing;
use crate::view::VaultView;

/// Largest vault file the node reads to serve.
const MAX_VAULT_BYTES: u64 = 512 << 20;

/// The handshake view of the personal vault of `identity`'s account.
///
/// The account's devices find each other under it. It is addressed by an id
/// that both sides derive from the account's gate secret, because a device
/// that holds only the phrase does not know the vault's own id yet.
///
/// `None` for an identity written before the gate secret existed.
#[must_use]
pub fn personal_view(identity: &SyncIdentity, dialing: Dialing) -> Option<VaultView> {
    let gate = identity.account_gate()?;
    let route = kdf::account_route_id(gate).ok()?;
    let cert = identity.devices().first().cloned()?;
    Some(VaultView {
        vault_id: route,
        accounts: vec![Account {
            client_id: cert.client_id,
            root_vk: Box::new(*identity.root_vk()),
        }],
        cert,
        sign: identity.sign_key(),
        revoked: identity.revocations().all().to_vec(),
        gate_keys: vec![kdf::p2p_gate_key(gate.expose(), &route).ok()?],
        dialing,
    })
}

/// A personal vault on this device that the node serves.
pub struct PersonalServe {
    route: [u8; 16],
    file: PathBuf,
    key: Secret<[u8; 32]>,
    device_id: [u8; 16],
}

impl PersonalServe {
    /// Serve the vault file at `file`, opened with `key`, under the handshake
    /// id `route`.
    #[must_use]
    pub const fn new(
        route: [u8; 16],
        file: PathBuf,
        key: Secret<[u8; 32]>,
        device_id: [u8; 16],
    ) -> Self {
        Self {
            route,
            file,
            key,
            device_id,
        }
    }

    /// The id the handshake addresses this vault by.
    #[must_use]
    pub const fn route(&self) -> &[u8; 16] {
        &self.route
    }

    fn read(&self) -> Result<VaultFile> {
        let len = std::fs::metadata(&self.file)?.len();
        if len > MAX_VAULT_BYTES {
            return Err(anyhow!("vault file too large"));
        }
        Ok(VaultFile::new(std::fs::read(&self.file)?))
    }

    /// The generation and commit tag of the vault file on disk, with the vault
    /// number: public fields, so no key is needed.
    #[must_use]
    pub fn announce(&self) -> Option<Vec<u8>> {
        let file = self.read().ok()?;
        let parsed = file.parse().ok()?;
        Some(encode_announce(&Announce {
            vault_id: parsed.header.vault_id,
            generation: parsed.generation,
            commit_tag: parsed.commit,
        }))
    }

    /// The vault file, in a snapshot that carries no attestations: personal
    /// records have none, and the receiver trusts the file by its commitment
    /// and the channel it came over.
    #[must_use]
    pub fn snapshot(&self) -> Option<Vec<u8>> {
        encode_snapshot(self.read().ok()?.as_bytes(), &[]).ok()
    }

    /// The winning revision of every record of the vault on disk.
    #[must_use]
    pub fn frontier(&self) -> Option<Vec<u8>> {
        let session = unlock_with_key(&self.read().ok()?, &self.key, self.device_id).ok()?;
        encode_frontier(&frontier(&session).ok()?).ok()
    }

    /// The winning sealed frame of one record.
    #[must_use]
    pub fn revision(&self, record_id: u32) -> Option<Vec<u8>> {
        let session = unlock_with_key(&self.read().ok()?, &self.key, self.device_id).ok()?;
        encode_personal_frame(&latest_frame(&session, record_id).ok()?).ok()
    }
}
