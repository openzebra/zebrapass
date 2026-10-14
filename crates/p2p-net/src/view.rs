//! What a node needs to speak for one vault, and what it serves.

use local::Verdict;
use p2p_core::{Account, Local};
use secret::Secret;
use session::{DeviceCert, DeviceSignKey, Revocation};
use zeroize::Zeroizing;

use crate::dialable::Dialing;

/// Everything the handshake needs for one vault, owned so it can cross
/// tasks.
#[derive(Debug)]
pub struct VaultView {
    /// The vault's number.
    pub vault_id: [u8; 16],
    /// This device's certificate.
    pub cert: DeviceCert,
    /// This device's signing key.
    pub sign: DeviceSignKey,
    /// The accounts whose devices may connect.
    pub accounts: Vec<Account>,
    /// Accepted revocations.
    pub revoked: Vec<Revocation>,
    /// Gate keys, the newest first.
    pub gate_keys: Vec<Secret<[u8; 32]>>,
    /// Which addresses this device may dial for the vault.
    pub dialing: Dialing,
}

impl VaultView {
    /// The borrowed form the handshake takes.
    #[must_use]
    pub fn local(&self) -> Local<'_> {
        Local {
            vault_id: self.vault_id,
            cert: &self.cert,
            sign: &self.sign,
            accounts: &self.accounts,
            revoked: &self.revoked,
            gate_keys: &self.gate_keys,
        }
    }
}

/// A snapshot to send: its prefix, then `file_len` bytes of `file`.
///
/// The file is a handle opened under the same lock as the prefix was made,
/// so the two belong together even if the vault file is replaced afterwards.
#[derive(Debug)]
pub struct SnapshotSource {
    /// What comes before the vault file.
    pub prefix: Vec<u8>,
    /// The vault file, read from its start.
    pub file: std::fs::File,
    /// Its length when it was opened.
    pub file_len: u64,
}

/// The vaults a node serves and their contents. Called for every incoming
/// connection, so a change to a vault shows at once.
pub trait Provider: Send + Sync + 'static {
    /// The vaults this node serves.
    fn views(&self) -> Vec<VaultView>;

    /// The vault's member log: each entry's wire bytes, concatenated.
    fn log(&self, vault_id: &[u8; 16]) -> Option<Vec<u8>>;

    /// A member's device was just handed the vault's member log.
    fn log_served(&self, _vault_id: &[u8; 16], _account: &[u8; 64]) {}

    /// The vault file with what goes in front of it, opened for reading.
    fn snapshot_source(&self, vault_id: &[u8; 16]) -> Option<SnapshotSource>;

    /// Which vault file this device holds for a personal vault: its number,
    /// generation and commit tag. Only a personal vault has one.
    fn announce(&self, _vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        None
    }

    /// The frontier of the vault: the winning revision of every record.
    fn frontier(&self, _vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        None
    }

    /// The winning revision of one record with its attestation.
    fn revision(&self, _vault_id: &[u8; 16], _record_id: u32) -> Option<Vec<u8>> {
        None
    }

    /// Keep a revision a peer pushed, if its attestation holds and its writer
    /// is a writer of the vault.
    fn accept_revision(
        &self,
        _vault_id: &[u8; 16],
        _account: &[u8; 64],
        _bundle: &[u8],
    ) -> Verdict {
        Verdict::Refused
    }

    /// Merge the member log entries a peer holds into the stored log, every
    /// new entry verified. Returns whether the log is now consistent with the
    /// peer's.
    fn merge_log(&self, _vault_id: &[u8; 16], _log: &[u8]) -> bool {
        false
    }

    /// This device's signed addresses and the ones it knows, as a list.
    fn peers(&self, _vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        None
    }

    /// Keep the addresses a member sent that verify. Returns how many.
    fn accept_peers(&self, _vault_id: &[u8; 16], _list: &[u8]) -> usize {
        0
    }

    /// Addresses of the other members, learned from them.
    fn peer_hints(&self, _vault_id: &[u8; 16]) -> Vec<String> {
        Vec::new()
    }

    /// Whether a peer's offer (its rekey answer, if any) means this device
    /// should take over the peer's vault file: a later epoch, or an open vault
    /// that is stale.
    fn needs_snapshot(&self, _vault_id: &[u8; 16], _rekey: Option<&[u8]>) -> bool {
        false
    }

    /// The vault's current seed and its epoch (64 bytes then 4 big-endian),
    /// for an account that is a member now. The connection has already
    /// authenticated that account's device.
    fn rekey(&self, _vault_id: &[u8; 16], _account: &[u8; 64]) -> Option<Zeroizing<Vec<u8>>> {
        None
    }

    /// Beacon keys and their corresponding 16-byte vault or route identifiers
    /// that this node should announce and listen for on the local network.
    fn beacon_targets(&self) -> Vec<(Secret<[u8; 32]>, [u8; 16])> {
        Vec::new()
    }
}
