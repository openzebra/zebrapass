//! Serving and joining shared vaults from the files `local` keeps.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use local::{
    is_pending, load_peers, open_shared_vault, read_member_log, read_shared_state, save_member_log,
    save_peers, shared_paths_for, verdict_of, SharedRef, SharedVault, SyncIdentity, Verdict,
};
use memberlog::{Entry, ENTRY_WIRE_LEN, MAX_ENTRIES};
use p2p_core::Account;
use secret::Secret;
use syncwire::{encode_peers, encode_snapshot_prefix};
use zeroize::Zeroizing;

use crate::personal::{personal_view, PersonalServe};
use crate::shared_join::parse_rekey;
use crate::view::{Provider, SnapshotSource, VaultView};

pub fn unavailable() -> anyhow::Error {
    anyhow!("shared vault unavailable")
}

/// A provider that serves the shared vaults this device holds. It owns a copy
/// of the device identity, so locking the personal vault means dropping it.
pub struct SharedProvider {
    base: PathBuf,
    identity: Arc<SyncIdentity>,
    served: Mutex<Vec<Arc<SharedRef>>>,
    node: Mutex<()>,
    book: crate::peers::PeerBook,
    delivered: Mutex<Vec<[u8; 16]>>,
    personal: Mutex<Option<Arc<PersonalServe>>>,
}

impl SharedProvider {
    /// A provider for the vaults under `base`, signing as `identity`.
    #[must_use]
    pub fn new(base: PathBuf, identity: Arc<SyncIdentity>) -> Self {
        Self {
            base,
            identity,
            served: Mutex::new(Vec::new()),
            node: Mutex::new(()),
            book: crate::peers::PeerBook::default(),
            delivered: Mutex::new(Vec::new()),
            personal: Mutex::new(None),
        }
    }

    /// Serve the personal vault whose file is `vault_file`, opened with `key`,
    /// to the other devices of this account. Returns `false` when the
    /// identity predates the account gate and so cannot be reached by them.
    pub fn serve_personal(&self, vault_file: PathBuf, key: Secret<[u8; 32]>) -> bool {
        let Some(device_id) = self.identity.device_id() else {
            return false;
        };
        let Some(route) = self
            .identity
            .account_gate()
            .and_then(|gate| kdf::account_route_id(gate).ok())
        else {
            return false;
        };
        let serve = Arc::new(PersonalServe::new(route, vault_file, key, device_id));
        self.personal
            .lock()
            .map(|mut slot| *slot = Some(serve))
            .is_ok()
    }

    /// The personal vault this node serves, if any.
    pub fn personal_serve(&self) -> Option<Arc<PersonalServe>> {
        self.personal.lock().ok()?.clone()
    }

    /// The frames other devices of this account pushed since the last call,
    /// for the open vault to apply.
    pub fn take_pushed(&self) -> Vec<Vec<u8>> {
        self.personal_serve()
            .map(|serve| serve.take_inbox())
            .unwrap_or_default()
    }

    fn personal_for(&self, vault_id: &[u8; 16]) -> Option<Arc<PersonalServe>> {
        self.personal
            .lock()
            .ok()?
            .as_ref()
            .filter(|serve| serve.route() == vault_id)
            .cloned()
    }

    /// Vaults this device has left whose member log another member has since
    /// fetched from it, once each: the leave has been delivered.
    pub fn take_delivered(&self) -> Vec<[u8; 16]> {
        self.delivered
            .lock()
            .map(|mut list| std::mem::take(&mut *list))
            .unwrap_or_default()
    }

    /// Stop serving a vault.
    pub fn unserve(&self, vault_id: &[u8; 16]) {
        if let Ok(mut served) = self.served.lock() {
            served.retain(|known| &known.vault_id != vault_id);
        }
    }

    /// Accept loopback addresses other members publish: for tests and
    /// single-machine setups.
    pub fn allow_loopback_peers(&self) {
        self.book.allow_loopback();
    }

    /// The addresses this device can be reached at, offered to members.
    pub fn set_hints(&self, hints: Vec<String>) {
        self.book.set_own(hints);
    }

    /// Run `act` while holding the node lock, for readers that open the files
    /// themselves and must not see a half-finished write.
    pub fn locked<T>(&self, act: impl FnOnce() -> T) -> Option<T> {
        let _held = self.node.lock().ok()?;
        Some(act())
    }

    /// Open the vault fresh from disk and run `act` on it while holding the
    /// node lock, so the files are only ever changed by one task at a time.
    /// The disk stays the source of truth: nothing is cached between calls.
    ///
    /// # Errors
    ///
    /// `shared vault unavailable` when the vault is not served or cannot be
    /// opened, and whatever `act` returns.
    pub fn with_vault<T>(
        &self,
        vault_id: &[u8; 16],
        act: impl FnOnce(&mut SharedVault, &SharedRef, &SyncIdentity) -> Result<T>,
    ) -> Result<T> {
        let reference = self.reference(vault_id).ok_or_else(unavailable)?;
        let _held = self.node.lock().map_err(|_| unavailable())?;
        let mut vault = open_shared_vault(&self.base, &reference, &self.identity)?;
        act(&mut vault, &reference, &self.identity)
    }

    /// Open the vault fresh from disk and run `act` on it without the node
    /// lock, for actions that change nothing. Every file is replaced
    /// atomically, so a reader sees whole files; one that races a writer may
    /// find them out of step and gets an error, never a wrong answer.
    ///
    /// # Errors
    ///
    /// As [`SharedProvider::with_vault`].
    pub fn read_vault<T>(
        &self,
        vault_id: &[u8; 16],
        act: impl FnOnce(&SharedVault) -> Result<T>,
    ) -> Result<T> {
        let reference = self.reference(vault_id).ok_or_else(unavailable)?;
        act(&open_shared_vault(&self.base, &reference, &self.identity)?)
    }

    /// Serve `reference`, replacing an earlier entry for the same vault.
    pub fn serve(&self, reference: Arc<SharedRef>) {
        self.restore_peers(&reference);
        if let Ok(mut served) = self.served.lock() {
            served.retain(|known| known.vault_id != reference.vault_id);
            served.push(reference);
        }
    }

    /// Take back the peer addresses stored for `reference`'s vault. Each
    /// record is checked again as if a member had just sent it, so expired
    /// ones, removed members' and forbidden addresses drop out; a missing or
    /// unreadable file only means the search starts from the invitation.
    fn restore_peers(&self, reference: &SharedRef) {
        let (Ok(_held), Ok(log), Some(own)) = (
            self.node.lock(),
            read_member_log(&self.base, reference),
            self.identity.devices().first(),
        ) else {
            return;
        };
        let paths = shared_paths_for(&self.base, &reference.vault_id);
        let stored = kdf::shared_peers_key(reference.seed.expose(), &reference.vault_id)
            .and_then(|key| load_peers(&paths.peers_store(), &key))
            .and_then(|records| encode_peers(&records));
        if let Ok(bytes) = stored {
            self.book
                .accept(&log, &own.device_id, &reference.hints, &bytes);
        }
    }

    fn store_peers(&self, reference: &SharedRef) {
        let Ok(_held) = self.node.lock() else {
            return;
        };
        let paths = shared_paths_for(&self.base, &reference.vault_id);
        let records = self.book.records_of(&reference.vault_id);
        // A failed write loses only a hint cache.
        let _ = kdf::shared_peers_key(reference.seed.expose(), &reference.vault_id)
            .and_then(|key| save_peers(&paths.peers_store(), &key, &records));
    }

    /// The handshake view of one shared vault: its members' accounts, its
    /// revocations, and the gate keys of every seed this device knows, so a
    /// member that missed a rotation can still reach it and receive the new
    /// seed.
    ///
    /// # Errors
    ///
    /// `shared vault unavailable` when the member log or state cannot be read
    /// and verified.
    pub fn view_for(&self, reference: &SharedRef) -> Result<VaultView> {
        let log = read_member_log(&self.base, reference)?;
        let state = read_shared_state(&self.base, reference)?;
        let cert = self
            .identity
            .devices()
            .first()
            .cloned()
            .ok_or_else(unavailable)?;
        let gate_keys = reference
            .seeds()
            .map(|seed| kdf::shared_gate_key(seed.expose(), &reference.vault_id))
            .collect::<Result<Vec<_>>>()?;
        let introducer = reference
            .introduction
            .as_ref()
            .filter(|_| is_pending(&self.base, reference))
            .map(|intro| Account {
                client_id: intro.inviter_id,
                root_vk: intro.inviter_vk.clone(),
            });
        Ok(VaultView {
            vault_id: reference.vault_id,
            cert,
            sign: self.identity.sign_key(),
            accounts: log
                .members()
                .iter()
                .map(|member| Account {
                    client_id: member.client_id,
                    root_vk: member.root_vk.clone(),
                })
                .chain(introducer)
                .collect(),
            revoked: state.revocations.all().to_vec(),
            gate_keys,
            dialing: self.book.dialing(),
        })
    }

    fn reference(&self, vault_id: &[u8; 16]) -> Option<Arc<SharedRef>> {
        self.served
            .lock()
            .ok()?
            .iter()
            .find(|known| &known.vault_id == vault_id)
            .cloned()
    }
}

impl Provider for SharedProvider {
    fn views(&self) -> Vec<VaultView> {
        let served = self
            .served
            .lock()
            .map(|list| list.clone())
            .unwrap_or_default();
        let serving = self.personal.lock().is_ok_and(|slot| slot.is_some());
        let personal = serving
            .then(|| personal_view(&self.identity, self.book.dialing()))
            .flatten();
        served
            .iter()
            .filter_map(|reference| self.view_for(reference).ok())
            .chain(personal)
            .collect()
    }

    fn log(&self, vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        let reference = self.reference(vault_id)?;
        let log = read_member_log(&self.base, &reference).ok()?;
        log.entries()
            .iter()
            .map(Entry::encode)
            .collect::<Result<Vec<_>>>()
            .ok()
            .map(|parts| parts.concat())
    }

    fn log_served(&self, vault_id: &[u8; 16], account: &[u8; 64]) {
        let Some(reference) = self.reference(vault_id) else {
            return;
        };
        let (Ok(log), Some(own)) = (
            read_member_log(&self.base, &reference),
            self.identity.devices().first(),
        ) else {
            return;
        };
        if log.role_of(&own.client_id).is_none() && account != &own.client_id {
            if let Ok(mut list) = self.delivered.lock() {
                if !list.contains(vault_id) {
                    list.push(*vault_id);
                }
            }
        }
    }

    fn announce(&self, vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        self.personal_for(vault_id)?.announce()
    }

    fn snapshot_source(&self, vault_id: &[u8; 16]) -> Option<SnapshotSource> {
        if let Some(serve) = self.personal_for(vault_id) {
            return serve.snapshot_source();
        }
        self.with_vault(vault_id, |vault, reference, identity| {
            let attestations = vault.attestations(reference, identity)?;
            let file = std::fs::File::open(&vault.paths.vault_file)?;
            let file_len = u64::try_from(vault.file.as_bytes().len())?;
            Ok(SnapshotSource {
                prefix: encode_snapshot_prefix(&attestations)?,
                file,
                file_len,
            })
        })
        .ok()
    }

    fn frontier(&self, vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        if let Some(serve) = self.personal_for(vault_id) {
            return serve.frontier();
        }
        self.read_vault(vault_id, SharedVault::frontier_wire).ok()
    }

    fn revision(&self, vault_id: &[u8; 16], record_id: u32) -> Option<Vec<u8>> {
        if let Some(serve) = self.personal_for(vault_id) {
            return serve.revision(record_id);
        }
        self.with_vault(vault_id, |vault, reference, identity| {
            vault.bundle(reference, identity, record_id)
        })
        .ok()
        .flatten()
    }

    fn accept_revision(&self, vault_id: &[u8; 16], account: &[u8; 64], bundle: &[u8]) -> Verdict {
        if let Some(serve) = self.personal_for(vault_id) {
            return serve.accept(bundle);
        }
        self.with_vault(vault_id, |vault, reference, _| {
            if vault.log.role_of(account).is_none() {
                return Ok(Verdict::Refused);
            }
            Ok(vault
                .accept(reference, bundle)
                .map_or_else(|error| verdict_of(&error), |_| Verdict::Applied))
        })
        .unwrap_or(Verdict::Refused)
    }

    fn peers(&self, vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        let reference = self.reference(vault_id)?;
        let log = read_member_log(&self.base, &reference).ok()?;
        let cert = self.identity.devices().first()?;
        self.book.list(&log, cert, &self.identity.sign_key()).ok()
    }

    fn accept_peers(&self, vault_id: &[u8; 16], list: &[u8]) -> usize {
        let Some(reference) = self.reference(vault_id) else {
            return 0;
        };
        let (Ok(log), Some(own)) = (
            read_member_log(&self.base, &reference),
            self.identity.devices().first(),
        ) else {
            return 0;
        };
        let kept = self
            .book
            .accept(&log, &own.device_id, &reference.hints, list);
        if kept > 0 {
            self.store_peers(&reference);
        }
        kept
    }

    fn peer_hints(&self, vault_id: &[u8; 16]) -> Vec<String> {
        self.reference(vault_id)
            .and_then(|reference| read_member_log(&self.base, &reference).ok())
            .map(|log| self.book.hints(&log))
            .unwrap_or_default()
    }

    fn needs_snapshot(&self, vault_id: &[u8; 16], rekey: Option<&[u8]>) -> bool {
        let Some(reference) = self.reference(vault_id) else {
            return false;
        };
        let offered_later = rekey
            .and_then(parse_rekey)
            .is_some_and(|(_, epoch)| epoch > reference.epoch);
        offered_later
            || self
                .read_vault(vault_id, |vault| Ok(vault.stale))
                .unwrap_or(false)
    }

    fn merge_log(&self, vault_id: &[u8; 16], log_bytes: &[u8]) -> bool {
        let Some(reference) = self.reference(vault_id) else {
            return false;
        };
        let Ok(_held) = self.node.lock() else {
            return false;
        };
        merge_into_stored_log(&self.base, &reference, log_bytes).is_ok()
    }

    fn rekey(&self, vault_id: &[u8; 16], account: &[u8; 64]) -> Option<Zeroizing<Vec<u8>>> {
        let reference = self.reference(vault_id)?;
        let log = read_member_log(&self.base, &reference).ok()?;
        log.role_of(account)?;
        let mut payload = Zeroizing::new(Vec::with_capacity(68));
        payload.extend_from_slice(reference.seed.expose());
        payload.extend_from_slice(&reference.epoch.to_be_bytes());
        Some(payload)
    }
}

pub fn decode_entries(log_bytes: &[u8]) -> Result<Vec<Entry>> {
    if log_bytes.len() % ENTRY_WIRE_LEN != 0 || log_bytes.len() / ENTRY_WIRE_LEN > MAX_ENTRIES {
        return Err(unavailable());
    }
    log_bytes
        .chunks_exact(ENTRY_WIRE_LEN)
        .map(Entry::decode)
        .collect()
}

/// Verify the peer's entries against the stored log and keep the ones that
/// extend it.
fn merge_into_stored_log(base: &Path, reference: &SharedRef, log_bytes: &[u8]) -> Result<()> {
    let entries = decode_entries(log_bytes)?;
    let mut log = read_member_log(base, reference)?;
    let before = log.entries().len();
    log.merge(&entries)?;
    if log.entries().len() == before {
        return Ok(());
    }
    let key = kdf::shared_members_key(reference.seed.expose(), &reference.vault_id)?;
    save_member_log(
        &shared_paths_for(base, &reference.vault_id).members_log(),
        &key,
        &log,
    )
}
