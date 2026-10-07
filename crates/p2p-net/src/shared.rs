//! Serving and joining shared vaults from the files `local` keeps.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use local::{
    adopt_shared_file, is_pending, load_peers, open_shared_vault, prepare_rekey, read_member_log,
    read_shared_state, save_member_log, save_peers, shared_paths_for, verdict_of, Attested,
    RekeyPlan, SharedRef, SharedVault, SyncIdentity, Verdict,
};
use memberlog::{Entry, ENTRY_WIRE_LEN, MAX_ENTRIES};
use p2p_core::Account;
use secret::Secret;
use session::VaultFile;
use syncwire::{decode_snapshot, encode_peers, encode_snapshot};
use zeroize::Zeroizing;

use crate::view::{Provider, VaultView};

fn unavailable() -> anyhow::Error {
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
        }
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
        served
            .iter()
            .filter_map(|reference| self.view_for(reference).ok())
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

    fn snapshot(&self, vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        self.with_vault(vault_id, |vault, reference, identity| {
            let attestations = vault.attestations(reference, identity)?;
            encode_snapshot(vault.file.as_bytes(), &attestations)
        })
        .ok()
    }

    fn frontier(&self, vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        self.with_vault(vault_id, |vault, _, _| vault.frontier_wire())
            .ok()
    }

    fn revision(&self, vault_id: &[u8; 16], record_id: u32) -> Option<Vec<u8>> {
        self.with_vault(vault_id, |vault, reference, identity| {
            vault.bundle(reference, identity, record_id)
        })
        .ok()
        .flatten()
    }

    fn accept_revision(&self, vault_id: &[u8; 16], account: &[u8; 64], bundle: &[u8]) -> Verdict {
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
                .with_vault(vault_id, |vault, _, _| Ok(vault.stale))
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

fn decode_entries(log_bytes: &[u8]) -> Result<Vec<Entry>> {
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

/// What finishing a fetch produced.
pub enum Joined {
    /// A device that was waiting for its first file now has the vault.
    Opened(Box<SharedVault>),
    /// A new seed was offered and everything checked out, but nothing is
    /// written yet. Store [`RekeyPlan::reference`] in the personal vault,
    /// then [`RekeyPlan::commit`].
    Rekey(Box<RekeyPlan>),
    /// The vault was already open and nothing in the fetch replaces it.
    Unchanged,
}

impl std::fmt::Debug for Joined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Opened(_) => "Opened",
            Self::Rekey(_) => "Rekey",
            Self::Unchanged => "Unchanged",
        })
    }
}

/// What a device already knows about the vault it is fetching.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Known {
    /// Generation of the vault file it has.
    pub generation: u64,
    /// The file only opens with a retired seed: a rotation reached the
    /// reference but not the files.
    pub stale: bool,
}

/// A seed and epoch as a peer offers them.
fn parse_rekey(bytes: &[u8]) -> Option<(Secret<[u8; 64]>, u32)> {
    let (seed, epoch) = bytes.split_first_chunk::<64>()?;
    let epoch = u32::from_be_bytes(<[u8; 4]>::try_from(epoch).ok()?);
    let mut secret = Secret::new([0u8; 64]);
    secret.expose_mut().copy_from_slice(seed);
    Some((secret, epoch))
}

/// Finish a fetch from what a member sent: its member log, its vault file,
/// and the seed it offered, if any.
///
/// A seed from a later epoch is taken only if the log (every new entry
/// verified) reached that epoch and the seed hashes to the owner-signed
/// commitment; the file must open with it. The same seed is taken again when
/// the open vault is stale, which finishes a rotation that was cut short.
/// Otherwise a device still waiting for its first file adopts it, and one
/// that already has a vault keeps it. `known` is `None` while pending.
///
/// # Errors
///
/// `shared vault unavailable` for any failed check: a log that does not
/// extend the stored one, a vault whose log no longer lists this account, a
/// seed that does not match its commitment, or a file that is not the vault;
/// storage and key-derivation errors.
pub fn finish_join(
    base: &Path,
    reference: &SharedRef,
    identity: &SyncIdentity,
    log_bytes: &[u8],
    snapshot: Vec<u8>,
    rekey: Option<&[u8]>,
    known: Option<Known>,
) -> Result<Joined> {
    let entries = decode_entries(log_bytes)?;
    let floor = known.map(|known| known.generation);
    let target = rekey.and_then(parse_rekey).and_then(|(seed, epoch)| {
        if epoch > reference.epoch {
            Some(reference.rotated(seed, epoch))
        } else if epoch == reference.epoch
            && known.is_some_and(|known| known.stale)
            && seed.expose() == reference.seed.expose()
        {
            Some(reference.duplicate())
        } else {
            None
        }
    });
    if let Some(next) = target {
        let (file, attestations) = decode_snapshot(snapshot)?;
        let plan = prepare_rekey(
            base,
            reference,
            next,
            Attested {
                file: VaultFile::new(file),
                attestations: &attestations,
            },
            identity,
            &entries,
            floor,
        )?;
        return Ok(Joined::Rekey(Box::new(plan)));
    }
    if known.is_some() {
        return Ok(Joined::Unchanged);
    }
    let (file, attestations) = decode_snapshot(snapshot)?;
    let paths = shared_paths_for(base, &reference.vault_id);
    let key = kdf::shared_members_key(reference.seed.expose(), &reference.vault_id)?;
    let mut log = read_member_log(base, reference)?;
    log.merge(&entries)?;
    let own = identity.devices().first().ok_or_else(unavailable)?;
    let introduced = reference
        .introduction
        .as_ref()
        .is_none_or(|intro| intro.confirms(&log));
    if log.role_of(&own.client_id).is_none() || !introduced {
        return Err(unavailable());
    }
    save_member_log(&paths.members_log(), &key, &log)?;
    let vault = adopt_shared_file(
        base,
        reference,
        VaultFile::new(file),
        &attestations,
        identity,
    )?;
    Ok(Joined::Opened(Box::new(vault)))
}
