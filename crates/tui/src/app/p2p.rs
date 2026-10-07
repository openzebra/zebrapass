//! The peer-to-peer node of an unlocked vault: it runs while the vault is
//! unlocked and dies with it, and its events are applied from the tick.
//!
//! It starts only when there is a shared vault to serve, listens only where
//! the user's setting says, and the interface always shows its state.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use local::{Listen, SyncIdentity};
use p2p_net::{finish_join, reachable_hints, Event, FetchError, Joined, Service, SharedProvider};

use crate::app::ctx::Ctx;
use crate::app::flows::home::Filter;
use crate::app::flows::unlocked::Unlocked;
use crate::ui::widgets::toast::Tone;
use crate::vault::records::Summary;
use crate::vault::shared::{references, SharedItem, Status};
use crate::vault::Vault;

/// The port a node tries first, so an invitation stays valid across runs.
const PORT: u16 = 7447;

/// How long an open shared vault goes without trading revisions.
const CHECK_EVERY: Duration = Duration::from_secs(15);

/// The running node and what it signs with. Dropping it stops the node and
/// wipes the identity copy it holds.
pub struct P2p {
    /// The network service.
    pub service: Service,
    /// What the node serves.
    pub provider: Arc<SharedProvider>,
    /// This device's identity.
    pub identity: Arc<SyncIdentity>,
    /// Where it was told to listen.
    pub listen: Listen,
    checked: Instant,
}

impl std::fmt::Debug for P2p {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2p")
            .field("status", &self.service.status())
            .finish_non_exhaustive()
    }
}

impl P2p {
    /// Start a node for `identity` over the shared vaults under `base`.
    #[must_use]
    pub fn start(base: &Path, identity: Arc<SyncIdentity>, listen: Listen) -> Option<Box<Self>> {
        let provider = Arc::new(SharedProvider::new(
            base.to_path_buf(),
            Arc::clone(&identity),
        ));
        let bind = |port: u16| match listen {
            Listen::Off => None,
            Listen::Local => Some(format!("127.0.0.1:{port}")),
            Listen::Lan => Some(format!("0.0.0.0:{port}")),
        };
        let service = Service::start(bind(PORT).as_deref(), Arc::clone(&provider))
            .or_else(|_| Service::start(bind(0).as_deref(), Arc::clone(&provider)))
            .ok()?;
        let node = Box::new(Self {
            service,
            provider,
            identity,
            listen,
            checked: Instant::now(),
        });
        node.provider.set_hints(node.hints());
        Some(node)
    }

    /// Whether it is time to check in with the members again; restarts the
    /// wait when it is.
    pub fn check_due(&mut self) -> bool {
        let due = self.checked.elapsed() >= CHECK_EVERY && self.service.status().fetching == 0;
        if due {
            self.checked = Instant::now();
        }
        due
    }

    /// Where other devices can reach this node; empty when it listens
    /// nowhere.
    #[must_use]
    pub fn hints(&self) -> Vec<String> {
        let Some(port) = self.service.local_addr().map(|addr| addr.port()) else {
            return Vec::new();
        };
        match self.listen {
            Listen::Off => Vec::new(),
            Listen::Local => vec![format!("127.0.0.1:{port}")],
            Listen::Lan => reachable_hints(port),
        }
    }
}

/// What a freshly unlocked personal vault brings up.
pub struct Setup {
    /// This device's sync identity, when the vault has one.
    pub identity: Option<Arc<SyncIdentity>>,
    /// The node, when there is a shared vault to serve.
    pub p2p: Option<Box<P2p>>,
    /// The shared vaults.
    pub shared: Vec<SharedItem>,
}

/// This vault's sync identity. Vaults made before sync existed have none.
#[must_use]
pub fn load_identity(vault: &Vault) -> Option<Arc<SyncIdentity>> {
    let key = vault.session.sync_identity_key().ok()?;
    SyncIdentity::load(&vault.paths.sync_identity(), &key)
        .ok()
        .map(Arc::new)
}

/// The node and shared vaults for a freshly unlocked personal vault. A vault
/// without a sync identity, or without shared vaults, runs no node.
#[must_use]
pub fn setup(vault: &Vault) -> Setup {
    let identity = load_identity(vault);
    let Some(identity) = identity else {
        return Setup {
            identity: None,
            p2p: None,
            shared: Vec::new(),
        };
    };
    let base = &vault.paths.base;
    let shared: Vec<SharedItem> = references(&vault.session)
        .into_iter()
        .map(|reference| SharedItem::open(base, reference, &identity))
        .collect();
    let listen = vault
        .meta
        .prefs
        .as_ref()
        .map_or_else(Listen::default, |prefs| prefs.p2p_listen);
    let p2p = if shared.is_empty() {
        None
    } else {
        P2p::start(base, Arc::clone(&identity), listen)
    };
    if let Some(p2p) = p2p.as_deref() {
        for item in &shared {
            p2p.provider.serve(Arc::clone(&item.reference));
            fetch(p2p, item);
        }
    }
    Setup {
        identity: Some(identity),
        p2p,
        shared,
    }
}

/// Ask the members for a vault: persistently while its file is still
/// missing, once when it is open and this is only a check-in.
pub fn fetch(p2p: &P2p, item: &SharedItem) {
    if item.reference.hints.is_empty() {
        return;
    }
    if let Ok(view) = p2p.provider.view_for(&item.reference) {
        if item.ready() {
            check_in(p2p, item);
        } else {
            p2p.service.fetch(view, item.reference.hints.clone());
        }
    }
}

/// Trade revisions with the members of an open shared vault, once.
pub fn check_in(p2p: &P2p, item: &SharedItem) {
    if !item.ready() {
        return;
    }
    p2p.service.check_in(
        Arc::clone(&p2p.provider),
        item.reference.vault_id,
        item.reference.hints.clone(),
    );
}

const fn reason_text(reason: FetchError) -> &'static str {
    match reason {
        FetchError::Unreachable => "could not be reached",
        FetchError::Refused => "turned this device away",
        FetchError::Failed => "did not answer properly",
    }
}

impl Unlocked {
    /// Where this device's node listens, from the saved setting.
    #[must_use]
    pub fn listen_mode(&self) -> Listen {
        self.info
            .prefs
            .as_ref()
            .map_or_else(Listen::default, |prefs| prefs.p2p_listen)
    }

    /// Start the node if it is not running and the vault has an identity.
    /// Returns whether a node runs afterwards.
    pub fn ensure_p2p(&mut self) -> bool {
        if self.p2p.is_some() {
            return true;
        }
        let Some(identity) = self.identity.clone() else {
            return false;
        };
        self.p2p = P2p::start(&self.base, identity, self.listen_mode());
        if let Some(p2p) = self.p2p.as_deref() {
            for item in &self.shared {
                p2p.provider.serve(Arc::clone(&item.reference));
                fetch(p2p, item);
            }
        }
        self.p2p.is_some()
    }

    /// Stop the node and start it again where the setting now says.
    pub fn restart_p2p(&mut self) {
        self.p2p = None;
        if !self.shared.is_empty() {
            self.ensure_p2p();
        }
    }

    /// Try again to fetch a pending vault, now.
    pub fn retry(&mut self, index: usize) -> bool {
        let Some(item) = self.shared.get_mut(index) else {
            return false;
        };
        if item.ready() {
            return false;
        }
        item.waiting = None;
        item.status = Status::Pending;
        let Some(item) = self.shared.get(index) else {
            return false;
        };
        self.p2p.as_deref().map(|p2p| fetch(p2p, item)).is_some()
    }

    /// The filters, with one entry per shared vault after the usual ones.
    #[must_use]
    pub fn filters(&self) -> Vec<(Filter, usize)> {
        let mut entries =
            crate::app::flows::home::filter_entries(&self.cache, self.health.as_deref());
        entries.extend(self.shared.iter().map(|item| {
            (
                Filter::Shared(item.reference.vault_id, item.name().into()),
                item.cache.len(),
            )
        }));
        entries
    }

    /// The shared vault with this id.
    #[must_use]
    pub fn shared_item(&self, vault_id: &[u8; 16]) -> Option<&SharedItem> {
        self.shared
            .iter()
            .find(|item| &item.reference.vault_id == vault_id)
    }

    /// The records the list shows: the personal vault's, or a shared vault's.
    #[must_use]
    pub fn active_cache(&self) -> &[Summary] {
        match &self.home.filter {
            Filter::Shared(id, _) => self.shared_item(id).map_or(&[][..], |item| &item.cache),
            _ => &self.cache,
        }
    }

    /// Whether the list shows a shared vault.
    #[must_use]
    pub const fn in_shared(&self) -> bool {
        matches!(self.home.filter, Filter::Shared(..))
    }

    /// Apply what the node reports; call every tick. Events wait while a job
    /// holds the vault, because adopting a new seed has to be stored in it.
    pub fn poll_p2p(&mut self, ctx: &mut Ctx) {
        if self.vault.is_none() {
            return;
        }
        self.check_in_due();
        let Some(p2p) = self.p2p.as_ref() else {
            return;
        };
        let events: Vec<Event> = p2p.service.events().try_iter().collect();
        for event in events {
            match event {
                Event::Fetched {
                    vault_id,
                    log,
                    snapshot,
                    rekey,
                } => self.arrived(
                    &vault_id,
                    &log,
                    snapshot,
                    rekey.as_deref().map(Vec::as_slice),
                    ctx,
                ),
                Event::FetchFailed { vault_id, reason } => {
                    if let Some(item) = self
                        .shared
                        .iter_mut()
                        .find(|item| item.reference.vault_id == vault_id)
                    {
                        item.waiting = Some(reason);
                        if !item.ready() {
                            let message = format!("{} {}.", item.name(), reason_text(reason));
                            ctx.toast(Tone::Warn, message);
                        }
                        ctx.redraw();
                    }
                }
                Event::Synced {
                    vault_id,
                    pulled,
                    refused,
                    ..
                } => {
                    if pulled > 0 {
                        self.reload_shared(&vault_id);
                        ctx.toast(Tone::Info, format!("{pulled} updated from the members."));
                    }
                    if refused > 0 {
                        ctx.toast(Tone::Warn, "A member sent changes that were refused.");
                    }
                    if let Some(item) = self
                        .shared
                        .iter_mut()
                        .find(|item| item.reference.vault_id == vault_id)
                    {
                        item.waiting = None;
                    }
                    ctx.redraw();
                }
                Event::PeerConnected { .. } | Event::PeerGone { .. } => ctx.redraw(),
                Event::Listening(_) => {}
            }
        }
    }

    fn arrived(
        &mut self,
        vault_id: &[u8; 16],
        log: &[u8],
        snapshot: Vec<u8>,
        rekey: Option<&[u8]>,
        ctx: &mut Ctx,
    ) {
        let Some(p2p) = self.p2p.as_ref() else {
            return;
        };
        let identity = Arc::clone(&p2p.identity);
        let base: PathBuf = self.base.clone();
        let Some(index) = self
            .shared
            .iter()
            .position(|item| &item.reference.vault_id == vault_id)
        else {
            return;
        };
        let Some(item) = self.shared.get(index) else {
            return;
        };
        let (name, was_ready) = (item.name().to_owned(), item.ready());
        let joined = finish_join(
            &base,
            &item.reference,
            &identity,
            log,
            snapshot,
            rekey,
            item.known(),
        );
        match joined {
            Ok(Joined::Opened(vault)) => {
                if let Some(item) = self.shared.get_mut(index) {
                    item.adopt(*vault);
                    let message = format!("{name} is synced: {} records.", item.cache.len());
                    ctx.toast(Tone::Success, message);
                }
            }
            Ok(Joined::Rekey(plan)) => self.take_new_key(index, *plan, ctx),
            Ok(Joined::Unchanged) => {
                if let Some(item) = self.shared.get_mut(index) {
                    item.waiting = None;
                }
            }
            Err(_) if was_ready => {
                let message = format!("An update for {name} did not verify and was ignored.");
                ctx.toast(Tone::Warn, message);
            }
            Err(_) => {
                if let Some(item) = self.shared.get_mut(index) {
                    item.status = Status::Unavailable;
                }
                let message = format!("{name} did not verify and was not opened.");
                ctx.toast(Tone::Danger, message);
            }
        }
        ctx.redraw();
    }

    /// An owner replaced the vault's seed and this member got it: store the
    /// new reference first, then move the files. A crash between the two
    /// leaves files that still open through the retired seed.
    fn take_new_key(&mut self, index: usize, plan: local::RekeyPlan, ctx: &mut Ctx) {
        let reference = Arc::new(plan.reference().duplicate());
        if !self.save_reference(&reference) {
            ctx.toast(Tone::Danger, "Could not store the new key. Try again.");
            return;
        }
        let Ok(vault) = plan.commit() else {
            if let Some(item) = self.shared.get_mut(index) {
                item.status = Status::Unavailable;
            }
            ctx.toast(Tone::Danger, "The vault could not be updated.");
            return;
        };
        if let Some(p2p) = self.p2p.as_deref() {
            p2p.provider.serve(Arc::clone(&reference));
        }
        if let Some(item) = self.shared.get_mut(index) {
            item.reference = reference;
            item.adopt(vault);
            let message = format!("{} has a new key from its owner.", item.name());
            ctx.toast(Tone::Success, message);
        }
    }

    /// Write `reference` over the record that points at this shared vault in
    /// the personal vault, now. Returns whether it was stored.
    pub fn save_reference(&mut self, reference: &local::SharedRef) -> bool {
        let Some(vault) = self.vault.as_deref_mut() else {
            return false;
        };
        let Some(id) = session::list_records(&vault.session)
            .unwrap_or_default()
            .iter()
            .find(|row| {
                session::open_record(&vault.session, row.id)
                    .ok()
                    .and_then(|doc| local::SharedRef::from_document(&doc).ok().flatten())
                    .is_some_and(|known| known.vault_id == reference.vault_id)
            })
            .map(|row| row.id)
        else {
            return false;
        };
        session::write_record(
            &mut vault.session,
            &mut vault.file,
            Some(id),
            &reference.to_document(),
        )
        .is_ok()
            && vault.persist().is_ok()
    }
}
