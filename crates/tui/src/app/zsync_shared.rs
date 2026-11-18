//! Shared vault `zsync` reconciliation and auto-discovery of newly synced
//! [`local::SharedRef`] entries from the personal vault.

use std::sync::Arc;

use local::{SharedRef, SharedVault, SyncIdentity};
use session::{Session, VaultFile};
use syncwire::encode_snapshot;
use zsync::{PulledShared, SharedStateInput, shared_wraps_tag};

use crate::app::ctx::Ctx;
use crate::app::flows::unlocked::Unlocked;
use crate::app::zsync::{ZSyncMsg, ZebraSync};
use crate::ui::widgets::toast::Tone;
use crate::vault::Vault;
use crate::vault::create::unix_ms;
use crate::vault::device;
use crate::vault::shared::{SharedItem, references};

struct OwnedSharedInput {
    reference: Arc<SharedRef>,
    member_entries: Vec<Vec<u8>>,
    snapshot_bytes: Option<Vec<u8>>,
    generation: u64,
    head_epoch: u64,
    bundles: Vec<(u32, u64, [u8; 16], Vec<u8>)>,
    rekeys: Vec<(u64, Vec<u8>)>,
}

impl ZebraSync {
    /// Reconcile a single [`SharedItem`] (pending or ready) with the cluster.
    pub fn trigger_reconcile_shared(&self, item: &mut SharedItem) {
        let vault_id = item.reference.vault_id;
        let known_epoch = self.shared_epochs.get(&vault_id).copied().unwrap_or(0);
        let reference = Arc::clone(&item.reference);
        let owned = match &mut item.status {
            crate::vault::shared::Status::Ready(sv) => {
                build_owned_shared(&reference, sv, &self.identity, known_epoch)
            }
            crate::vault::shared::Status::Pending | crate::vault::shared::Status::Unavailable => {
                OwnedSharedInput {
                    reference,
                    member_entries: Vec::new(),
                    snapshot_bytes: None,
                    generation: 0,
                    head_epoch: known_epoch,
                    bundles: Vec::new(),
                    rekeys: Vec::new(),
                }
            }
        };
        self.spawn_shared_reconcile(owned);
    }

    fn spawn_shared_reconcile(&self, owned: OwnedSharedInput) {
        let client = Arc::clone(&self.client);
        let identity = Arc::clone(&self.identity);
        let tx = self.msg_tx.clone();
        self.rt.spawn(async move {
            let vault_id = owned.reference.vault_id;
            let input = SharedStateInput {
                shared_seed: owned.reference.seed.expose(),
                vault_id,
                anchor: owned.reference.anchor,
                member_entries: &owned.member_entries,
                snapshot_bytes: owned.snapshot_bytes.as_deref(),
                generation: owned.generation,
                head_epoch: owned.head_epoch,
                bundles: &owned.bundles,
                rekeys: &owned.rekeys,
            };
            match client.reconcile_shared(&identity, input).await {
                Ok(pulled) => {
                    let _ = tx.send(ZSyncMsg::SharedReconciled { vault_id, pulled });
                }
                Err(err) => {
                    let _ = tx.send(ZSyncMsg::Error(err.to_string()));
                }
            }
        });
    }
}

fn build_owned_shared(
    reference: &Arc<SharedRef>,
    sv: &mut SharedVault,
    identity: &local::SyncIdentity,
    known_epoch: u64,
) -> OwnedSharedInput {
    let member_entries = sv
        .log
        .entries()
        .iter()
        .filter_map(|e| e.encode().ok())
        .collect();
    let snapshot_bytes = if sv
        .role_of(identity)
        .is_some_and(memberlog::Role::can_manage)
    {
        sv.attestations(reference, identity)
            .ok()
            .and_then(|att| encode_snapshot(sv.file.as_bytes(), &att).ok())
    } else {
        None
    };
    let mut bundles = Vec::new();
    for row in session::list_records(&sv.session).unwrap_or_default() {
        if let Ok(Some(bundle)) = sv.bundle(reference, identity, row.id)
            && let Ok(raw) = session::latest_frame(&sv.session, row.id)
            && let Ok(hdr) = frame::parse(&raw)
        {
            bundles.push((row.id, hdr.revision, hdr.origin_device, bundle));
        }
    }
    let generation = sv.session.generation();
    OwnedSharedInput {
        reference: Arc::clone(reference),
        member_entries,
        snapshot_bytes,
        generation,
        head_epoch: known_epoch.max(generation),
        bundles,
        rekeys: Vec::new(),
    }
}

impl Unlocked {
    /// Refresh watched repos or restart `zsync` if configured endpoints changed.
    pub fn refresh_zsync(&mut self, ctx: &Ctx) {
        let Some(vault) = self.vault.as_deref() else {
            return;
        };
        let desired =
            crate::app::zsync::resolve_sync_servers(vault.meta.prefs.as_ref(), ctx, &self.shared);
        if let Some(zsync) = self.zsync.as_deref() {
            if desired.iter().all(|u| zsync.endpoints.contains(u)) {
                zsync.update_watched(&self.shared);
            } else {
                self.restart_zsync(ctx);
            }
        } else if !desired.is_empty() {
            self.start_zsync(ctx);
        }
    }

    /// Reconcile one shared vault snapshot, membership log, and all record
    /// bundles after a write or membership change.
    pub fn sync_push_shared_full(&mut self, vault_id: &[u8; 16]) {
        let Some(zsync) = self.zsync.as_deref_mut() else {
            return;
        };
        let Some(item) = self
            .shared
            .iter_mut()
            .find(|item| &item.reference.vault_id == vault_id)
        else {
            return;
        };
        let reference = Arc::clone(&item.reference);
        if let crate::vault::shared::Status::Ready(sv) = &mut item.status {
            let prev = zsync.shared_epochs.get(vault_id).copied().unwrap_or(0);
            let known_wrap = zsync.shared_wraps.get(vault_id).copied();
            let mut owned = build_owned_shared(&reference, sv, &zsync.identity, prev);
            if let Some(snap) = owned.snapshot_bytes.as_deref()
                && let Ok(wtag) = shared_wraps_tag(snap)
            {
                let changed = known_wrap.is_none_or(|kw| kw != wtag);
                if changed || sv.session.generation() >= owned.head_epoch {
                    let next_epoch = prev.max(sv.session.generation()).saturating_add(1);
                    owned.head_epoch = next_epoch;
                    zsync.shared_epochs.insert(*vault_id, next_epoch);
                }
                zsync.shared_wraps.insert(*vault_id, wtag);
            }
            zsync.spawn_shared_reconcile(owned);
        } else {
            zsync.trigger_reconcile_shared(item);
        }
    }

    /// Reconcile a shared vault after one record edit (delta-only unless wraps changed).
    pub fn sync_push_shared_record(&mut self, vault_id: &[u8; 16], _record_id: u32) {
        let Some(zsync) = self.zsync.as_deref_mut() else {
            return;
        };
        let Some(item) = self
            .shared
            .iter_mut()
            .find(|item| &item.reference.vault_id == vault_id)
        else {
            return;
        };
        let reference = Arc::clone(&item.reference);
        if let crate::vault::shared::Status::Ready(sv) = &mut item.status {
            let known_epoch = zsync.shared_epochs.get(vault_id).copied().unwrap_or(0);
            let known_wrap = zsync.shared_wraps.get(vault_id).copied();
            let mut owned = build_owned_shared(&reference, sv, &zsync.identity, known_epoch);
            if let Some(snap) = owned.snapshot_bytes.as_deref()
                && let Ok(wtag) = shared_wraps_tag(snap)
                && known_wrap.is_none_or(|kw| kw != wtag)
            {
                let next_epoch = known_epoch.max(sv.session.generation()).saturating_add(1);
                owned.head_epoch = next_epoch;
                zsync.shared_epochs.insert(*vault_id, next_epoch);
                zsync.shared_wraps.insert(*vault_id, wtag);
            } else if known_epoch > 0 {
                owned.head_epoch = known_epoch;
            }
            zsync.spawn_shared_reconcile(owned);
        }
    }

    /// Discover any [`local::SharedRef`] records synced into the personal vault
    /// that are not yet tracked in `self.shared`, open/queue them, and trigger
    /// cluster sync.
    pub fn discover_new_shared_refs(&mut self, ctx: &Ctx) {
        let (Some(vault), Some(identity)) = (self.vault.as_deref(), self.identity.clone()) else {
            return;
        };
        let refs = references(&vault.session);
        let mut added = Vec::new();
        for reference in refs {
            if !self
                .shared
                .iter()
                .any(|item| item.reference.vault_id == reference.vault_id)
            {
                let item = SharedItem::open(&self.base, Arc::clone(&reference), &identity);
                if let Some(p2p) = self.p2p.as_deref() {
                    p2p.provider.serve(Arc::clone(&reference));
                    crate::app::p2p::fetch(p2p, &item);
                }
                self.shared.push(item);
                added.push(reference);
            }
        }
        if added.is_empty() {
            return;
        }
        self.refresh_zsync(ctx);
        if let Some(zsync) = self.zsync.as_deref() {
            for reference in &added {
                if let Some(item) = self
                    .shared
                    .iter_mut()
                    .find(|i| i.reference.vault_id == reference.vault_id)
                {
                    zsync.trigger_reconcile_shared(item);
                }
            }
        }
    }

    pub(crate) fn apply_zsync_shared(
        &mut self,
        vault_id: [u8; 16],
        pulled: PulledShared,
        ctx: &mut Ctx,
    ) {
        if let Some(zsync) = self.zsync.as_deref_mut() {
            let prev = zsync.shared_epochs.get(&vault_id).copied().unwrap_or(0);
            zsync
                .shared_epochs
                .insert(vault_id, prev.max(pulled.head_epoch));
            if let Some((snap_bytes, _)) = &pulled.snapshot
                && let Ok(wtag) = shared_wraps_tag(snap_bytes)
            {
                zsync.shared_wraps.insert(vault_id, wtag);
            }
            zsync.last_sync_ms = Some(unix_ms());
        }
        let Some(index) = self
            .shared
            .iter()
            .position(|item| item.reference.vault_id == vault_id)
        else {
            return;
        };
        let mut log_wire =
            Vec::with_capacity(pulled.member_entries.len() * memberlog::ENTRY_WIRE_LEN);
        for entry in &pulled.member_entries {
            if let Ok(enc) = entry.encode() {
                log_wire.extend_from_slice(&enc);
            }
        }
        let was_ready = self.shared.get(index).is_some_and(SharedItem::ready);
        if let Some((snap_bytes, snap_epoch)) = pulled.snapshot {
            let known = self
                .zsync
                .as_deref()
                .and_then(|z| z.shared_epochs.get(&vault_id).copied())
                .unwrap_or(0);
            if !was_ready || snap_epoch >= known {
                self.arrived(&vault_id, &log_wire, snap_bytes.to_vec(), None, ctx);
            }
        }

        let mut applied = 0usize;
        let mut members_changed = false;
        if let Some(item) = self.shared.get_mut(index) {
            let reference = Arc::clone(&item.reference);
            if let Some(sv) = item.vault_mut() {
                let before = sv.log.entries().len();
                if sv.log.merge(&pulled.member_entries).is_ok() && sv.log.entries().len() > before {
                    let _ = sv.save_log(&reference.seed);
                    members_changed = true;
                }
                for bundle in &pulled.bundles {
                    if sv.accept(&reference, bundle).is_ok() {
                        applied = applied.saturating_add(1);
                    }
                }
            }
        }
        if applied > 0 || members_changed {
            self.reload_shared(&vault_id);
            if applied > 0 {
                ctx.toast(Tone::Info, format!("{applied} updated in shared vault."));
            }
            ctx.redraw();
        }
    }
}

pub(super) fn merge_local_records_into(
    old_sess: &Session,
    new_sess: &mut Session,
    new_file: &mut VaultFile,
) -> bool {
    let mut merged = false;
    let remote_rows = session::list_records(new_sess).unwrap_or_default();
    for local_row in session::list_records(old_sess).unwrap_or_default() {
        let local_key = session::latest_frame(old_sess, local_row.id)
            .ok()
            .and_then(|raw| frame::parse(&raw).ok())
            .map(|h| (h.revision, h.origin_device));
        let remote_key = remote_rows
            .iter()
            .find(|r| r.id == local_row.id)
            .and_then(|r| session::latest_frame(new_sess, r.id).ok())
            .and_then(|raw| frame::parse(&raw).ok())
            .map(|h| (h.revision, h.origin_device));
        let keep_local = match (local_key, remote_key) {
            (Some(lk), Some(rk)) => lk > rk,
            (Some(_), None) => true,
            _ => false,
        };
        if keep_local
            && let Ok(doc) = session::open_record(old_sess, local_row.id)
            && session::write_record(new_sess, new_file, Some(local_row.id), &doc).is_ok()
        {
            merged = true;
        }
    }
    merged
}

pub(super) fn preserve_local_chip_wrap(
    old_vault: &Vault,
    identity: &SyncIdentity,
    new_session: &mut Session,
    new_file: &mut VaultFile,
) -> bool {
    let Some(owned) = device::owned_id(&old_vault.paths) else {
        return false;
    };
    if identity
        .devices()
        .first()
        .is_some_and(|own| identity.revocations().is_revoked(own))
    {
        return false;
    }
    let already_present = session::wrap_directory(new_file).is_ok_and(|dir| {
        dir.factors
            .iter()
            .any(|f| matches!(f, session::Factor::Chip(c) if c.publics.id == owned))
    });
    if already_present {
        return false;
    }
    let local_publics = session::wrap_directory(&old_vault.file)
        .ok()
        .and_then(|dir| {
            dir.factors.into_iter().find_map(|f| match f {
                session::Factor::Chip(c) if c.publics.id == owned => Some(c.publics),
                session::Factor::Chip(_)
                | session::Factor::Recovery
                | session::Factor::Password { .. }
                | session::Factor::Prf { .. } => None,
            })
        });
    local_publics.is_some_and(|pubs| session::add_chip_unlock(new_session, new_file, &pubs).is_ok())
}
