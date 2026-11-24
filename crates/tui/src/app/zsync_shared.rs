//! Shared vault `zsync` reconciliation, hybrid PQ member-removal rekeying,
//! and auto-discovery of newly synced [`local::SharedRef`] entries.

use std::sync::Arc;

use local::{Attested, SharedRef, SharedVault, prepare_rekey};
use memberlog::Entry;
use session::VaultFile;
use syncwire::{decode_snapshot, encode_snapshot};
use zsync::{PulledShared, SharedStateInput, shared_wraps_tag};

use crate::app::ctx::Ctx;
use crate::app::flows::unlocked::Unlocked;
use crate::app::zsync::{ZSyncMsg, ZebraSync};
use crate::app::zsync_merge::{SeedAdvance, SharedRekeySlice, evaluate_shared_seed_advance};
use crate::ui::widgets::toast::Tone;
use crate::vault::create::unix_ms;
use crate::vault::shared::{SharedItem, references};

struct OwnedSharedInput {
    reference: Arc<SharedRef>,
    rotate_to: Option<Arc<SharedRef>>,
    member_entries: Vec<Vec<u8>>,
    snapshot_bytes: Option<Vec<u8>>,
    generation: u64,
    head_epoch: u64,
    bundles: Vec<(u32, u64, [u8; 16], Vec<u8>)>,
    rekeys: Vec<(u64, [u8; 16], Vec<u8>)>,
}

impl ZebraSync {
    /// Reconcile a single [`SharedItem`] (pending, stale, or ready) with the cluster.
    pub fn trigger_reconcile_shared(&self, item: &mut SharedItem) {
        if item.my_role.is_none() && item.ready() {
            return;
        }
        let vault_id = item.reference.vault_id;
        let known_epoch = self.shared_epochs.get(&vault_id).copied().unwrap_or(0);
        let reference = Arc::clone(&item.reference);
        let owned = match (&mut item.status, item.stale) {
            (crate::vault::shared::Status::Ready(sv), false) => {
                build_owned_shared(&reference, sv, &self.identity, known_epoch)
            }
            _ => OwnedSharedInput {
                reference,
                rotate_to: None,
                member_entries: Vec::new(),
                snapshot_bytes: None,
                generation: 0,
                head_epoch: known_epoch,
                bundles: Vec::new(),
                rekeys: Vec::new(),
            },
        };
        self.spawn_shared_reconcile(owned);
    }

    /// Publish an updated `MemberLog` (removal/rotation) and per-device hybrid
    /// PQ `SignedRekey` grants to the retired `sid_0` repository so remaining
    /// members receive the new seed and removed members are immediately cut off.
    pub fn push_shared_rekey_notice(
        &self,
        old_ref: Arc<SharedRef>,
        new_ref: Arc<SharedRef>,
        member_entries: Vec<Vec<u8>>,
        rekeys: Vec<(u64, [u8; 16], Vec<u8>)>,
    ) {
        self.spawn_shared_reconcile(OwnedSharedInput {
            reference: old_ref,
            rotate_to: Some(new_ref),
            member_entries,
            snapshot_bytes: None,
            generation: 0,
            head_epoch: 0,
            bundles: Vec::new(),
            rekeys,
        });
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
                rotate_to: owned.rotate_to.as_ref().map(|r| (&r.seed, r.epoch)),
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

    fn ingest_pulled_shared(&mut self, vault_id: [u8; 16], pulled: &mut PulledShared) -> u64 {
        let prev = self.shared_epochs.get(&vault_id).copied().unwrap_or(0);
        self.shared_epochs
            .insert(vault_id, prev.max(pulled.head_epoch));
        if let Some((snap_bytes, _)) = &pulled.snapshot
            && let Ok(wtag) = shared_wraps_tag(snap_bytes)
        {
            self.shared_wraps.insert(vault_id, wtag);
        }
        let own_dev = self.identity.device_id();
        let slot = self.shared_member_devices.entry(vault_id).or_default();
        for dev in std::mem::take(&mut pulled.member_devices) {
            if Some(dev.cert.device_id) != own_dev {
                slot.retain(|d| d.cert.device_id != dev.cert.device_id);
                slot.push(dev);
            }
        }
        self.last_sync_ms = Some(unix_ms());
        prev
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
    for entry in session::frontier(&sv.session).unwrap_or_default() {
        if let Ok(Some(bundle)) = sv.bundle(reference, identity, entry.record_id) {
            bundles.push((entry.record_id, entry.revision, entry.origin_device, bundle));
        }
    }
    let generation = sv.session.generation();
    OwnedSharedInput {
        reference: Arc::clone(reference),
        rotate_to: None,
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
        if let (crate::vault::shared::Status::Ready(sv), false) = (&mut item.status, item.stale) {
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
        if item.stale {
            return;
        }
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
        mut pulled: PulledShared,
        ctx: &mut Ctx,
    ) {
        let prev_epoch = self
            .zsync
            .as_deref_mut()
            .map_or(0, |zs| zs.ingest_pulled_shared(vault_id, &mut pulled));

        if self.try_advance_shared_seed(vault_id, &pulled.member_entries, &pulled.rekeys, ctx) {
            return;
        }

        let Some(index) = self
            .shared
            .iter()
            .position(|item| item.reference.vault_id == vault_id)
        else {
            return;
        };
        let (was_ready, is_stale) = self
            .shared
            .get(index)
            .map_or((false, false), |item| (item.ready(), item.stale));

        if let Some((snap_bytes, snap_epoch)) = pulled.snapshot {
            if is_stale {
                if let (Some(identity), Some(reference)) = (
                    self.identity.clone(),
                    self.shared.get(index).map(|i| Arc::clone(&i.reference)),
                ) && let Ok((file, attestations)) = decode_snapshot(snap_bytes.to_vec())
                    && let Ok(plan) = prepare_rekey(
                        &self.base,
                        &reference,
                        reference.duplicate(),
                        Attested {
                            file: VaultFile::new(file),
                            attestations: &attestations,
                        },
                        &identity,
                        &pulled.member_entries,
                        None,
                    )
                {
                    self.take_new_key(index, plan, ctx);
                }
            } else if !was_ready || snap_epoch > prev_epoch {
                let mut log_wire =
                    Vec::with_capacity(pulled.member_entries.len() * memberlog::ENTRY_WIRE_LEN);
                for entry in &pulled.member_entries {
                    if let Ok(enc) = entry.encode() {
                        log_wire.extend_from_slice(&enc);
                    }
                }
                self.arrived(&vault_id, &log_wire, snap_bytes.to_vec(), None, ctx);
            }
        }

        let mut applied = 0usize;
        let mut members_changed = false;
        if let Some(item) = self.shared.get_mut(index)
            && !item.stale
        {
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
            if let Some(zsync) = self.zsync.as_deref() {
                zsync.update_watched(&self.shared);
            }
            if applied > 0 {
                ctx.toast(Tone::Info, format!("{applied} updated in shared vault."));
            }
            ctx.redraw();
        }
    }

    fn try_advance_shared_seed(
        &mut self,
        vault_id: [u8; 16],
        entries: &[Entry],
        rekeys: SharedRekeySlice<'_>,
        ctx: &mut Ctx,
    ) -> bool {
        let Some(identity) = self.identity.clone() else {
            return false;
        };
        let Some(index) = self
            .shared
            .iter()
            .position(|item| item.reference.vault_id == vault_id)
        else {
            return false;
        };
        let advance = match self.shared.get(index) {
            Some(item) => {
                evaluate_shared_seed_advance(&self.base, item, &identity, entries, rekeys)
            }
            None => return false,
        };
        match advance {
            SeedAdvance::None => false,
            SeedAdvance::Removed => {
                if let Some(item) = self.shared.get_mut(index) {
                    let reference = Arc::clone(&item.reference);
                    if let Some(sv) = item.vault_mut()
                        && sv.log.merge(entries).is_ok()
                    {
                        let _ = sv.save_log(&reference.seed);
                    }
                }
                self.reload_shared(&vault_id);
                if let Some(zsync) = self.zsync.as_deref() {
                    zsync.update_watched(&self.shared);
                }
                ctx.redraw();
                true
            }
            SeedAdvance::Rotated(seed, target_epoch) => {
                let Some(next_ref) = self
                    .shared
                    .get(index)
                    .map(|item| Arc::new(item.reference.rotated(seed, target_epoch)))
                else {
                    return false;
                };
                if !self.save_reference(&next_ref) {
                    return false;
                }
                if let Some(item) = self.shared.get_mut(index) {
                    if item.ready() {
                        item.stale = true;
                        if let Some(sv) = item.vault_mut() {
                            sv.stale = true;
                        }
                    }
                    item.reference = Arc::clone(&next_ref);
                }
                if let Some(p2p) = self.p2p.as_deref() {
                    p2p.provider.serve(Arc::clone(&next_ref));
                }
                if let Some(zsync) = self.zsync.as_deref_mut() {
                    zsync.shared_epochs.remove(&vault_id);
                    zsync.shared_wraps.remove(&vault_id);
                    zsync.update_watched(&self.shared);
                    if let Some(item) = self.shared.get_mut(index) {
                        zsync.trigger_reconcile_shared(item);
                    }
                }
                self.sync_push_personal(None);
                true
            }
        }
    }
}
