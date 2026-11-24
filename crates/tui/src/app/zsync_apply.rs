//! Apply pulled `zsync` personal vault deltas, snapshots, hybrid PQ `VK`
//! rekeys, device announcements, revocations, and local rolling backups.

use std::path::Path;
use std::sync::Arc;

use local::{
    PERSONAL_DEVICE_MAGIC, PersonalDeviceEntry, SyncIdentity, save_master_grant,
    seal_personal_rekey, write_rolling_backup,
};
use secret::Secret;
use zeroize::Zeroizing;
use zsync::{PulledPersonal, RepoKind, WorkerEvent, wraps_tag};

use crate::app::ctx::Ctx;
use crate::app::flows::info::VaultInfo;
use crate::app::flows::unlocked::Unlocked;
use crate::app::zsync::{PersonalQueue, ZSyncMsg, ZebraSync};
use crate::app::zsync_merge::{SnapshotOutcome, try_apply_snapshot_to_vault};
use crate::ui::widgets::toast::Tone;
use crate::vault::create::unix_ms;
use crate::vault::factors::presence;
use crate::vault::ops::FactorRef;

impl Unlocked {
    /// Start background `zsync` worker and client if server sync is enabled.
    pub fn start_zsync(&mut self, ctx: &Ctx) {
        if self.zsync.is_some() {
            return;
        }
        let (Some(vault), Some(identity)) = (self.vault.as_deref(), self.identity.as_ref()) else {
            return;
        };
        self.zsync = ZebraSync::start(vault, Arc::clone(identity), &self.shared, ctx);
        if let Some(zsync) = self.zsync.as_deref() {
            for item in &mut self.shared {
                zsync.trigger_reconcile_shared(item);
            }
        }
    }

    /// Restart background `zsync` after sync settings or server list change.
    pub fn restart_zsync(&mut self, ctx: &Ctx) {
        self.zsync = None;
        self.start_zsync(ctx);
    }

    /// Push a personal vault mutation to `zsync` servers and update rolling
    /// local backups when configured.
    pub fn sync_push_personal(&mut self, _record_id: Option<u32>) {
        let Some(vault) = self.vault.as_deref() else {
            return;
        };
        if let Some(prefs) = self.info.prefs.as_ref()
            && let Some(dir) = prefs.backup_dir.as_deref()
            && prefs.backup_keep > 0
        {
            let _ = write_rolling_backup(
                &self.base,
                &vault.session,
                &vault.file,
                &vault.meta.name,
                Path::new(dir),
                prefs.backup_keep,
            );
        }
        if let Some(zsync) = self.zsync.as_deref_mut() {
            zsync.trigger_reconcile_personal(vault, false, false);
        }
    }

    /// Publish device revocation (when revoking a peer device), hybrid PQ `VK`
    /// rekey grants for every remaining non-revoked peer device, and the rotated
    /// snapshot.
    pub fn sync_push_personal_rotation(&mut self, revoked: Option<FactorRef>) {
        let Some(vault) = self.vault.as_deref() else {
            return;
        };
        let Ok(id_key) = vault.session.sync_identity_key() else {
            return;
        };
        if let Ok(mut fresh_id) = SyncIdentity::load(&vault.paths.sync_identity(), &id_key) {
            if let Some(FactorRef::Device(wrap_id)) = revoked
                && let Some(zsync) = self.zsync.as_deref()
                && let Some(target) = zsync
                    .peer_devices
                    .iter()
                    .find(|peer| peer.wrap_id == Some(wrap_id))
                    .map(|peer| peer.cert.clone())
                && fresh_id.revoke_device(&target, unix_ms()).is_ok()
            {
                let _ = fresh_id.save(&vault.paths.sync_identity(), &id_key);
            }
            let arc_id = Arc::new(fresh_id);
            self.identity = Some(Arc::clone(&arc_id));
            if let Some(zsync) = self.zsync.as_deref_mut() {
                zsync.identity = arc_id;
            }
        }
        if let Some(zsync) = self.zsync.as_deref_mut() {
            let vk = vault.session.reopen_key();
            let generation = vault.session.generation();
            let vault_id = vault.session.vault_id();
            for peer in &zsync.peer_devices {
                if zsync.identity.revocations().is_revoked(&peer.cert) {
                    continue;
                }
                if let Ok(grant) = seal_personal_rekey(
                    &peer.publics,
                    &peer.cert.device_id,
                    vault_id,
                    generation,
                    &vk,
                ) {
                    zsync
                        .pending_rekeys
                        .push((generation, peer.cert.device_id, grant));
                }
            }
            zsync.trigger_reconcile_personal(vault, true, false);
        }
    }

    /// Drain background `zsync` worker notifications and reconciliation results.
    pub fn poll_zsync(&mut self, ctx: &mut Ctx) {
        if self.vault.is_none() || self.zsync.is_none() {
            return;
        }
        let mut worker_events = Vec::new();
        let mut msgs = Vec::new();
        if let Some(zsync) = self.zsync.as_deref_mut() {
            while let Ok(ev) = zsync.worker_rx.try_recv() {
                worker_events.push(ev);
            }
            while let Ok(msg) = zsync.msg_rx.try_recv() {
                msgs.push(msg);
            }
        }
        for ev in worker_events {
            match ev {
                WorkerEvent::ModeChanged(mode) => {
                    if let Some(zsync) = self.zsync.as_deref_mut() {
                        zsync.last_mode = mode;
                    }
                    ctx.redraw();
                }
                WorkerEvent::RepoChanged { kind, vault_id, .. } => {
                    self.handle_repo_changed(kind, vault_id);
                }
            }
        }
        for msg in msgs {
            match msg {
                ZSyncMsg::PersonalReconciled {
                    pulled,
                    initial_check,
                } => self.apply_zsync_personal(pulled, initial_check, ctx),
                ZSyncMsg::PersonalFailed {
                    err,
                    rekeys,
                    force_head,
                } => self.record_personal_failure(err, rekeys, force_head),
                ZSyncMsg::SharedReconciled { vault_id, pulled } => {
                    self.apply_zsync_shared(vault_id, pulled, ctx);
                }
                ZSyncMsg::RelayedFrames(frames) => {
                    self.apply_pulled(&frames, ctx);
                    if let (Some(zsync), Some(vault)) =
                        (self.zsync.as_deref_mut(), self.vault.as_deref())
                    {
                        zsync.refresh_relay_snapshot(vault);
                    }
                }
                ZSyncMsg::Error(err) => self.record_zsync_error(err),
            }
        }
    }

    fn record_personal_failure(
        &mut self,
        err: String,
        rekeys: Vec<(u64, [u8; 16], Vec<u8>)>,
        force_head: bool,
    ) {
        if let Some(zsync) = self.zsync.as_deref_mut()
            && !rekeys.is_empty()
        {
            zsync.pending_rekeys.extend(rekeys);
        }
        let rerun_force = self
            .zsync
            .as_ref()
            .and_then(|zsync| match zsync.personal_queue {
                PersonalQueue::Running {
                    dirty: true,
                    force_head: qf,
                } => Some(qf || force_head),
                _ if force_head => Some(true),
                _ => None,
            });
        self.record_zsync_error(err);
        if let (Some(fh), Some(vault), Some(zsync)) = (
            rerun_force,
            self.vault.as_deref(),
            self.zsync.as_deref_mut(),
        ) && zsync.personal_queue == PersonalQueue::Idle
        {
            zsync.trigger_reconcile_personal(vault, fh, false);
        }
    }

    fn record_zsync_error(&mut self, err: String) {
        if let Some(p2p) = self.p2p.as_deref_mut() {
            p2p.log.push_line(format!("zsync // {err}"));
        }
        let rerun = if let Some(zsync) = self.zsync.as_deref_mut() {
            zsync.last_error = Some(err);
            let prev = zsync.personal_queue;
            zsync.personal_queue = PersonalQueue::Idle;
            match prev {
                PersonalQueue::Running {
                    dirty: true,
                    force_head,
                } => Some(force_head),
                _ => None,
            }
        } else {
            None
        };
        if let (Some(fh), Some(vault), Some(zsync)) =
            (rerun, self.vault.as_deref(), self.zsync.as_deref_mut())
        {
            zsync.trigger_reconcile_personal(vault, fh, false);
        }
    }

    fn handle_repo_changed(&mut self, kind: RepoKind, vault_id: [u8; 16]) {
        match kind {
            RepoKind::Personal => {
                if let (Some(vault), Some(zsync)) =
                    (self.vault.as_deref(), self.zsync.as_deref_mut())
                {
                    zsync.trigger_reconcile_personal(vault, false, false);
                }
            }
            RepoKind::Shared => {
                if let Some(zsync) = self.zsync.as_deref()
                    && let Some(item) = self
                        .shared
                        .iter_mut()
                        .find(|i| i.reference.vault_id == vault_id)
                {
                    zsync.trigger_reconcile_shared(item);
                }
            }
        }
    }

    fn apply_zsync_personal(
        &mut self,
        pulled: PulledPersonal,
        _initial_check: bool,
        ctx: &mut Ctx,
    ) {
        let (prev_head_epoch, queue_after) = if let Some(zsync) = self.zsync.as_deref_mut() {
            let prev_ep = zsync.head_epoch;
            zsync.last_sync_ms = Some(unix_ms());
            zsync.last_error = None;
            let prev_q = zsync.personal_queue;
            zsync.personal_queue = PersonalQueue::Idle;
            (prev_ep, prev_q)
        } else {
            (0, PersonalQueue::Idle)
        };

        let new_peers = self.ingest_personal_control(&pulled, ctx);
        let PulledPersonal {
            snapshot,
            master_grant,
            adopted_vk,
            head_epoch: pulled_epoch,
            frames,
            rekeys,
            ..
        } = pulled;
        let rec_frames: Vec<Vec<u8>> = frames
            .into_iter()
            .filter(|raw| !raw.starts_with(&PERSONAL_DEVICE_MAGIC))
            .map(|raw| raw.to_vec())
            .collect();

        let had_no_snapshot = snapshot.is_none();
        let mut same_head = false;
        let mut need_push_back = false;
        let upgraded = snapshot.is_some_and(|snap| {
            self.maybe_adopt_personal_snapshot(
                snap,
                prev_head_epoch,
                adopted_vk.as_ref().map(|(_, vk)| vk),
                &rekeys,
                &rec_frames,
                (&mut same_head, &mut need_push_back),
            )
        });
        if (upgraded || same_head || had_no_snapshot)
            && let Some(zsync) = self.zsync.as_deref_mut()
        {
            zsync.head_epoch = zsync.head_epoch.max(pulled_epoch);
        }
        if upgraded {
            if let Some(vault) = self.vault.as_deref() {
                if let Some(grant) = master_grant.as_deref()
                    && presence(&vault.directory, None).recovery
                {
                    let _ = save_master_grant(&vault.paths, grant);
                }
                if let Some(zsync) = self.zsync.as_deref_mut()
                    && let Ok(wtag) = wraps_tag(vault.file.as_bytes())
                {
                    zsync.last_wraps_tag = wtag;
                }
            }
            self.refresh();
            ctx.toast(Tone::Info, "Synced updated vault from another device.");
            ctx.redraw();
        } else if !rec_frames.is_empty() {
            self.apply_pulled(&rec_frames, ctx);
        }
        self.discover_new_shared_refs(ctx);

        let follow_up = match queue_after {
            PersonalQueue::Running {
                dirty: true,
                force_head,
            } => Some(force_head || need_push_back),
            _ if need_push_back => Some(false),
            _ => None,
        };
        if let (Some(force_head), Some(vault), Some(zsync)) =
            (follow_up, self.vault.as_deref(), self.zsync.as_deref_mut())
        {
            zsync.trigger_reconcile_personal(vault, force_head, false);
        } else if let (true, Some(vault), Some(zsync)) =
            (new_peers, self.vault.as_deref(), self.zsync.as_deref_mut())
            && !zsync.peer_devices.is_empty()
        {
            zsync.refresh_relay_snapshot(vault);
        }
    }

    fn ingest_personal_control(&mut self, pulled: &PulledPersonal, ctx: &mut Ctx) -> bool {
        let Some(vault) = self.vault.as_deref() else {
            return false;
        };
        let Ok(id_key) = vault.session.sync_identity_key() else {
            return false;
        };
        let Ok(mut identity) = SyncIdentity::load(&vault.paths.sync_identity(), &id_key) else {
            return false;
        };
        let now = unix_ms();
        let own_device = identity.device_id();
        let mut changed = false;
        let mut new_peers = false;
        for rev in &pulled.revocations {
            if identity.add_revocation(rev.clone(), now).unwrap_or(false) {
                changed = true;
            }
        }
        for cert in &pulled.certs {
            if Some(cert.device_id) != own_device && identity.add_peer(cert.clone(), now).is_ok() {
                changed = true;
            }
        }
        if let Some(own) = identity.devices().first()
            && identity.revocations().is_revoked(own)
        {
            ctx.toast(
                Tone::Danger,
                "This device has been revoked by another device of your account.",
            );
        }
        for raw in &pulled.frames {
            if raw.starts_with(&PERSONAL_DEVICE_MAGIC)
                && let Ok(entry) = PersonalDeviceEntry::verify_decode(
                    raw,
                    identity.root_vk(),
                    vault.session.vault_id(),
                    now,
                )
                && Some(entry.cert.device_id) != own_device
            {
                if identity.add_peer(entry.cert.clone(), now).is_ok() {
                    changed = true;
                }
                if let Some(zsync) = self.zsync.as_deref_mut()
                    && !zsync.peer_devices.iter().any(|p| {
                        p.cert.device_id == entry.cert.device_id && p.wrap_id == entry.wrap_id
                    })
                {
                    zsync
                        .peer_devices
                        .retain(|p| p.cert.device_id != entry.cert.device_id);
                    zsync.peer_devices.push(entry);
                    new_peers = true;
                }
            }
        }
        if changed {
            let _ = identity.save(&vault.paths.sync_identity(), &id_key);
            let arc = Arc::new(identity);
            self.identity = Some(Arc::clone(&arc));
            if let Some(zsync) = self.zsync.as_deref_mut() {
                zsync.identity = arc;
            }
        }
        new_peers
    }

    fn maybe_adopt_personal_snapshot(
        &mut self,
        snap: zsync::DecryptedSnapshot,
        prev_head_epoch: u64,
        adopted_vk: Option<&Secret<[u8; 32]>>,
        rekeys: &[(u64, Zeroizing<Vec<u8>>)],
        rec_frames: &[Vec<u8>],
        (same_head, need_push_back): (&mut bool, &mut bool),
    ) -> bool {
        let (Some(vault), Some(identity)) = (self.vault.as_deref_mut(), self.identity.clone())
        else {
            return false;
        };
        let outcome = try_apply_snapshot_to_vault(
            vault,
            &identity,
            snap,
            prev_head_epoch,
            adopted_vk,
            rekeys,
            rec_frames,
        );
        match outcome {
            SnapshotOutcome::Rejected => false,
            SnapshotOutcome::SameHead => {
                *same_head = true;
                false
            }
            SnapshotOutcome::Adopted {
                updated_id,
                need_push_back: push_back,
            } => {
                *need_push_back = push_back;
                if let Some(arc) = updated_id {
                    self.identity = Some(Arc::clone(&arc));
                    if let Some(zsync) = self.zsync.as_deref_mut() {
                        zsync.identity = arc;
                    }
                }
                self.info = VaultInfo::from(&*vault);
                true
            }
        }
    }
}
