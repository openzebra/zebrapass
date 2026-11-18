//! Apply pulled `zsync` personal vault deltas, snapshots, hybrid PQ `VK`
//! rekeys, device announcements, revocations, and local rolling backups.

use std::path::Path;
use std::sync::Arc;

use local::{
    PERSONAL_DEVICE_MAGIC, PersonalDeviceEntry, SyncIdentity, decode_personal_head,
    load_personal_entries, open_personal_rekey, save_personal_entries, seal_personal_rekey,
    write_rolling_backup,
};
use session::{VaultFile, check_seen, unlock_with_key};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
use zsync::{PulledPersonal, RepoKind, WorkerEvent};

use crate::app::ctx::Ctx;
use crate::app::flows::info::VaultInfo;
use crate::app::flows::unlocked::Unlocked;
use crate::app::zsync::{PersonalQueue, ZSyncMsg, ZebraSync};
use crate::app::zsync_shared::{merge_local_records_into, preserve_local_chip_wrap};
use crate::ui::widgets::toast::Tone;
use crate::vault::create::unix_ms;
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

    fn record_zsync_error(&mut self, err: String) {
        if let Some(p2p) = self.p2p.as_deref_mut() {
            p2p.log.push_line(format!("zsync // {err}"));
        }
        let rerun = if let Some(zsync) = self.zsync.as_deref_mut() {
            zsync.last_error = Some(err);
            let prev = zsync.personal_queue;
            zsync.personal_queue = PersonalQueue::Idle;
            matches!(prev, PersonalQueue::Running { dirty: true, .. })
        } else {
            false
        };
        if rerun
            && let (Some(vault), Some(zsync)) = (self.vault.as_deref(), self.zsync.as_deref_mut())
        {
            zsync.trigger_reconcile_personal(vault, false, false);
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
            let prev_epoch = zsync.head_epoch;
            zsync.head_epoch = zsync.head_epoch.max(pulled.head_epoch);
            zsync.last_sync_ms = Some(unix_ms());
            zsync.last_error = None;
            let prev = zsync.personal_queue;
            zsync.personal_queue = PersonalQueue::Idle;
            (prev_epoch, prev)
        } else {
            (0, PersonalQueue::Idle)
        };

        let new_peers = self.ingest_personal_control(&pulled, ctx);
        let rec_frames: Vec<Vec<u8>> = pulled
            .frames
            .into_iter()
            .filter(|raw| !raw.starts_with(&PERSONAL_DEVICE_MAGIC))
            .map(|raw| raw.to_vec())
            .collect();

        let mut need_push_back = false;
        let upgraded = match pulled.snapshot {
            Some(snap) => self.maybe_adopt_personal_snapshot(
                snap,
                prev_head_epoch,
                &pulled.rekeys,
                &rec_frames,
                &mut need_push_back,
            ),
            None => false,
        };
        if upgraded {
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
        (snap_bytes, head_bytes, head_epoch): zsync::DecryptedSnapshot,
        prev_head_epoch: u64,
        rekeys: &[(u64, Zeroizing<Vec<u8>>)],
        rec_frames: &[Vec<u8>],
        need_push_back: &mut bool,
    ) -> bool {
        let (Some(vault), Some(identity)) = (self.vault.as_deref_mut(), self.identity.clone())
        else {
            return false;
        };
        let Ok((head_vid, head_commit, head_vault_gen)) = decode_personal_head(&head_bytes) else {
            return false;
        };
        if !bool::from(head_vid.ct_eq(vault.session.vault_id())) {
            return false;
        }
        let mut file = VaultFile::new(snap_bytes.to_vec());
        let Ok(parsed) = file.parse() else {
            return false;
        };
        if !bool::from(parsed.commit.ct_eq(&head_commit)) || parsed.generation != head_vault_gen {
            return false;
        }
        if bool::from(vault.session.commit_tag().ct_eq(&parsed.commit)) {
            return false;
        }
        let Some(dev_id) = identity.device_id() else {
            return false;
        };
        let mut unlocked_via_rekey = false;
        let mut candidate = unlock_with_key(&file, &vault.session.reopen_key(), dev_id).ok();
        if candidate.is_none() {
            for (rgen, blob) in rekeys {
                if let Ok(vk_new) =
                    open_personal_rekey(identity.share_keys(), &dev_id, &head_vid, *rgen, blob)
                    && let Ok(sess) = unlock_with_key(&file, &vk_new, dev_id)
                {
                    candidate = Some(sess);
                    unlocked_via_rekey = true;
                    break;
                }
            }
        }
        let Some(mut new_session) = candidate else {
            return false;
        };
        if !unlocked_via_rekey {
            let seen = vault.meta.seen.map(|c| session::Seen {
                generation: c.generation,
                commit_tag: c.commit_tag,
            });
            if head_epoch <= prev_head_epoch && check_seen(&new_session, seen).is_err() {
                return false;
            }
        }
        let preserved = merge_local_records_into(&vault.session, &mut new_session, &mut file);
        for frame in rec_frames {
            let _ = session::accept_peer_frame(&mut new_session, &mut file, frame);
        }
        let readded_chip = preserve_local_chip_wrap(vault, &identity, &mut new_session, &mut file);
        *need_push_back = preserved || readded_chip;
        let old_id = vault
            .session
            .sync_identity_key()
            .ok()
            .and_then(|k| SyncIdentity::load(&vault.paths.sync_identity(), &k).ok());
        let old_peers = vault
            .session
            .personal_peers_key()
            .ok()
            .and_then(|k| load_personal_entries(&vault.paths.peers_store(), &k, true).ok());
        vault.session = new_session;
        vault.file = file;
        if vault.persist().is_err() {
            return false;
        }
        if let (Some(id), Ok(key)) = (old_id, vault.session.sync_identity_key()) {
            let _ = id.save(&vault.paths.sync_identity(), &key);
        }
        if let (Some(peers), Ok(key)) = (old_peers, vault.session.personal_peers_key()) {
            let _ = save_personal_entries(&vault.paths.peers_store(), &key, &peers);
        }
        self.info = VaultInfo::from(&*vault);
        true
    }
}
