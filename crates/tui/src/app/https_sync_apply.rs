//! Apply pulled HTTPS/WSS + `SplitHTTP` personal and shared vault updates,
//! hybrid PQ `VK` rekeys, device announcements, revocations, and local rolling backups.

use std::path::Path;
use std::sync::Arc;

use local::{
    PERSONAL_DEVICE_MAGIC, PersonalDeviceEntry, SyncIdentity, decode_personal_head,
    load_personal_entries, open_personal_rekey, save_personal_entries, seal_personal_rekey,
    write_rolling_backup,
};
use session::{VaultFile, check_seen, unlock_with_key};
use subtle::ConstantTimeEq;
use sync_https::{PulledPersonal, WorkerEvent};
use zeroize::Zeroizing;

use crate::app::ctx::Ctx;
use crate::app::flows::info::VaultInfo;
use crate::app::flows::unlocked::Unlocked;
use crate::app::https_sync::{HttpsMsg, HttpsSync};
use crate::ui::widgets::toast::Tone;
use crate::vault::create::unix_ms;
use crate::vault::ops::FactorRef;

impl Unlocked {
    /// Start background HTTPS/WSS + `SplitHTTP` sync if sync endpoints are configured.
    pub fn start_https_sync(&mut self, ctx: &Ctx) {
        if self.https.is_some() {
            return;
        }
        let (Some(vault), Some(identity)) = (self.vault.as_deref(), self.identity.as_ref()) else {
            return;
        };
        self.https = HttpsSync::start(vault, Arc::clone(identity), &self.shared, ctx);
    }

    /// Restart background HTTPS sync after sync settings or shared hints change.
    pub fn restart_https_sync(&mut self, ctx: &Ctx) {
        self.https = None;
        self.start_https_sync(ctx);
    }

    /// Push a personal vault mutation to sync servers and update rolling local
    /// backups when configured.
    pub fn sync_push_personal(&self, record_id: Option<u32>) {
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
        let Some(https) = self.https.as_deref() else {
            return;
        };
        if let Some(id) = record_id
            && let Ok(frame_bytes) = session::latest_frame(&vault.session, id)
        {
            https.push_personal_frame(frame_bytes, vault.session.generation());
        }
        https.push_personal_snapshot(vault);
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
                && let Some(https) = self.https.as_deref()
                && let Some(target) = https
                    .peer_devices
                    .iter()
                    .find(|peer| peer.wrap_id == Some(wrap_id))
                    .map(|peer| peer.cert.clone())
                && let Ok(rev) = fresh_id.revoke_device(&target, unix_ms())
            {
                let _ = fresh_id.save(&vault.paths.sync_identity(), &id_key);
                https.push_personal_revocation(rev);
            }
            let arc_id = Arc::new(fresh_id);
            self.identity = Some(Arc::clone(&arc_id));
            if let Some(https) = self.https.as_deref_mut() {
                https.identity = arc_id;
            }
        }
        if let Some(https) = self.https.as_deref() {
            let vk = vault.session.reopen_key();
            let generation = vault.session.generation();
            let vault_id = vault.session.vault_id();
            for peer in &https.peer_devices {
                if https.identity.revocations().is_revoked(&peer.cert) {
                    continue;
                }
                if let Ok(grant) = seal_personal_rekey(
                    &peer.publics,
                    &peer.cert.device_id,
                    vault_id,
                    generation,
                    &vk,
                ) {
                    https.push_personal_rekey(generation, peer.cert.device_id, grant);
                }
            }
            https.push_personal_snapshot(vault);
        }
    }

    /// Drain background HTTPS worker events and completed async pulls/backups.
    pub fn poll_https(&mut self, ctx: &mut Ctx) {
        if self.vault.is_none() || self.https.is_none() {
            return;
        }
        let mut worker_events = Vec::new();
        let mut msgs = Vec::new();
        if let Some(https) = self.https.as_deref_mut() {
            while let Ok(ev) = https.worker_rx.try_recv() {
                worker_events.push(ev);
            }
            while let Ok(msg) = https.msg_rx.try_recv() {
                msgs.push(msg);
            }
        }
        for ev in worker_events {
            match ev {
                WorkerEvent::TransportChanged(transport) => {
                    if let Some(https) = self.https.as_deref_mut() {
                        https.last_transport = transport;
                    }
                    ctx.redraw();
                }
                WorkerEvent::MailboxUpdated {
                    kind,
                    vault_id,
                    head_seq,
                } => self.handle_mailbox_updated(kind, vault_id, head_seq),
            }
        }
        for msg in msgs {
            match msg {
                HttpsMsg::PersonalPulled {
                    pulled,
                    initial_check,
                } => self.apply_https_personal(pulled, initial_check, ctx),
                HttpsMsg::SharedPulled { vault_id, pulled } => {
                    self.apply_https_shared(vault_id, pulled, ctx);
                }
                HttpsMsg::CloudBackupPushed => {
                    ctx.toast(Tone::Success, "Encrypted backup uploaded to sync server.");
                }
                HttpsMsg::CloudBackupPulled(bytes) => self.apply_cloud_backup(&bytes, ctx),
                HttpsMsg::Error(err) => {
                    ctx.toast(Tone::Warn, err);
                }
            }
        }
    }

    fn handle_mailbox_updated(
        &self,
        kind: sync_https::MailboxKind,
        vault_id: [u8; 16],
        head_seq: u64,
    ) {
        let Some(https) = self.https.as_deref() else {
            return;
        };
        match kind {
            sync_https::MailboxKind::Personal if head_seq > https.personal_seq => {
                https.trigger_pull_personal(false);
            }
            sync_https::MailboxKind::Shared => {
                let known = https.shared_seqs.get(&vault_id).copied().unwrap_or(0);
                if head_seq > known
                    && let Some(item) = self.shared_item(&vault_id)
                {
                    https.trigger_pull_shared(&item.reference);
                }
            }
            sync_https::MailboxKind::Personal => {}
        }
    }

    fn apply_https_personal(
        &mut self,
        pulled: Option<PulledPersonal>,
        initial_check: bool,
        ctx: &mut Ctx,
    ) {
        let Some(pulled) = pulled else {
            if initial_check {
                if let Some(https) = self.https.as_deref_mut() {
                    https.announce_self();
                }
                self.sync_push_personal(None);
            }
            return;
        };
        let remote_snap_gen = pulled.snapshot.as_ref().map(|(_, _, g)| *g);
        if let Some(https) = self.https.as_deref_mut() {
            https.personal_seq = https.personal_seq.max(pulled.head_seq);
            https.last_sync_ms = Some(unix_ms());
        }
        let saw_self = self.ingest_personal_control(&pulled, ctx);
        if !saw_self && let Some(https) = self.https.as_deref_mut() {
            https.announce_self();
        }
        let rec_frames: Vec<Vec<u8>> = pulled
            .frames
            .into_iter()
            .filter(|(_, raw)| !raw.starts_with(&PERSONAL_DEVICE_MAGIC))
            .map(|(_, raw)| raw.to_vec())
            .collect();
        if pulled.rekeys.is_empty() && !rec_frames.is_empty() {
            self.apply_pulled(&rec_frames, ctx);
        }
        let mut readded_chip = false;
        let upgraded = match pulled.snapshot {
            Some(snap) => self.maybe_adopt_personal_snapshot(
                snap,
                &pulled.rekeys,
                &rec_frames,
                &mut readded_chip,
            ),
            None => false,
        };
        if upgraded {
            self.refresh();
            if readded_chip {
                self.sync_push_personal(None);
            }
            ctx.toast(Tone::Info, "Synced updated vault from another device.");
            ctx.redraw();
        } else if initial_check
            && remote_snap_gen.is_none_or(|g| {
                self.vault
                    .as_deref()
                    .is_some_and(|v| v.session.generation() > g)
            })
        {
            self.sync_push_personal(None);
        }
        self.discover_new_shared_refs(ctx);
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
        for rev in &pulled.revocations {
            if identity.add_revocation(rev.clone(), now).unwrap_or(false) {
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
        let mut saw_self = false;
        for (_, raw) in &pulled.frames {
            if raw.starts_with(&PERSONAL_DEVICE_MAGIC)
                && let Ok(entry) = PersonalDeviceEntry::verify_decode(
                    raw,
                    identity.root_vk(),
                    vault.session.vault_id(),
                    now,
                )
            {
                if Some(entry.cert.device_id) == own_device {
                    saw_self = true;
                } else {
                    if identity.add_peer(entry.cert.clone(), now).is_ok() {
                        changed = true;
                    }
                    if let Some(https) = self.https.as_deref_mut() {
                        https
                            .peer_devices
                            .retain(|known| known.cert.device_id != entry.cert.device_id);
                        https.peer_devices.push(entry);
                    }
                }
            }
        }
        if changed {
            let _ = identity.save(&vault.paths.sync_identity(), &id_key);
            let arc = Arc::new(identity);
            self.identity = Some(Arc::clone(&arc));
            if let Some(https) = self.https.as_deref_mut() {
                https.identity = arc;
            }
        }
        saw_self
    }

    fn maybe_adopt_personal_snapshot(
        &mut self,
        (snap_bytes, head_bytes, snap_gen): sync_https::DecryptedSnapshot,
        rekeys: &[(u64, Zeroizing<Vec<u8>>)],
        rec_frames: &[Vec<u8>],
        readded_chip: &mut bool,
    ) -> bool {
        let (Some(vault), Some(identity)) = (self.vault.as_deref_mut(), self.identity.clone())
        else {
            return false;
        };
        let Ok((head_vid, head_commit, head_gen)) = decode_personal_head(&head_bytes) else {
            return false;
        };
        if head_gen != snap_gen
            || !bool::from(head_vid.ct_eq(vault.session.vault_id()))
            || (snap_gen <= vault.session.generation() && rekeys.is_empty())
        {
            return false;
        }
        let mut file = VaultFile::new(snap_bytes.to_vec());
        let Ok(parsed) = file.parse() else {
            return false;
        };
        if !bool::from(parsed.commit.ct_eq(&head_commit)) || parsed.generation != snap_gen {
            return false;
        }
        let Some(dev_id) = identity.device_id() else {
            return false;
        };
        let mut candidate = unlock_with_key(&file, &vault.session.reopen_key(), dev_id).ok();
        if candidate.is_none() {
            for (rgen, blob) in rekeys {
                if let Ok(vk_new) =
                    open_personal_rekey(identity.share_keys(), &dev_id, &head_vid, *rgen, blob)
                    && let Ok(sess) = unlock_with_key(&file, &vk_new, dev_id)
                {
                    candidate = Some(sess);
                    break;
                }
            }
        }
        let Some(mut new_session) = candidate else {
            return false;
        };
        let seen = vault.meta.seen.map(|c| session::Seen {
            generation: c.generation,
            commit_tag: c.commit_tag,
        });
        if check_seen(&new_session, seen).is_err() {
            return false;
        }
        for frame in rec_frames {
            let _ = session::accept_peer_frame(&mut new_session, &mut file, frame);
        }
        *readded_chip = preserve_local_chip_wrap(vault, &identity, &mut new_session, &mut file);
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

fn preserve_local_chip_wrap(
    old_vault: &crate::vault::Vault,
    identity: &SyncIdentity,
    new_session: &mut session::Session,
    new_file: &mut VaultFile,
) -> bool {
    let Some(owned) = crate::vault::device::owned_id(&old_vault.paths) else {
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
