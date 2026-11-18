//! Shared vault HTTPS/WSS + `SplitHTTP` synchronization, new shared-ref
//! auto-discovery, and remote encrypted `.zpbackup` push/pull helpers.

use std::sync::Arc;

use local::{SharedRef, SharedVault, encode_personal_head};
use memberlog::Entry;
use sync_https::PulledShared;
use syncwire::encode_snapshot;

use crate::app::ctx::Ctx;
use crate::app::flows::unlocked::Unlocked;
use crate::app::https_sync::{HttpsMsg, HttpsSync, collect_sync_urls};
use crate::ui::widgets::toast::Tone;
use crate::vault::create::unix_ms;
use crate::vault::shared::{SharedItem, references};

impl HttpsSync {
    /// Push a shared vault snapshot and member log (`Role::Owner`), or member entries
    /// only (`Role::Writer`/`Reader` e.g. leave).
    pub fn push_shared_full(&self, shared: &mut SharedVault, reference: &SharedRef) {
        let client = Arc::clone(&self.client);
        let identity = Arc::clone(&self.identity);
        let shared_ref = reference.duplicate();
        let is_owner = shared
            .role_of(&identity)
            .is_some_and(memberlog::Role::can_manage);
        let entries = shared.log.entries().to_vec();
        if !is_owner {
            self.rt.spawn(async move {
                let _ = client
                    .append_shared_members(
                        &identity,
                        shared_ref.seed.expose(),
                        shared_ref.vault_id,
                        &entries,
                    )
                    .await;
            });
            return;
        }
        let Ok(attestations) = shared.attestations(reference, &identity) else {
            return;
        };
        let Ok(snap_bytes) = encode_snapshot(shared.file.as_bytes(), &attestations) else {
            return;
        };
        let generation = shared.session.generation();
        let head = encode_personal_head(
            shared.session.vault_id(),
            shared.session.commit_tag(),
            generation,
        );
        self.rt.spawn(async move {
            let _ = client
                .push_shared_state(
                    &identity,
                    shared_ref.seed.expose(),
                    shared_ref.vault_id,
                    shared_ref.anchor,
                    &entries,
                    &snap_bytes,
                    &head,
                    generation,
                )
                .await;
        });
    }

    /// Append one attested shared record bundle, with owner fallback to full snapshot push
    /// if the shared mailbox has not yet been initialized on the server.
    pub fn push_shared_record(
        &self,
        shared: &mut SharedVault,
        reference: &SharedRef,
        record_id: u32,
    ) {
        let Ok(Some(bundle)) = shared.bundle(reference, &self.identity, record_id) else {
            return;
        };
        let client = Arc::clone(&self.client);
        let identity = Arc::clone(&self.identity);
        let shared_ref = reference.duplicate();
        let generation = shared.session.generation();
        let fallback_owner = if shared
            .role_of(&identity)
            .is_some_and(memberlog::Role::can_manage)
        {
            shared
                .attestations(reference, &identity)
                .ok()
                .and_then(|att| encode_snapshot(shared.file.as_bytes(), &att).ok())
                .map(|snap| {
                    let entries: Vec<Entry> = shared.log.entries().to_vec();
                    let head = encode_personal_head(
                        shared.session.vault_id(),
                        shared.session.commit_tag(),
                        generation,
                    );
                    (entries, snap, head, generation)
                })
        } else {
            None
        };
        self.rt.spawn(async move {
            let res = client
                .append_shared_frame(
                    &identity,
                    shared_ref.seed.expose(),
                    shared_ref.vault_id,
                    &bundle,
                    generation,
                )
                .await;
            if res.is_err()
                && let Some((entries, snap, head, key_gen)) = fallback_owner
            {
                let _ = client
                    .push_shared_state(
                        &identity,
                        shared_ref.seed.expose(),
                        shared_ref.vault_id,
                        shared_ref.anchor,
                        &entries,
                        &snap,
                        &head,
                        key_gen,
                    )
                    .await;
            }
        });
    }

    /// Upload a `.zpbackup` bundle under an outer Cascade layer to the sync server.
    pub fn push_cloud_backup(&self, zpbk_bytes: Vec<u8>) {
        let client = Arc::clone(&self.client);
        let identity = Arc::clone(&self.identity);
        let tx = self.msg_tx.clone();
        self.rt.spawn(async move {
            match client.push_cloud_backup(&identity, &zpbk_bytes).await {
                Ok(()) => {
                    let _ = tx.send(HttpsMsg::CloudBackupPushed);
                }
                Err(err) => {
                    let _ = tx.send(HttpsMsg::Error(format!(
                        "Cloud backup upload failed: {err}"
                    )));
                }
            }
        });
    }

    /// Pull the outer-sealed `.zpbackup` bundle from the sync server.
    pub fn pull_cloud_backup(&self) {
        let client = Arc::clone(&self.client);
        let identity = Arc::clone(&self.identity);
        let tx = self.msg_tx.clone();
        self.rt.spawn(async move {
            match client.pull_cloud_backup(&identity).await {
                Ok(Some(bytes)) => {
                    let _ = tx.send(HttpsMsg::CloudBackupPulled(bytes));
                }
                Ok(None) => {
                    let _ = tx.send(HttpsMsg::Error(String::from(
                        "No remote backup found on sync server.",
                    )));
                }
                Err(err) => {
                    let _ = tx.send(HttpsMsg::Error(format!("Cloud backup pull failed: {err}")));
                }
            }
        });
    }
}

impl Unlocked {
    /// Refresh watched mailbox subscriptions (or restart if a new shared invitation
    /// introduced a previously unconfigured server URL).
    pub fn refresh_https_sync(&mut self, ctx: &Ctx) {
        let Some(vault) = self.vault.as_deref() else {
            return;
        };
        let desired = collect_sync_urls(vault.meta.prefs.as_ref(), &ctx.sync_servers, &self.shared);
        if let Some(https) = self.https.as_deref() {
            if desired.iter().all(|u| https.endpoints.contains(u)) {
                https.update_boxes(&self.shared);
            } else {
                self.restart_https_sync(ctx);
            }
        } else if !desired.is_empty() {
            self.start_https_sync(ctx);
        }
    }

    /// Push a shared vault snapshot and member log to sync servers.
    pub fn sync_push_shared_full(&mut self, vault_id: &[u8; 16]) {
        let Some(https) = self.https.as_deref() else {
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
        if let Some(sv) = item.vault_mut() {
            https.push_shared_full(sv, &reference);
        }
    }

    /// Push one shared record update bundle to sync servers.
    pub fn sync_push_shared_record(&mut self, vault_id: &[u8; 16], record_id: u32) {
        let Some(https) = self.https.as_deref() else {
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
        if let Some(sv) = item.vault_mut() {
            https.push_shared_record(sv, &reference, record_id);
        }
    }

    /// Discover any [`local::SharedRef`] records synced into the personal vault
    /// that are not yet tracked in `self.shared`, open/queue them, and start
    /// fetching from peers and sync servers.
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
        self.refresh_https_sync(ctx);
        if let Some(https) = self.https.as_deref() {
            for reference in &added {
                https.trigger_pull_shared(reference);
            }
        }
    }

    pub(crate) fn apply_https_shared(
        &mut self,
        vault_id: [u8; 16],
        pulled: Option<PulledShared>,
        ctx: &mut Ctx,
    ) {
        let Some(pulled) = pulled else {
            self.sync_push_shared_full(&vault_id);
            return;
        };
        let missing_snapshot = pulled.snapshot.is_none();
        if let Some(https) = self.https.as_deref_mut() {
            let prev = https.shared_seqs.get(&vault_id).copied().unwrap_or(0);
            https
                .shared_seqs
                .insert(vault_id, prev.max(pulled.head_seq));
            https.last_sync_ms = Some(unix_ms());
        }
        let Some(index) = self
            .shared
            .iter()
            .position(|item| item.reference.vault_id == vault_id)
        else {
            return;
        };
        let mut log_wire = Vec::with_capacity(pulled.entries.len() * memberlog::ENTRY_WIRE_LEN);
        for entry in &pulled.entries {
            if let Ok(enc) = entry.encode() {
                log_wire.extend_from_slice(&enc);
            }
        }
        let (was_ready, local_gen) = self.shared.get(index).map_or((false, 0), |item| {
            (
                item.ready(),
                item.session().map_or(0, session::Session::generation),
            )
        });
        if let Some((snap_bytes, _, snap_gen)) = pulled.snapshot
            && (!was_ready || snap_gen > local_gen)
        {
            self.arrived(&vault_id, &log_wire, snap_bytes.to_vec(), None, ctx);
        } else if missing_snapshot && was_ready {
            self.sync_push_shared_full(&vault_id);
        }

        let mut applied = 0usize;
        let mut members_changed = false;
        if let Some(item) = self.shared.get_mut(index) {
            let reference = Arc::clone(&item.reference);
            if let Some(sv) = item.vault_mut() {
                let before = sv.log.entries().len();
                if sv.log.merge(&pulled.entries).is_ok() && sv.log.entries().len() > before {
                    let _ = sv.save_log(&reference.seed);
                    members_changed = true;
                }
                for (_, bundle) in &pulled.frames {
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

    pub(crate) fn apply_cloud_backup(&mut self, zpbk_bytes: &[u8], ctx: &mut Ctx) {
        let (Some(vault), Some(identity)) = (self.vault.as_deref_mut(), self.identity.clone())
        else {
            ctx.toast(Tone::Warn, "Vault unavailable.");
            return;
        };
        let Ok(contents) = local::open_backup_with_vk(
            zpbk_bytes,
            &vault.session.reopen_key(),
            vault.meta.device_id,
        ) else {
            ctx.toast(Tone::Danger, "Server backup failed authentication.");
            return;
        };
        let (backup_sess, shared) = match contents {
            local::BackupContents::Bundle(b) => (b.session, b.shared),
            local::BackupContents::LegacyVault(l) => (l.session, Vec::new()),
        };
        let mut merged = 0usize;
        for row in session::list_records(&backup_sess).unwrap_or_default() {
            if let Ok(frame) = session::latest_frame(&backup_sess, row.id)
                && session::accept_peer_frame(&mut vault.session, &mut vault.file, &frame).is_ok()
            {
                merged = merged.saturating_add(1);
            }
        }
        if merged > 0 {
            let _ = vault.persist();
        }
        let shared_count = if shared.is_empty() {
            0
        } else {
            local::restore_shared_entries(&self.base, &identity, &vault.session, &shared, false)
                .unwrap_or(0)
        };
        self.refresh();
        self.discover_new_shared_refs(ctx);
        ctx.toast(
            Tone::Success,
            format!("Backup restored: {merged} records, {shared_count} shared vaults."),
        );
        ctx.redraw();
    }
}
