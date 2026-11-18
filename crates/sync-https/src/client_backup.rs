//! Remote encrypted cloud backup push/pull and indexed slice download
//! helpers over [`SyncClient`].

use anyhow::anyhow;
use kdf::{cloud_backup_key, personal_mailbox_id};
use local::SyncIdentity;
use zeroize::Zeroizing;

use crate::client::{ChunkFetch, SyncClient};
use crate::client_ops::require_gate;
use crate::envelope::{EnvelopePurpose, open_envelope, seal_envelope};
use crate::limits::{MAX_ENVELOPE_BYTES, SPLIT_TRANSFER_CHUNK};
use crate::proxy::SyncEndpoint;
use crate::wire::{ChunkTarget, MailboxKind, OpPayload};

impl SyncClient {
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit indexed slice item download"
    )]
    pub(crate) async fn download_indexed_item(
        &self,
        ep: &SyncEndpoint,
        identity: &SyncIdentity,
        box_id: [u8; 32],
        kind: MailboxKind,
        target: ChunkTarget,
        index: u32,
        max_len: usize,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let max_slice = u32::try_from(SPLIT_TRANSFER_CHUNK).unwrap_or(6_144);
        let mut out = Zeroizing::new(Vec::new());
        let mut offset = 0u32;
        loop {
            let rep = self
                .post_chunk_once(
                    ep, identity, box_id, kind, target, [0u8; 32], index, offset, max_slice,
                )
                .await?;
            if out.len().saturating_add(rep.data.len()) > max_len {
                anyhow::bail!("indexed item exceeds limit");
            }
            out.extend_from_slice(&rep.data);
            let got = u32::try_from(rep.data.len()).map_err(|_| anyhow!("slice overflow"))?;
            offset = offset.saturating_add(got);
            if rep.data.is_empty() || offset >= rep.total_len {
                break;
            }
        }
        Ok(out)
    }

    /// Seal `.zpbackup` bytes under an additional outer `cloud_backup_key` Cascade
    /// layer and upload them in `6 KiB` `SplitHTTP` chunks.
    ///
    /// # Errors
    ///
    /// Missing account gate or all endpoints failed.
    pub async fn push_cloud_backup(
        &self,
        identity: &SyncIdentity,
        zpbk_bytes: &[u8],
    ) -> anyhow::Result<()> {
        let gate = require_gate(identity)?;
        let mut ok_count = 0usize;
        let mut last_err = None;
        for ep in self.endpoints() {
            let fut = async {
                let box_id = personal_mailbox_id(gate, &ep.origin)?;
                let key = cloud_backup_key(gate, &box_id)?;
                let outer =
                    seal_envelope(&key, &box_id, EnvelopePurpose::CloudBackup, 1, zpbk_bytes)?;
                let (backup_id, total_chunks) = self
                    .upload_chunks_raw(ep, identity, box_id, MailboxKind::Personal, &outer)
                    .await?;
                self.send_personal_op(
                    ep,
                    identity,
                    box_id,
                    &OpPayload::CommitBackup {
                        backup_id,
                        total_chunks,
                    },
                )
                .await?;
                Ok::<(), anyhow::Error>(())
            };
            match fut.await {
                Ok(()) => ok_count = ok_count.saturating_add(1),
                Err(err) => last_err = Some(err),
            }
        }
        if ok_count > 0 {
            Ok(())
        } else {
            Err(last_err.unwrap_or_else(|| anyhow!("no endpoints reachable")))
        }
    }

    /// Pull and open the outer-sealed `.zpbackup` remote backup from the first
    /// reachable endpoint.
    ///
    /// # Errors
    ///
    /// Authentication/decryption failure or all endpoints unreachable.
    pub async fn pull_cloud_backup(
        &self,
        identity: &SyncIdentity,
    ) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        let gate = require_gate(identity)?;
        let mut last_err = None;
        for ep in self.endpoints() {
            let fut = async {
                let box_id = personal_mailbox_id(gate, &ep.origin)?;
                let key = cloud_backup_key(gate, &box_id)?;
                let st = self
                    .post_state(ep, identity, box_id, MailboxKind::Personal, 0, 0)
                    .await?;
                let Some(backup_id) = st.backup_id else {
                    return Ok(None);
                };
                let outer = self
                    .download_sliced(
                        ep,
                        identity,
                        ChunkFetch {
                            box_id,
                            kind: MailboxKind::Personal,
                            target: ChunkTarget::Backup,
                            object_id: backup_id,
                            chunk_count: st.backup_chunks,
                            max_total_bytes: MAX_ENVELOPE_BYTES,
                        },
                    )
                    .await?;
                let (_, zpbk) = open_envelope(&key, &box_id, EnvelopePurpose::CloudBackup, &outer)?;
                Ok::<Option<Zeroizing<Vec<u8>>>, anyhow::Error>(Some(zpbk))
            };
            match fut.await {
                Ok(res) => return Ok(res),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no endpoints reachable")))
    }
}
