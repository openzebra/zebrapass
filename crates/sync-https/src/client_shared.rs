//! High-level shared vault sync operations over [`SyncClient`] with
//! multi-endpoint failover.

use anyhow::anyhow;
use kdf::{shared_envelope_key, shared_mailbox_id};
use local::SyncIdentity;
use memberlog::Entry;
use zeroize::Zeroizing;

use crate::client::SyncClient;
use crate::client_ops::{DecryptedSnapshot, MailboxCtx};
use crate::envelope::{EnvelopePurpose, seal_envelope};
use crate::limits::SPLIT_TRANSFER_CHUNK;
use crate::wire::{ChunkTarget, MailboxKind, OpPayload};

/// Pulled remote state for one shared vault mailbox.
#[derive(Debug)]
pub struct PulledShared {
    /// Decrypted `(snapshot_bytes, head_meta_plain, key_generation)`.
    pub snapshot: Option<DecryptedSnapshot>,
    /// Newly appended `(seq, plain_bundle_bytes)` since `since_seq`.
    pub frames: Vec<(u64, Zeroizing<Vec<u8>>)>,
    /// Full verified sequence of [`memberlog::Entry`] items on the server.
    pub entries: Vec<Entry>,
    /// Latest server sequence number observed.
    pub head_seq: u64,
}

fn encode_entries_flat(entries: &[Entry]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(entries.len() * memberlog::ENTRY_WIRE_LEN);
    for entry in entries {
        out.extend_from_slice(&entry.encode()?);
    }
    Ok(out)
}

impl SyncClient {
    /// Push a shared vault snapshot + verified member log to all reachable endpoints.
    ///
    /// # Errors
    ///
    /// Encoding error or every configured endpoint failed.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit shared vault parameters"
    )]
    pub async fn push_shared_state(
        &self,
        identity: &SyncIdentity,
        shared_seed: &[u8; 64],
        vault_id: [u8; 16],
        anchor: [u8; 32],
        entries: &[Entry],
        snapshot_bytes: &[u8],
        head_meta_plain: &[u8],
        key_generation: u64,
    ) -> anyhow::Result<()> {
        let entries_raw = encode_entries_flat(entries)?;
        let mut ok_count = 0usize;
        let mut last_err = None;
        for ep in self.endpoints() {
            let fut = async {
                let box_id = shared_mailbox_id(shared_seed, &vault_id, &ep.origin)?;
                let key = shared_envelope_key(shared_seed, &box_id)?;
                let snap_env = seal_envelope(
                    &key,
                    &box_id,
                    EnvelopePurpose::SharedSnapshot,
                    key_generation,
                    snapshot_bytes,
                )?;
                let head_env = seal_envelope(
                    &key,
                    &box_id,
                    EnvelopePurpose::SharedHead,
                    key_generation,
                    head_meta_plain,
                )?;
                self.ensure_shared_cert(
                    ep,
                    identity,
                    box_id,
                    Some((vault_id, anchor, &entries_raw)),
                )
                .await?;
                let (snap_id, total_chunks) = self
                    .upload_chunks_raw(ep, identity, box_id, MailboxKind::Shared, &snap_env)
                    .await?;
                self.send_shared_op(
                    ep,
                    identity,
                    box_id,
                    &OpPayload::CommitSnapshot {
                        snap_id,
                        total_chunks,
                        key_generation,
                        head_meta: head_env,
                    },
                    Some((vault_id, anchor, &entries_raw)),
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

    /// Append one shared vault frame bundle (`Attestation` + sealed frame)
    /// across endpoints.
    ///
    /// # Errors
    ///
    /// All endpoints failed or rejected write (`Role::Reader`).
    pub async fn append_shared_frame(
        &self,
        identity: &SyncIdentity,
        shared_seed: &[u8; 64],
        vault_id: [u8; 16],
        bundle_bytes: &[u8],
        seq_hint: u64,
    ) -> anyhow::Result<()> {
        let mut ok_count = 0usize;
        let mut last_err = None;
        for ep in self.endpoints() {
            let fut = async {
                let box_id = shared_mailbox_id(shared_seed, &vault_id, &ep.origin)?;
                let key = shared_envelope_key(shared_seed, &box_id)?;
                let env = seal_envelope(
                    &key,
                    &box_id,
                    EnvelopePurpose::SharedFrame,
                    seq_hint,
                    bundle_bytes,
                )?;
                if env.len() <= SPLIT_TRANSFER_CHUNK {
                    self.send_shared_op(
                        ep,
                        identity,
                        box_id,
                        &OpPayload::AppendFrame {
                            frame_seq_hint: seq_hint,
                            envelope: env,
                        },
                        None,
                    )
                    .await?;
                } else {
                    let (chunk_id, total_chunks) = self
                        .upload_chunks_raw(ep, identity, box_id, MailboxKind::Shared, &env)
                        .await?;
                    self.send_shared_op(
                        ep,
                        identity,
                        box_id,
                        &OpPayload::CommitChunkedFrame {
                            chunk_id,
                            total_chunks,
                        },
                        None,
                    )
                    .await?;
                }
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

    /// Append new membership log entries to a shared mailbox.
    ///
    /// # Errors
    ///
    /// Encoding failure or all endpoints failed.
    pub async fn append_shared_members(
        &self,
        identity: &SyncIdentity,
        shared_seed: &[u8; 64],
        vault_id: [u8; 16],
        entries: &[Entry],
    ) -> anyhow::Result<()> {
        let raw = encode_entries_flat(entries)?;
        let mut ok_count = 0usize;
        let mut last_err = None;
        for ep in self.endpoints() {
            let fut = async {
                let box_id = shared_mailbox_id(shared_seed, &vault_id, &ep.origin)?;
                let (chunk_id, total_chunks) = self
                    .upload_chunks_raw(ep, identity, box_id, MailboxKind::Shared, &raw)
                    .await?;
                self.send_shared_op(
                    ep,
                    identity,
                    box_id,
                    &OpPayload::CommitMembers {
                        chunk_id,
                        total_chunks,
                    },
                    None,
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

    /// Pull shared vault snapshot, frames, and member log entries from the
    /// first reachable endpoint.
    ///
    /// # Errors
    ///
    /// Member log / AEAD verification failure or all endpoints unreachable.
    pub async fn pull_shared_state(
        &self,
        identity: &SyncIdentity,
        shared_seed: &[u8; 64],
        vault_id: [u8; 16],
        since_seq: u64,
    ) -> anyhow::Result<Option<PulledShared>> {
        let mut last_err = None;
        for ep in self.endpoints() {
            let fut = async {
                let box_id = shared_mailbox_id(shared_seed, &vault_id, &ep.origin)?;
                let key = shared_envelope_key(shared_seed, &box_id)?;
                let first = self
                    .post_state(ep, identity, box_id, MailboxKind::Shared, since_seq, 0)
                    .await?;
                if !first.exists {
                    return Ok(None);
                }
                let ctx = MailboxCtx {
                    ep,
                    identity,
                    box_id,
                    kind: MailboxKind::Shared,
                    key: &key,
                };
                let snapshot = self
                    .fetch_snapshot_pair(
                        &ctx,
                        &first,
                        (EnvelopePurpose::SharedHead, EnvelopePurpose::SharedSnapshot),
                    )
                    .await?;
                let frames = self
                    .fetch_frames_paged(
                        &ctx,
                        EnvelopePurpose::SharedFrame,
                        first.clone(),
                        since_seq,
                    )
                    .await?;
                let mut entries =
                    Vec::with_capacity(usize::try_from(first.member_count).unwrap_or(0));
                for idx in 0..first.member_count {
                    let raw = self
                        .download_indexed_item(
                            ep,
                            identity,
                            box_id,
                            MailboxKind::Shared,
                            ChunkTarget::Members,
                            idx,
                            memberlog::ENTRY_WIRE_LEN,
                        )
                        .await?;
                    entries.push(Entry::decode(&raw)?);
                }
                Ok::<Option<PulledShared>, anyhow::Error>(Some(PulledShared {
                    snapshot,
                    frames,
                    entries,
                    head_seq: first.head_seq,
                }))
            };
            match fut.await {
                Ok(res) => return Ok(res),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no endpoints reachable")))
    }
}
