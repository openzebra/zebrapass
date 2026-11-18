//! High-level personal vault and rekey/revocation operations over [`SyncClient`]
//! with automatic endpoint failover.

use anyhow::anyhow;
use kdf::{personal_envelope_key, personal_mailbox_id};
use local::SyncIdentity;
use secret::Secret;
use session::Revocation;
use syncwire::{REVOCATION_WIRE_LEN, decode_revocation, encode_revocation};
use zeroize::Zeroizing;

use crate::auth::now_ms;
use crate::client::{ChunkFetch, SyncClient};
pub use crate::client_shared::PulledShared;
use crate::envelope::{EnvelopePurpose, open_envelope, seal_envelope};
use crate::limits::{MAX_ENVELOPE_BYTES, SPLIT_TRANSFER_CHUNK};
use crate::proxy::SyncEndpoint;
use crate::wire::{ChunkTarget, MailboxKind, OpPayload};
use crate::wire_rpc::{FrameItem, MailboxSummary};

/// Decrypted `(snapshot_bytes, head_meta_plain, key_generation)` tuple.
pub type DecryptedSnapshot = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, u64);

/// Pulled remote state for the account's personal mailbox.
#[derive(Debug)]
pub struct PulledPersonal {
    /// Decrypted `(vault_file_bytes, head_meta_plain, key_generation)` when present.
    pub snapshot: Option<DecryptedSnapshot>,
    /// Newly appended `(seq, plain_frame_bytes)` since `since_seq`.
    pub frames: Vec<(u64, Zeroizing<Vec<u8>>)>,
    /// Key-rotation grants addressed to this device (`(generation, payload)`).
    pub rekeys: Vec<(u64, Zeroizing<Vec<u8>>)>,
    /// Account-signed device revocations verified against `identity.root_vk()`.
    pub revocations: Vec<Revocation>,
    /// Latest server sequence number observed.
    pub head_seq: u64,
}

pub(crate) struct MailboxCtx<'a> {
    pub ep: &'a SyncEndpoint,
    pub identity: &'a SyncIdentity,
    pub box_id: [u8; 32],
    pub kind: MailboxKind,
    pub key: &'a Secret<[u8; 32]>,
}

pub(crate) fn require_gate(identity: &SyncIdentity) -> anyhow::Result<&[u8; 32]> {
    identity
        .account_gate()
        .map(Secret::expose)
        .ok_or_else(|| anyhow!("account gate secret missing from sync identity"))
}

impl SyncClient {
    /// Push a personal vault snapshot across endpoints (succeeding once at least
    /// one configured endpoint accepts it, mirroring best-effort to the rest).
    ///
    /// # Errors
    ///
    /// Missing account gate or every configured endpoint failed.
    pub async fn push_personal_snapshot(
        &self,
        identity: &SyncIdentity,
        vault_file_bytes: &[u8],
        head_meta_plain: &[u8],
        key_generation: u64,
    ) -> anyhow::Result<()> {
        let gate = require_gate(identity)?;
        let mut ok_count = 0usize;
        let mut last_err = None;
        for ep in self.endpoints() {
            let fut = async {
                let box_id = personal_mailbox_id(gate, &ep.origin)?;
                let key = personal_envelope_key(gate, &box_id)?;
                let snap_env = seal_envelope(
                    &key,
                    &box_id,
                    EnvelopePurpose::PersonalSnapshot,
                    key_generation,
                    vault_file_bytes,
                )?;
                let head_env = seal_envelope(
                    &key,
                    &box_id,
                    EnvelopePurpose::PersonalHead,
                    key_generation,
                    head_meta_plain,
                )?;
                let (snap_id, total_chunks) = self
                    .upload_chunks_raw(ep, identity, box_id, MailboxKind::Personal, &snap_env)
                    .await?;
                self.send_personal_op(
                    ep,
                    identity,
                    box_id,
                    &OpPayload::CommitSnapshot {
                        snap_id,
                        total_chunks,
                        key_generation,
                        head_meta: head_env,
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

    /// Append one outer-sealed personal record frame across endpoints.
    ///
    /// # Errors
    ///
    /// Missing gate secret or all endpoints failed.
    pub async fn append_personal_frame(
        &self,
        identity: &SyncIdentity,
        frame_bytes: &[u8],
        seq_hint: u64,
    ) -> anyhow::Result<()> {
        let gate = require_gate(identity)?;
        let mut ok_count = 0usize;
        let mut last_err = None;
        for ep in self.endpoints() {
            let fut = async {
                let box_id = personal_mailbox_id(gate, &ep.origin)?;
                let key = personal_envelope_key(gate, &box_id)?;
                let env = seal_envelope(
                    &key,
                    &box_id,
                    EnvelopePurpose::PersonalFrame,
                    seq_hint,
                    frame_bytes,
                )?;
                if env.len() <= SPLIT_TRANSFER_CHUNK {
                    self.send_personal_op(
                        ep,
                        identity,
                        box_id,
                        &OpPayload::AppendFrame {
                            frame_seq_hint: seq_hint,
                            envelope: env,
                        },
                    )
                    .await?;
                } else {
                    let (chunk_id, total_chunks) = self
                        .upload_chunks_raw(ep, identity, box_id, MailboxKind::Personal, &env)
                        .await?;
                    self.send_personal_op(
                        ep,
                        identity,
                        box_id,
                        &OpPayload::CommitChunkedFrame {
                            chunk_id,
                            total_chunks,
                        },
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

    /// Publish an encrypted hybrid-PQ personal `VK` rekey grant to a peer device.
    ///
    /// # Errors
    ///
    /// Missing gate secret or all endpoints failed.
    pub async fn push_personal_rekey(
        &self,
        identity: &SyncIdentity,
        generation: u64,
        target_device: [u8; 16],
        rekey_blob: &[u8],
    ) -> anyhow::Result<()> {
        let gate = require_gate(identity)?;
        let mut ok_count = 0usize;
        let mut last_err = None;
        for ep in self.endpoints() {
            let fut = async {
                let box_id = personal_mailbox_id(gate, &ep.origin)?;
                let key = personal_envelope_key(gate, &box_id)?;
                let env = seal_envelope(
                    &key,
                    &box_id,
                    EnvelopePurpose::PersonalRekey,
                    generation,
                    rekey_blob,
                )?;
                self.send_personal_op(
                    ep,
                    identity,
                    box_id,
                    &OpPayload::PutRekey {
                        generation,
                        target_device,
                        envelope: env,
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

    /// Publish a signed device revocation in `6 KiB` `SplitHTTP` chunks.
    ///
    /// # Errors
    ///
    /// Encoding failure or all endpoints failed.
    pub async fn push_personal_revocation(
        &self,
        identity: &SyncIdentity,
        revocation: &Revocation,
    ) -> anyhow::Result<()> {
        let gate = require_gate(identity)?;
        let rev_wire = encode_revocation(revocation)?;
        let mut ok_count = 0usize;
        let mut last_err = None;
        for ep in self.endpoints() {
            let fut = async {
                let box_id = personal_mailbox_id(gate, &ep.origin)?;
                let (chunk_id, total_chunks) = self
                    .upload_chunks_raw(ep, identity, box_id, MailboxKind::Personal, &rev_wire)
                    .await?;
                self.send_personal_op(
                    ep,
                    identity,
                    box_id,
                    &OpPayload::CommitRevocation {
                        chunk_id,
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

    pub(crate) async fn fetch_snapshot_pair(
        &self,
        ctx: &MailboxCtx<'_>,
        summary: &MailboxSummary,
        purposes: (EnvelopePurpose, EnvelopePurpose),
    ) -> anyhow::Result<Option<DecryptedSnapshot>> {
        let Some(snap_id) = summary.snap_id else {
            return Ok(None);
        };
        let (_, head_plain) = open_envelope(ctx.key, &ctx.box_id, purposes.0, &summary.head_meta)?;
        let snap_env = self
            .download_sliced(
                ctx.ep,
                ctx.identity,
                ChunkFetch {
                    box_id: ctx.box_id,
                    kind: ctx.kind,
                    target: ChunkTarget::Snapshot,
                    object_id: snap_id,
                    chunk_count: summary.snap_chunks,
                    max_total_bytes: MAX_ENVELOPE_BYTES,
                },
            )
            .await?;
        let (_, snap_plain) = open_envelope(ctx.key, &ctx.box_id, purposes.1, &snap_env)?;
        Ok(Some((snap_plain, head_plain, summary.snap_generation)))
    }

    pub(crate) async fn fetch_frames_paged(
        &self,
        ctx: &MailboxCtx<'_>,
        purpose: EnvelopePurpose,
        mut page: MailboxSummary,
        mut cursor: u64,
    ) -> anyhow::Result<Vec<(u64, Zeroizing<Vec<u8>>)>> {
        let mut frames = Vec::new();
        loop {
            for item in page.frames {
                let (seq, raw) = match item {
                    FrameItem::Inline { seq, envelope } => (seq, Zeroizing::new(envelope)),
                    FrameItem::External {
                        seq,
                        chunk_id,
                        total_len,
                    } => {
                        let max_bytes = usize::try_from(total_len)
                            .unwrap_or(MAX_ENVELOPE_BYTES)
                            .min(MAX_ENVELOPE_BYTES);
                        let raw = self
                            .download_sliced(
                                ctx.ep,
                                ctx.identity,
                                ChunkFetch {
                                    box_id: ctx.box_id,
                                    kind: ctx.kind,
                                    target: ChunkTarget::Frame,
                                    object_id: chunk_id,
                                    chunk_count: 1,
                                    max_total_bytes: max_bytes,
                                },
                            )
                            .await?;
                        (seq, raw)
                    }
                };
                let (_, plain) = open_envelope(ctx.key, &ctx.box_id, purpose, &raw)?;
                cursor = cursor.max(seq);
                frames.push((seq, plain));
            }
            if !page.has_more_frames {
                break;
            }
            page = self
                .post_state(ctx.ep, ctx.identity, ctx.box_id, ctx.kind, cursor, 0)
                .await?;
        }
        Ok(frames)
    }

    /// Pull and authenticate personal mailbox updates from the first reachable
    /// endpoint.
    ///
    /// # Errors
    ///
    /// Missing gate secret, authentication/AEAD failure, or all endpoints unreachable.
    pub async fn pull_personal_state(
        &self,
        identity: &SyncIdentity,
        since_seq: u64,
    ) -> anyhow::Result<Option<PulledPersonal>> {
        let gate = require_gate(identity)?;
        let mut last_err = None;
        for ep in self.endpoints() {
            let fut = async {
                let box_id = personal_mailbox_id(gate, &ep.origin)?;
                let key = personal_envelope_key(gate, &box_id)?;
                let first = self
                    .post_state(ep, identity, box_id, MailboxKind::Personal, since_seq, 0)
                    .await?;
                if !first.exists {
                    return Ok(None);
                }
                let ctx = MailboxCtx {
                    ep,
                    identity,
                    box_id,
                    kind: MailboxKind::Personal,
                    key: &key,
                };
                let snapshot = self
                    .fetch_snapshot_pair(
                        &ctx,
                        &first,
                        (
                            EnvelopePurpose::PersonalHead,
                            EnvelopePurpose::PersonalSnapshot,
                        ),
                    )
                    .await?;
                let frames = self
                    .fetch_frames_paged(
                        &ctx,
                        EnvelopePurpose::PersonalFrame,
                        first.clone(),
                        since_seq,
                    )
                    .await?;
                let mut rekeys = Vec::with_capacity(first.rekeys.len());
                for (key_gen, env) in first.rekeys {
                    let (_, plain) =
                        open_envelope(&key, &box_id, EnvelopePurpose::PersonalRekey, &env)?;
                    rekeys.push((key_gen, plain));
                }
                let mut revocations = Vec::new();
                let now = now_ms();
                for idx in 0..first.revocation_count {
                    let one = self
                        .download_indexed_item(
                            ep,
                            identity,
                            box_id,
                            MailboxKind::Personal,
                            ChunkTarget::Revocation,
                            idx,
                            REVOCATION_WIRE_LEN,
                        )
                        .await?;
                    let rev = decode_revocation(&one)?;
                    rev.verify(identity.root_vk(), now)?;
                    revocations.push(rev);
                }
                Ok::<Option<PulledPersonal>, anyhow::Error>(Some(PulledPersonal {
                    snapshot,
                    frames,
                    rekeys,
                    revocations,
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
