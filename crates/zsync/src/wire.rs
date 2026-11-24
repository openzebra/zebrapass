//! Binary protocol types and length-framed I/O over PQ TLS 1.3 streams.

use pq::{SYNC_SIG_LEN, SYNC_VK_LEN};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::limits::{WIRE_MAGIC, WIRE_VERSION};

/// Canonical 512-bit (`[u8; 64]`) server-independent repository identifier.
pub type StorageId = [u8; 64];

/// First byte on every multiplexed TLS stream selecting the protocol role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StreamRole {
    /// Client Git-like frontier + delta sync RPCs.
    ClientRpc = 1,
    /// Client authenticated push-notification stream.
    ClientWatch = 2,
    /// Zero-storage live P2P stream relay (`Reserve` / `Connect` / `Accept`).
    Relay = 3,
    /// Authenticated server-to-server mesh replication & anti-entropy.
    PeerMesh = 4,
}

impl TryFrom<u8> for StreamRole {
    type Error = anyhow::Error;

    fn try_from(v: u8) -> anyhow::Result<Self> {
        match v {
            1 => Ok(Self::ClientRpc),
            2 => Ok(Self::ClientWatch),
            3 => Ok(Self::Relay),
            4 => Ok(Self::PeerMesh),
            _ => Err(anyhow::anyhow!("unknown stream role")),
        }
    }
}

/// Repository namespace kind.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RepoKind {
    Personal = 1,
    Shared = 2,
}

impl TryFrom<u8> for RepoKind {
    type Error = anyhow::Error;

    fn try_from(v: u8) -> anyhow::Result<Self> {
        match v {
            1 => Ok(Self::Personal),
            2 => Ok(Self::Shared),
            _ => Err(anyhow::anyhow!("unknown repo kind")),
        }
    }
}

/// Version identifier for a vault wrap-directory + base snapshot head.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HeadVer {
    pub generation: u64,
    pub commit_tag: [u8; 32],
    pub origin_device: [u8; 16],
}

/// Signed encrypted vault wrap-header + snapshot at [`HeadVer`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedHead {
    pub ver: HeadVer,
    pub head_meta: Vec<u8>,
    pub snapshot_env: Vec<u8>,
    pub master_grant: Option<Vec<u8>>,
    pub signature: Box<[u8; SYNC_SIG_LEN]>,
}

/// Version identifier for one record frame (`revision` monotonic; ties broken
/// deterministically by `(origin_device, frame_hash)`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RecordVer {
    pub revision: u64,
    pub origin_device: [u8; 16],
    pub frame_hash: [u8; 32],
    pub record_id: u32,
}

impl RecordVer {
    /// Deterministic partial order key for comparing two revisions of the same record.
    #[must_use]
    pub const fn order_key(&self) -> (u64, [u8; 16]) {
        (self.revision, self.origin_device)
    }
}

/// Signed, outer-sealed per-record commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordCommit {
    pub ver: RecordVer,
    pub key_generation: u64,
    pub envelope: Vec<u8>,
    pub signature: Box<[u8; SYNC_SIG_LEN]>,
    pub signer_device: [u8; 16],
}

/// Signed hybrid-PQ `VK` or shared-seed rekey grant targeted at `target_device`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRekey {
    pub generation: u64,
    pub origin_device: [u8; 16],
    pub target_device: [u8; 16],
    pub envelope: Vec<u8>,
    pub signature: Box<[u8; SYNC_SIG_LEN]>,
}

/// Client authentication attached to a [`RepoFrontier`] request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontierAuth {
    pub timestamp_s: u64,
    pub nonce: [u8; 16],
    pub cert_wire: Vec<u8>,
    pub signature: Box<[u8; SYNC_SIG_LEN]>,
}

/// Compact Git-like frontier describing what a device or peer server holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepoFrontier {
    pub kind: RepoKind,
    pub storage_id: StorageId,
    pub personal_anchor: Option<Vec<u8>>,
    pub root_vk: Option<Box<[u8; SYNC_VK_LEN]>>,
    pub shared_proof: Option<Vec<u8>>,
    pub auth: Option<FrontierAuth>,
    pub certs: Vec<[u8; 16]>,
    pub head: Option<HeadVer>,
    pub records: Vec<RecordVer>,
    pub rev_count: u32,
    pub member_count: u32,
    pub dev_key_count: u16,
}

/// Missing objects the receiver asks the sender to push after comparing frontiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Wanted {
    pub record_ids: Vec<u32>,
    pub flags: u8,
}

impl Wanted {
    pub const NEED_HEAD: u8 = 1;
    pub const NEED_MEMBERS: u8 = 1 << 1;
    pub const NEED_REVS: u8 = 1 << 2;
    pub const NEED_DEVICE_KEYS: u8 = 1 << 3;
    pub const ALL_FLAGS: u8 =
        Self::NEED_HEAD | Self::NEED_MEMBERS | Self::NEED_REVS | Self::NEED_DEVICE_KEYS;

    #[must_use]
    pub const fn bit(mask: u8, cond: bool) -> u8 {
        if cond { mask } else { 0 }
    }

    #[must_use]
    pub const fn need_head(&self) -> bool {
        self.flags & Self::NEED_HEAD != 0
    }

    #[must_use]
    pub const fn need_members(&self) -> bool {
        self.flags & Self::NEED_MEMBERS != 0
    }

    #[must_use]
    pub const fn need_revs(&self) -> bool {
        self.flags & Self::NEED_REVS != 0
    }

    #[must_use]
    pub const fn need_device_keys(&self) -> bool {
        self.flags & Self::NEED_DEVICE_KEYS != 0
    }

    /// Whether the sender has nothing left to upload.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.flags == 0 && self.record_ids.is_empty()
    }
}

/// Verified encrypted objects transferred between client and servers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncDelta {
    pub kind: RepoKind,
    pub storage_id: StorageId,
    pub personal_anchor: Option<Vec<u8>>,
    pub root_vk: Option<Box<[u8; SYNC_VK_LEN]>>,
    pub shared_proof: Option<Vec<u8>>,
    pub certs: Vec<Vec<u8>>,
    pub device_keys: Vec<Vec<u8>>,
    pub revocations: Vec<Vec<u8>>,
    pub member_entries: Vec<Vec<u8>>,
    pub head: Option<SignedHead>,
    pub rekeys: Vec<SignedRekey>,
    pub records: Vec<RecordCommit>,
}

impl SyncDelta {
    /// Empty delta for `(kind, storage_id)`.
    #[must_use]
    pub const fn empty(kind: RepoKind, storage_id: StorageId) -> Self {
        Self {
            kind,
            storage_id,
            personal_anchor: None,
            root_vk: None,
            shared_proof: None,
            certs: Vec::new(),
            device_keys: Vec::new(),
            revocations: Vec::new(),
            member_entries: Vec::new(),
            head: None,
            rekeys: Vec::new(),
            records: Vec::new(),
        }
    }

    /// Whether no state-changing objects are included.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.certs.is_empty()
            && self.device_keys.is_empty()
            && self.revocations.is_empty()
            && self.member_entries.is_empty()
            && self.head.is_none()
            && self.rekeys.is_empty()
            && self.records.is_empty()
    }
}

/// Authenticated subscription to push notifications on [`StreamRole::ClientWatch`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchSub {
    pub timestamp_s: u64,
    pub device_id: [u8; 16],
    pub nonce: [u8; 16],
    pub repos: Vec<(RepoKind, StorageId)>,
    pub cert_wire: Vec<u8>,
    pub personal_anchor: Option<Vec<u8>>,
    pub root_vk: Option<Box<[u8; SYNC_VK_LEN]>>,
    pub shared_proofs: Vec<Vec<u8>>,
    pub signature: Box<[u8; SYNC_SIG_LEN]>,
}

/// Lightweight notification pushed when a watched repository updates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchEvent {
    pub kind: RepoKind,
    pub storage_id: StorageId,
}

/// Relay control messages on [`StreamRole::Relay`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayMsg {
    Reserve {
        timestamp_s: u64,
        slot: [u8; 16],
        nonce: [u8; 16],
        slot_vk: Box<[u8; SYNC_VK_LEN]>,
        signature: Box<[u8; SYNC_SIG_LEN]>,
    },
    Connect {
        slot: [u8; 16],
    },
    Accept {
        conn_id: [u8; 16],
    },
    Ping(u64),
    Reserved {
        observed: String,
        ttl_s: u16,
    },
    Incoming {
        conn_id: [u8; 16],
    },
    SpliceOk,
    Offline,
    Pong(u64),
}

/// Compact per-repo digest exchanged between peer mesh servers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepoDigest {
    pub kind: RepoKind,
    pub storage_id: StorageId,
    pub digest: [u8; 32],
}

/// Wire tag values for `write_wire` / `read_wire`.
pub const TAG_FRONTIER: u8 = 1;
pub const TAG_DIFF: u8 = 2;
pub const TAG_DELTA: u8 = 3;
pub const TAG_ACK: u8 = 4;
pub const TAG_WATCH_SUB: u8 = 5;
pub const TAG_WATCH_EVENT: u8 = 6;
pub const TAG_RELAY: u8 = 7;
pub const TAG_MESH_DIGESTS: u8 = 8;
pub const TAG_MESH_FRONTIER: u8 = 10;
pub const TAG_MESH_DELTA: u8 = 11;
pub const TAG_MESH_HELLO: u8 = 12;
pub const TAG_MESH_AUTH: u8 = 13;

/// Write one length-prefixed wire frame (`ZBS3 || ver || tag || len_be || body`).
///
/// # Errors
///
/// Frame larger than `u32::MAX` or I/O error.
pub async fn write_wire<W: AsyncWrite + Unpin>(
    w: &mut W,
    tag: u8,
    payload: &[u8],
) -> anyhow::Result<()> {
    let len = u32::try_from(payload.len())?;
    let mut header = [0u8; 10];
    if let Some((magic, rest)) = header.split_at_mut_checked(4) {
        magic.copy_from_slice(&WIRE_MAGIC);
        if let Some((meta, len_bytes)) = rest.split_at_mut_checked(2) {
            meta.copy_from_slice(&[WIRE_VERSION, tag]);
            len_bytes.copy_from_slice(&len.to_be_bytes());
        }
    }
    w.write_all(&header).await?;
    if !payload.is_empty() {
        w.write_all(payload).await?;
    }
    w.flush().await?;
    Ok(())
}

/// Read one bounded length-prefixed wire frame. Checks magic, version, and `len <= max_len`
/// before allocating memory.
///
/// # Errors
///
/// Bad magic/version, oversized length, EOF, or I/O error.
pub async fn read_wire<R: AsyncRead + Unpin>(
    r: &mut R,
    max_len: usize,
) -> anyhow::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 10];
    r.read_exact(&mut header).await?;
    let (magic, rest) = header
        .split_at_checked(4)
        .ok_or_else(|| anyhow::anyhow!("corrupt wire header"))?;
    if magic != WIRE_MAGIC {
        anyhow::bail!("bad wire magic");
    }
    let (meta, len_bytes) = rest
        .split_at_checked(2)
        .ok_or_else(|| anyhow::anyhow!("corrupt wire header"))?;
    let [ver, tag] = *meta else {
        anyhow::bail!("corrupt wire header");
    };
    if ver != WIRE_VERSION {
        anyhow::bail!("unsupported wire version");
    }
    let raw_len: [u8; 4] = len_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("corrupt wire length"))?;
    let len = usize::try_from(u32::from_be_bytes(raw_len))?;
    if len > max_len {
        anyhow::bail!("wire frame exceeds limit");
    }
    let mut body = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut body).await?;
    }
    Ok((tag, body))
}
