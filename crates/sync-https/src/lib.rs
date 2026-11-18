//! Zero-knowledge post-quantum HTTPS/WSS + `SplitHTTP` sync and cloud backup
//! client and self-hostable server (`X25519MLKEM768` TLS 1.3, `WebTunnel` URL
//! camouflage, `socks5h://`/`http://` proxy tunneling, outer Cascade `0xA005`
//! envelopes, and `ML-DSA-65` authenticated mailbox operations).

#![forbid(unsafe_code)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "rustls and aws-lc-rs transitively pull getrandom 0.2 alongside workspace getrandom 0.4"
)]

pub mod auth;
pub mod b64;
pub mod camouflage;
pub mod client;
pub mod client_backup;
pub mod client_ops;
pub mod client_shared;
pub mod envelope;
pub mod http_wire;
pub mod limits;
pub mod proxy;
pub mod server;
mod store;
mod store_apply;
mod store_disk;
mod store_ops;
pub mod tls;
pub mod wire;
pub mod wire_reply;
pub mod wire_rpc;
pub mod worker;
pub mod ws_wire;

pub use client::SyncClient;
pub use client_ops::{DecryptedSnapshot, PulledPersonal, PulledShared};
pub use envelope::{EnvelopePurpose, open_envelope, seal_envelope};
pub use proxy::{ProxyConfig, SyncEndpoint};
pub use server::{SyncServerConfig, SyncServerHandle, start_server};
pub use tls::NegotiatedTls;
pub use wire::{ChunkTarget, MailboxKind, OpPayload};
pub use wire_reply::{ChunkReply, FrameItem, MailboxSummary, OpReply, OpStatus, PushEvent};
pub use worker::{ServerSyncWorker, WatchedBox, WorkerEvent, WorkerTransport};
