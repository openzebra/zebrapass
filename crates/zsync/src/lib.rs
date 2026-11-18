//! Unified PQ TLS 1.3 zero-knowledge Git-versioned sync, live P2P relay,
//! and parallel multi-server replication for `ZebraPass`.

#![forbid(unsafe_code)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "rustls/aws-lc-rs pulls transitive getrandom 0.2"
)]

pub mod limits;

mod auth;
mod client;
mod client_shared;
mod mesh;
mod relay;
mod relay_p2p;
mod repo;
mod repo_disk;
mod server;
mod tls;
mod wire;
mod wire_aux;
mod wire_codec;
mod worker;

#[cfg(test)]
mod tests;

pub use client::{
    DecryptedSnapshot, PersonalStateInput, PulledPersonal, ZebraClient, device_announce_record_id,
    personal_storage_id,
};
pub use client_shared::{PulledShared, SharedStateInput, shared_wraps_tag, wraps_tag};
pub use relay::{connect_relay_slot, hold_relay_slot};
pub use relay_p2p::{relay_sync_initiator, relay_sync_responder};
pub use server::{ZebraServerConfig, ZebraServerHandle, start_server};
pub use tls::Endpoint;
pub use wire::{RepoKind, StorageId};
pub use worker::{WatchedRepo, WorkerEvent, WorkerMode, ZebraWorker};
