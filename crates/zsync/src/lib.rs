//! Unified PQ TLS 1.3 zero-knowledge Git-versioned sync, live P2P relay,
//! and authenticated parallel multi-server replication for `ZebraPass`.

#![forbid(unsafe_code)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "rustls/aws-lc-rs pulls transitive getrandom 0.2"
)]

pub mod limits;

mod auth;
mod client;
mod client_personal;
mod client_shared;
mod mesh;
mod mesh_auth;
mod relay;
mod relay_client;
mod relay_p2p;
mod replay;
mod repo;
mod repo_diff;
mod repo_disk;
mod server;
mod tls;
mod tls_pin;
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
pub use mesh_auth::{MeshAuthConfig, MeshPeer, format_mesh_vk_hex, parse_mesh_vk_hex};
pub use relay_client::{RelayCredentials, connect_relay_slot, hold_relay_slot};
pub use relay_p2p::{relay_sync_initiator, relay_sync_responder};
pub use repo::RepoState;
pub use repo_disk::RepoStore;
pub use server::{ZebraServerConfig, ZebraServerHandle, start_server};
pub use tls::{Endpoint, resolved_addr_allowed};
pub use wire::{RepoKind, StorageId, StreamRole};
pub use worker::{WatchedRepo, WorkerEvent, WorkerMode, ZebraWorker};
