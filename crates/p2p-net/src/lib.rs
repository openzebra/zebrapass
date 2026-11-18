//! A binary peer protocol over the post-quantum channel.
//!
//! A node serves the vaults it holds to authenticated members and fetches
//! from, and pushes to, peers. TCP carries only sealed frames; inside them
//! run typed request and reply messages, several in flight at once.

#![forbid(unsafe_code)]

mod beacon;
mod blob;
mod chain;
mod client;
mod client_calls;
mod dialable;
mod interfaces;
mod io;
mod limits;
pub mod nat;
mod peers;
mod personal;
mod personal_client;
mod personal_pull;
mod relay;
mod relay_client;
mod relay_flow;
mod relay_hold;
mod relay_splice;
mod relay_wire;
mod serve;
mod server;
mod service;
mod shared;
mod shared_join;
mod sync;
mod view;

pub use beacon::{BeaconConfig, BeaconIdentity, BeaconListener};
pub use chain::{deterministic_relay_hint, expand_chain_hints};
pub use client::{Conn, FetchError, Fetched};
pub use client_calls::{Push, fetch};
pub use dialable::{Dialing, Policy, Stage, Target};
pub use interfaces::{
    broadcast_targets, default_gateways, local_ips, reachable_hints, subnet_unicast_targets,
};
pub use io::{HANDSHAKE_TIMEOUT, now_ms};
pub use limits::{Limits, Tickets};
pub use nat::{
    STUN_MAGIC_COOKIE, decode_stun_binding_response, encode_stun_binding_request,
    probe_nat_pmp_gateway,
};
pub use peers::PeerBook;
pub use personal::{PersonalServe, personal_view};
pub use personal_client::{PersonalFetch, fetch_personal};
pub use relay::{Relay, RelayLimits, RelayStats};
pub use server::{authenticate, first_message, serve_requests, serve_requests_with};
pub use service::{Event, Service, Status};
pub use shared::SharedProvider;
pub use shared_join::{Joined, Known, finish_join};
pub use sync::Moved;
pub use syncwire::{Announce, RelayHint};
pub use view::{Provider, SnapshotSource, VaultView};
