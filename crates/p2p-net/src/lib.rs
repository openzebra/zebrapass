//! A binary peer protocol over the post-quantum channel.
//!
//! A node serves the vaults it holds to authenticated members and fetches
//! from, and pushes to, peers. TCP carries only sealed frames; inside them
//! run typed request and reply messages, several in flight at once.

#![forbid(unsafe_code)]

mod beacon;
mod blob;
mod client;
mod client_calls;
mod dialable;
mod interfaces;
mod io;
mod limits;
mod peers;
mod personal;
mod personal_client;
mod personal_pull;
mod relay;
mod relay_client;
mod relay_dir;
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
pub use client::{Conn, FetchError, Fetched};
pub use client_calls::{fetch, Push};
pub use dialable::{Dialing, Policy, Target};
pub use interfaces::{broadcast_targets, local_ips, reachable_hints};
pub use io::{now_ms, HANDSHAKE_TIMEOUT};
pub use limits::{Limits, Tickets};
pub use peers::PeerBook;
pub use personal::{personal_view, PersonalServe};
pub use personal_client::{fetch_personal, PersonalFetch};
pub use relay::{Relay, RelayLimits, RelayStats};
pub use relay_dir::{
    closest_relays, default_relays, deterministic_relay_hint, embedded_relays, haversine_km,
    parse_relays_toml, RelayEntry, EMBEDDED_RELAYS_TOML,
};
pub use server::{authenticate, first_message, serve_requests, serve_requests_with};
pub use service::{Event, Service, Status};
pub use shared::SharedProvider;
pub use shared_join::{finish_join, Joined, Known};
pub use sync::Moved;
pub use syncwire::{Announce, RelayHint};
pub use view::{Provider, SnapshotSource, VaultView};
