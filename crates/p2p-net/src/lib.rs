//! HTTP/2 over the post-quantum channel.
//!
//! A node serves the vaults it holds to authenticated members and fetches
//! from peers. TCP carries only sealed frames; the HTTP/2 inside is plain
//! `h2` over an in-memory pipe that the channel seals and opens.

#![forbid(unsafe_code)]

mod client;
mod dialable;
mod io;
mod limits;
mod peers;
mod personal;
mod personal_client;
mod personal_pull;
mod server;
mod service;
mod shared;
mod shared_join;
mod sync;
mod view;

pub use client::{fetch, fetch_paths, Conn, FetchError, Fetched};
pub use dialable::{Dialing, Policy};
pub use io::{now_ms, HANDSHAKE_TIMEOUT};
pub use limits::{Limits, Tickets};
pub use peers::PeerBook;
pub use personal::{personal_view, PersonalServe};
pub use personal_client::{fetch_personal, PersonalFetch};
pub use server::{authenticate, first_message, serve_requests, serve_requests_with};
pub use service::{reachable_hints, Event, Service, Status};
pub use shared::SharedProvider;
pub use shared_join::{finish_join, Joined, Known};
pub use sync::Moved;
pub use syncwire::Announce;
pub use view::{Provider, VaultView};
