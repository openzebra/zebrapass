//! HTTP/2 over the post-quantum channel.
//!
//! A node serves the vaults it holds to authenticated members and fetches
//! from peers. TCP carries only sealed frames; the HTTP/2 inside is plain
//! `h2` over an in-memory pipe that the channel seals and opens.

#![forbid(unsafe_code)]

mod client;
mod io;
mod peers;
mod server;
mod service;
mod shared;
mod sync;
mod view;

pub use client::{fetch, fetch_paths, Conn, FetchError, Fetched};
pub use io::{now_ms, HANDSHAKE_TIMEOUT};
pub use peers::PeerBook;
pub use server::{authenticate, first_message, serve_requests};
pub use service::{reachable_hints, Event, Service, Status};
pub use shared::{finish_join, Joined, Known, SharedProvider};
pub use sync::Moved;
pub use view::{Provider, VaultView};
