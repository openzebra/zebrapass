//! Post-quantum handshake and secure channel between devices of one account.
//!
//! This crate does no I/O: it turns bytes into bytes. A transport feeds it
//! the messages it receives and sends the ones it returns. After the
//! handshake both sides hold a [`Channel`] bound to the peer's certified
//! device id.

#![forbid(unsafe_code)]

mod admission;
mod auth;
mod beacon;
mod channel;
mod handshake;
mod mux;
mod relay_pow;
pub mod suite;
mod wire;

pub use admission::{CookieSecret, Load, COOKIE_WINDOW_MS, GATE_WINDOW_MS, MAX_DIFFICULTY};
pub use auth::{Account, Local, Role};
pub use beacon::{open_beacon, seal_beacon, BEACON_WINDOW_MS, MAX_BEACON};
pub use channel::{Channel, RecvHalf, SendHalf, Side, MAX_MESSAGES, MAX_PLAINTEXT, OVERHEAD};
pub use handshake::{Accept, Established, Initiator, Responder};
pub use mux::{Dispatcher, Done, Inbound, Message, Outcome, Reassembler, Reply};
pub use relay_pow::{relay_pow_ok, relay_pow_solve, relay_random, RELAY_POW_DOMAIN};

/// Offset of the kind byte in every handshake message.
pub use suite::KIND_OFFSET;
