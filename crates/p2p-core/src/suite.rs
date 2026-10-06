//! The one cipher suite and the exact size of every handshake message.
//!
//! There is no negotiation: a peer that sends another suite id is refused,
//! so there is nothing to downgrade.

use frame::{CASCADE_OVERHEAD, HEADER_LEN as FRAME_HEADER_LEN, TAG_LEN};
use pq::{KEM_CT_LEN, PQ_PK_LEN, SYNC_SIG_LEN};
use syncwire::CERT_WIRE_LEN;

/// First four bytes of every handshake message.
pub const MAGIC: [u8; 4] = *b"ZPHS";

/// Handshake wire version.
pub const WIRE_VERSION: u16 = 1;

/// ML-KEM-768 + P-256 ECDH key exchange, ML-DSA-65 authentication, and the
/// AEGIS-256 / Kuznyechik cascade for sealed payloads.
pub const SUITE: u16 = 0x0001;

/// Message kinds.
pub const KIND_HELLO: u8 = 1;
pub const KIND_REPLY: u8 = 2;
pub const KIND_FINISH: u8 = 3;
pub const KIND_CHALLENGE: u8 = 4;
pub const KIND_SOLVED: u8 = 5;

/// Offset of the kind byte in every message.
pub const KIND_OFFSET: usize = 8;

/// Length of each side's random nonce.
pub const NONCE_LEN: usize = 32;

/// Magic, version, suite, kind.
pub const HEADER_LEN: usize = 4 + 2 + 2 + 1;

/// Length of an uncompressed P-256 point.
pub const EC_PUB_LEN: usize = 65;

/// Length of the gate tag (HMAC-SHA256).
pub const GATE_TAG_LEN: usize = 32;

/// The part of a hello the gate tag covers: header, EC share, KEM
/// encapsulation key, nonce, timestamp.
pub const HELLO_BODY_LEN: usize = HEADER_LEN + EC_PUB_LEN + PQ_PK_LEN + NONCE_LEN + 8;

/// Initiator hello: the body and its gate tag.
pub const HELLO_LEN: usize = HELLO_BODY_LEN + GATE_TAG_LEN;

/// Puzzle cookie: difficulty, issue time, MAC.
pub const COOKIE_LEN: usize = 1 + 8 + 32;

/// Responder puzzle challenge.
pub const CHALLENGE_LEN: usize = HEADER_LEN + COOKIE_LEN;

/// Initiator answer to a challenge: the cookie, the solution, the hello.
pub const SOLVED_LEN: usize = HEADER_LEN + COOKIE_LEN + 8 + HELLO_LEN;

/// The unsealed part of the responder reply: header, EC share, KEM
/// ciphertext, nonce.
pub const REPLY_FIXED_LEN: usize = HEADER_LEN + EC_PUB_LEN + KEM_CT_LEN + NONCE_LEN;

/// A certificate followed by an ML-DSA signature.
pub const PROOF_LEN: usize = CERT_WIRE_LEN + SYNC_SIG_LEN;

/// A proof sealed as one cascade frame.
pub const SEALED_PROOF_LEN: usize = FRAME_HEADER_LEN + PROOF_LEN + CASCADE_OVERHEAD + TAG_LEN;

/// Whole responder reply.
pub const REPLY_LEN: usize = REPLY_FIXED_LEN + SEALED_PROOF_LEN;

/// Whole initiator finish.
pub const FINISH_LEN: usize = HEADER_LEN + SEALED_PROOF_LEN;

/// Largest handshake message, for the transport to bound its read.
pub const MAX_HANDSHAKE_MSG: usize = REPLY_LEN;

const _: () = assert!(SOLVED_LEN <= MAX_HANDSHAKE_MSG);
