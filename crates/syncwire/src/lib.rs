//! Canonical wire encoding for signed sync records and device certificates.
//!
//! Every integer is big-endian and every variable part is length-prefixed.
//! Each object starts with a magic and a version. Decoding is strict: every
//! length is checked against a constant in [`limits`] before anything is
//! allocated, unknown versions are rejected, and trailing bytes are an error.

#![forbid(unsafe_code)]

mod attestation;
mod beacon;
mod cert;
pub mod limits;
pub mod mux;
mod mux_body;
mod peer;
mod personal;
pub mod reader;
mod record;
mod revocation;
mod snapshot;

pub use attestation::{
    decode_attestation, decode_bundle, decode_frontier, encode_attestation, encode_bundle,
    encode_frontier, ATTESTATION_MAGIC, ATTESTATION_WIRE_LEN, ATTESTATION_WIRE_VERSION,
    MAX_FRONTIER,
};
pub use beacon::{
    decode_beacon, encode_beacon, Beacon, BEACON_MAGIC, BEACON_WIRE_MAX, BEACON_WIRE_VERSION,
    MAX_BEACON_VAULTS,
};
pub use cert::{decode_cert, encode_cert, CERT_MAGIC, CERT_WIRE_LEN, CERT_WIRE_VERSION};
pub use mux::{Direction, Header, MsgType};
pub use mux_body::{Chunk, ChunkRequest, Extent, Ping, SnapHead, Want, WhoAmI};
pub use peer::{decode_peers, encode_peers, MAX_PEERS, PEER_MAGIC, PEER_WIRE_VERSION};
pub use personal::{
    decode_announce, decode_personal_frame, encode_announce, encode_personal_frame, Announce,
    ANNOUNCE_MAGIC, ANNOUNCE_WIRE_LEN, ANNOUNCE_WIRE_VERSION, PERSONAL_FRAME_MAGIC,
    PERSONAL_FRAME_WIRE_VERSION,
};
pub use record::{decode_record, encode_record, RECORD_MAGIC, RECORD_WIRE_VERSION};
pub use revocation::{
    decode_revocation, encode_revocation, REVOCATION_MAGIC, REVOCATION_WIRE_LEN,
    REVOCATION_WIRE_VERSION,
};
pub use snapshot::{
    decode_snapshot, encode_snapshot, encode_snapshot_prefix, MAX_SNAPSHOT_ATTESTATIONS,
    SNAPSHOT_MAGIC, SNAPSHOT_WIRE_VERSION,
};
