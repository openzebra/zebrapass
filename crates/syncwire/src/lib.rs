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
mod relay;
mod revocation;
mod snapshot;

pub use attestation::{
    ATTESTATION_MAGIC, ATTESTATION_WIRE_LEN, ATTESTATION_WIRE_VERSION, MAX_FRONTIER,
    decode_attestation, decode_bundle, decode_frontier, encode_attestation, encode_bundle,
    encode_frontier,
};
pub use beacon::{
    BEACON_MAGIC, BEACON_WIRE_MAX, BEACON_WIRE_VERSION, Beacon, MAX_BEACON_RELAYS,
    MAX_BEACON_VAULTS, decode_beacon, encode_beacon,
};
pub use cert::{CERT_MAGIC, CERT_WIRE_LEN, CERT_WIRE_VERSION, decode_cert, encode_cert};
pub use mux::{Direction, Header, MsgType};
pub use mux_body::{Chunk, ChunkRequest, Extent, Ping, SnapHead, Want, WhoAmI};
pub use peer::{MAX_PEERS, PEER_MAGIC, PEER_WIRE_VERSION, decode_peers, encode_peers};
pub use personal::{
    ANNOUNCE_MAGIC, ANNOUNCE_WIRE_LEN, ANNOUNCE_WIRE_VERSION, Announce, PERSONAL_FRAME_MAGIC,
    PERSONAL_FRAME_WIRE_VERSION, decode_announce, decode_personal_frame, encode_announce,
    encode_personal_frame,
};
pub use record::{RECORD_MAGIC, RECORD_WIRE_VERSION, decode_record, encode_record};
pub use relay::{
    Challenge, Claim, RELAY_MAGIC, RELAY_WIRE_VERSION, RelayHeader, RelayHint, RelayType, Reserved,
    Side as RelaySide, decode_incoming, decode_open, encode_incoming, encode_open,
};
pub use revocation::{
    REVOCATION_MAGIC, REVOCATION_WIRE_LEN, REVOCATION_WIRE_VERSION, decode_revocation,
    encode_revocation,
};
pub use snapshot::{
    MAX_SNAPSHOT_ATTESTATIONS, SNAPSHOT_MAGIC, SNAPSHOT_WIRE_VERSION, decode_snapshot,
    encode_snapshot, encode_snapshot_prefix,
};
