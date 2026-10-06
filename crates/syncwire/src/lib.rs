//! Canonical wire encoding for signed sync records and device certificates.
//!
//! Every integer is big-endian and every variable part is length-prefixed.
//! Each object starts with a magic and a version. Decoding is strict: every
//! length is checked against a constant in [`limits`] before anything is
//! allocated, unknown versions are rejected, and trailing bytes are an error.

#![forbid(unsafe_code)]

mod attestation;
mod cert;
pub mod limits;
pub mod reader;
mod record;
mod revocation;

pub use attestation::{
    decode_attestation, decode_bundle, decode_frontier, encode_attestation, encode_bundle,
    encode_frontier, ATTESTATION_MAGIC, ATTESTATION_WIRE_LEN, ATTESTATION_WIRE_VERSION,
    MAX_FRONTIER,
};
pub use cert::{decode_cert, encode_cert, CERT_MAGIC, CERT_WIRE_LEN, CERT_WIRE_VERSION};
pub use record::{decode_record, encode_record, RECORD_MAGIC, RECORD_WIRE_VERSION};
pub use revocation::{
    decode_revocation, encode_revocation, REVOCATION_MAGIC, REVOCATION_WIRE_LEN,
    REVOCATION_WIRE_VERSION,
};
