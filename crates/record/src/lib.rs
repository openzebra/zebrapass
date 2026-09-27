//! Versioned TLV document stored inside a revision frame.
//!
//! A [`Document`] is the plaintext payload of one frame: a schema version
//! followed by typed fields. Standard tags (`0x0100..=0x7FFF`) carry the
//! well-known record fields; custom tags (`0x8000..=0xFFFF`) carry a UTF-8
//! name plus opaque data. Fields with unknown tags — including tags this
//! build does not know — are preserved verbatim and re-emitted on encode,
//! so an older application never destroys the data of a newer one.

mod doc;
mod limits;
mod tags;

pub use doc::{Document, Field, ValueType};
pub use limits::{MAX_CUSTOM_NAME, MAX_DOC_LEN, MAX_FIELDS, SCHEMA_VERSION};
pub use tags::*;
