//! The membership log of a shared vault.
//!
//! A shared vault belongs to several accounts. Who they are, and what each
//! may do, is a signed, hash-chained log that every member replays and
//! verifies for itself. A change is valid only if a device of a current owner
//! signed it, so no peer and no server can add a member or promote one.

#![forbid(unsafe_code)]

mod entry;
mod log;
mod role;
mod wire;

pub use entry::{rotation_commit, sign_entry, Action, Entry};
pub use log::{Member, MemberLog, MAX_ENTRIES, MAX_MEMBERS};
pub use role::Role;
pub use wire::{ENTRY_MAGIC, ENTRY_WIRE_LEN, ENTRY_WIRE_VERSION};
