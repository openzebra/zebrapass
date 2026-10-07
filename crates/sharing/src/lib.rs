//! Contact cards and invitations: how people join a shared vault.
//!
//! The person to be added gives a *contact card*; the owner pastes it, adds
//! them to the member log and gives back an *invitation* that carries the
//! vault number, the member log and the vault's seed sealed to the invitee's
//! device. Both travel as text, so they can be copied and pasted; both are
//! authenticated by a short fingerprint the two people compare aloud.

#![forbid(unsafe_code)]

mod card;
mod fingerprint;
mod invitation;
mod text;

pub use card::{ContactCard, CARD_PREFIX, CARD_WIRE_LEN, MAX_CARD_AGE_MS};
pub use fingerprint::{account_fingerprint, vault_fingerprint, vault_number, Fingerprint};
pub use invitation::{
    Invitation, Inviter, Offer, Opened, INVITE_PREFIX, MAX_HINT, MAX_HINTS, MAX_INVITE_WIRE_LEN,
    MAX_NAME,
};
pub use text::{decode as decode_text, encode as encode_text};
