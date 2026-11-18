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
mod uri;

pub use card::{CARD_PREFIX, CARD_WIRE_LEN, ContactCard, MAX_CARD_AGE_MS};
pub use fingerprint::{Fingerprint, account_fingerprint, vault_fingerprint, vault_number};
pub use invitation::{
    INVITE_PREFIX, Invitation, Inviter, MAX_HINT, MAX_HINTS, MAX_INVITE_WIRE_LEN, MAX_NAME, Offer,
    Opened,
};
pub use text::{decode as decode_text, encode as encode_text};
pub use uri::{
    MAX_SHARE_URI_ADDR, MAX_SHARE_URI_LEN, SHARE_URI_HOST, SHARE_URI_SCHEME, SHARE_URI_VERSION,
    ShareUri,
};
