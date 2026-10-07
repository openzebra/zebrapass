//! Standard and custom field tags.
//!
//! `0x0100..=0x7FFF` is the standard range; `0x8000..=0xFFFF` is the custom
//! range where the field value carries a UTF-8 name. `0x0205..=0x0206`
//! carry the sync cursor: the seen generation and commit tag used for
//! rollback detection.

/// Title (`Text`).
pub const TAG_TITLE: u16 = 0x0101;

/// URL (`Text`).
pub const TAG_URL: u16 = 0x0102;

/// Username (`Text`).
pub const TAG_USERNAME: u16 = 0x0103;

/// Email (`Text`).
pub const TAG_EMAIL: u16 = 0x0104;

/// Password (`Secret`).
pub const TAG_PASSWORD: u16 = 0x0105;

/// Notes (`Text`).
pub const TAG_NOTES: u16 = 0x0106;

/// TOTP seed (`Secret`).
pub const TAG_TOTP: u16 = 0x0107;

/// Local device id, 16 bytes (`Bytes`).
pub const TAG_DEVICE_ID: u16 = 0x0201;

/// Uniform client id derived from the master seed, 64 bytes (`Bytes`).
pub const TAG_CLIENT_ID: u16 = 0x0202;

/// Creation time in unix milliseconds (`Bytes`, 8-byte little-endian `u64`).
pub const TAG_CREATED_AT_MS: u16 = 0x0203;

/// Vault display name (`Text`).
pub const TAG_NAME: u16 = 0x0204;

/// Last accepted vault generation, 8 little-endian bytes (`Bytes`).
pub const TAG_SEEN_GENERATION: u16 = 0x0205;

/// Last accepted vault commit tag, 32 bytes (`Bytes`).
pub const TAG_SEEN_COMMIT: u16 = 0x0206;

// Tag `0x0207` (the retired X25519 device book) is never reused.

/// Auto-lock delay in seconds, 2 little-endian bytes (`Bytes`).
pub const TAG_PREF_LOCK_AFTER: u16 = 0x0210;

/// Clipboard clear delay in seconds, 1 byte (`Bytes`).
pub const TAG_PREF_CLIP_CLEAR: u16 = 0x0211;

/// Reveal auto-hide delay in seconds, 1 byte (`Bytes`).
pub const TAG_PREF_REVEAL_HIDE: u16 = 0x0212;

/// Color theme id, 1 byte (`Bytes`).
pub const TAG_PREF_THEME: u16 = 0x0213;

/// Interface switches (animation, ASCII, focus lock), 1 byte (`Bytes`).
pub const TAG_PREF_FLAGS: u16 = 0x0214;

/// Sync mode, 1 byte (`Bytes`).
pub const TAG_PREF_SYNC_MODE: u16 = 0x0215;

/// Sync server origin, `https://host[:port]` (`Text`).
pub const TAG_PREF_SERVER_ORIGIN: u16 = 0x0216;

/// Pinned sync server key fingerprint, 32 bytes (`Bytes`).
pub const TAG_PREF_SERVER_PIN: u16 = 0x0217;

/// Where this device's sync node listens, 1 byte (`Bytes`).
pub const TAG_PREF_P2P_LISTEN: u16 = 0x0218;

/// The public `ip:port` this device tells other members to reach it at, text
/// (`Text`).
pub const TAG_PREF_P2P_ADVERTISE: u16 = 0x0219;

/// Record copy usage on this device: packed 16-byte entries
/// `id u32 LE ‖ count u32 LE ‖ last_ms u64 LE`, sorted by id (`Bytes`).
pub const TAG_USAGE: u16 = 0x0220;

// Tag `0x0230` is reserved: the device signing seed is never put in a
// document, it is the first 32 bytes of the sealed sync identity payload.

/// Account root ML-DSA verifying key, 1952 bytes (`Bytes`).
pub const TAG_SYNC_ROOT_VK: u16 = 0x0231;

/// This device's root-signed certificate, as encoded by `syncwire` (`Bytes`).
pub const TAG_SYNC_OWN_CERT: u16 = 0x0232;

/// First of the peer certificate tags: each field is one encoded
/// certificate (`Bytes`), contiguous from here.
pub const TAG_SYNC_PEER_MIN: u16 = 0x0240;

/// Number of peer certificate tags.
pub const SYNC_PEER_TAGS: usize = 32;

/// Marks a personal-vault record as a reference to a shared vault, 1 byte
/// (`Bytes`).
pub const TAG_SHARED_MARK: u16 = 0x0270;

/// The shared vault's id, 16 bytes (`Bytes`).
pub const TAG_SHARED_VAULT_ID: u16 = 0x0271;

/// Hash of the shared vault's first member log entry, 32 bytes (`Bytes`).
pub const TAG_SHARED_ANCHOR: u16 = 0x0272;

/// The shared vault's seed, 64 bytes (`Secret`).
pub const TAG_SHARED_SEED: u16 = 0x0273;

/// Where the inviter's device was reachable, `host:port` entries joined by
/// newlines (`Text`).
pub const TAG_SHARED_HINTS: u16 = 0x0274;

/// How many times the shared seed was replaced when this one was current,
/// 4 bytes little-endian (`Bytes`).
pub const TAG_SHARED_EPOCH: u16 = 0x0275;

/// Hash of the newest member log entry the inviter signed for, 32 bytes
/// (`Bytes`). Present while the device has not yet fetched the full log.
pub const TAG_SHARED_HEAD: u16 = 0x0276;

/// The inviter's account id followed by its root key (`Bytes`). Present with
/// [`TAG_SHARED_HEAD`].
pub const TAG_SHARED_INTRODUCER: u16 = 0x0277;

/// First of the retired shared seeds, newest first, contiguous from here
/// (`Secret`). A device keeps them to open files and logs sealed before the
/// last rotation reached it.
pub const TAG_SHARED_RETIRED_MIN: u16 = 0x0280;

/// Number of retired-seed tags.
pub const SHARED_RETIRED_TAGS: usize = 8;

/// First of the signed revocation tags: each field is one encoded
/// revocation (`Bytes`), contiguous from here.
pub const TAG_SYNC_REVOKED_MIN: u16 = 0x0260;

/// Number of revocation tags.
pub const SYNC_REVOKED_TAGS: usize = 64;

/// First of the last-seen tags, contiguous from here (`Bytes`).
///
/// Each field packs up to [`SYNC_LAST_SEEN_PER_TAG`] 12-byte entries
/// `record_id u32 LE ‖ revision u64 LE`, sorted by id across the whole run.
/// One field is capped at 65535 bytes, hence the shards.
pub const TAG_SYNC_LAST_SEEN_MIN: u16 = 0x0300;

/// Number of last-seen tags (16384 records).
pub const SYNC_LAST_SEEN_TAGS: usize = 4;

/// Entries in one full last-seen field.
pub const SYNC_LAST_SEEN_PER_TAG: usize = 4096;

/// Name of the custom field holding comma-separated tags.
pub const CUSTOM_TAGS: &str = "tags";

/// Name of the custom field marking a favorite (`"1"`).
pub const CUSTOM_FAVORITE: &str = "favorite";

/// First custom tag. Custom values carry `name_len ‖ name ‖ data`.
pub const TAG_CUSTOM_MIN: u16 = 0x8000;

/// First standard tag, inclusive.
pub const TAG_STANDARD_MIN: u16 = 0x0100;

/// Last standard tag, inclusive.
pub const TAG_STANDARD_MAX: u16 = 0x7FFF;

/// `true` when `tag` is in the custom range.
#[must_use]
pub const fn is_custom(tag: u16) -> bool {
    tag >= TAG_CUSTOM_MIN
}
