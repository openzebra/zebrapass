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
