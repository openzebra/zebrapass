//! The puzzle a relay sets before it spends anything on a request.
//!
//! A solution is a nonce for which `SHA-256(domain ‖ salt ‖ id ‖ nonce)`
//! starts with at least `difficulty` zero bits. The salt belongs to one
//! connection and the id names what is asked for, so a solution cannot be
//! reused for another request. Hashing here is the work function, not a MAC
//! or a key derivation.

use sha2::{Digest, Sha256};

/// Domain of the puzzle hash.
pub const RELAY_POW_DOMAIN: &[u8] = b"brby/v2/p2p-relay-pow";

fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in hash {
        if *byte == 0 {
            bits += 8;
        } else {
            return bits + byte.leading_zeros();
        }
    }
    bits
}

fn digest(salt: &[u8; 16], id: &[u8; 16], nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RELAY_POW_DOMAIN);
    hasher.update(salt);
    hasher.update(id);
    hasher.update(nonce.to_be_bytes());
    hasher.finalize().into()
}

/// Whether `nonce` solves the puzzle of `salt` for `id` at `difficulty`.
#[must_use]
pub fn relay_pow_ok(salt: &[u8; 16], id: &[u8; 16], nonce: u64, difficulty: u8) -> bool {
    leading_zero_bits(&digest(salt, id, nonce)) >= u32::from(difficulty)
}

/// The first nonce that solves the puzzle, which takes about
/// `2^difficulty` hashes.
#[must_use]
pub fn relay_pow_solve(salt: &[u8; 16], id: &[u8; 16], difficulty: u8) -> Option<u64> {
    (0..=u64::MAX).find(|nonce| relay_pow_ok(salt, id, *nonce, difficulty))
}

/// Sixteen random bytes from the operating system: a puzzle salt, a slot, a
/// connection id. Failure is an error, never a fallback.
///
/// # Errors
///
/// The operating system has no entropy to give.
pub fn relay_random() -> anyhow::Result<[u8; 16]> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
    Ok(bytes)
}
