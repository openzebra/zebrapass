//! Cheap checks that run before any asymmetric work.
//!
//! Two layers protect the responder from being made to do expensive work:
//!
//! 1. The gate: every hello carries an HMAC under a key only the intended
//!    peers hold, and a timestamp. A stranger is rejected after one HMAC,
//!    and is not even given a puzzle.
//! 2. The puzzle: under load the responder answers a gated hello with a
//!    stateless cookie and asks for a SHA-256 hashcash solution first. A
//!    solution costs the client about `2^difficulty` hashes and costs the
//!    responder one hash and one HMAC to check, so a flood of guesses is
//!    cheap to refuse. A memory-hard puzzle would not be: checking a guess
//!    would cost the responder as much as making it.

use anyhow::{anyhow, Result};
use hmac::{Hmac, KeyInit, Mac};
use secret::{ct_eq_32, Secret};
use sha2::{Digest, Sha256};

use crate::auth::failed;
use crate::suite::GATE_TAG_LEN;

type HmacSha256 = Hmac<Sha256>;

const DOMAIN_GATE: &[u8] = b"brby/v2/p2p-gate";
const DOMAIN_COOKIE: &[u8] = b"brby/v2/p2p-cookie";
const DOMAIN_POW: &[u8] = b"brby/v2/p2p-pow";
const DOMAIN_HELLO: &[u8] = b"brby/v2/p2p-hello";

/// How far a hello timestamp may be from the responder's clock.
pub const GATE_WINDOW_MS: u64 = 30_000;

/// How long a puzzle cookie stays valid.
pub const COOKIE_WINDOW_MS: u64 = 60_000;

/// Hardest puzzle a responder issues and a client agrees to solve.
pub const MAX_DIFFICULTY: u8 = 24;

/// The responder's current load: the puzzle difficulty in leading zero bits,
/// `0` for no puzzle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Load {
    pub difficulty: u8,
}

/// The secret that signs puzzle cookies. Rotate it periodically; cookies
/// issued under an old one simply stop verifying.
#[derive(Debug)]
pub struct CookieSecret(Secret<[u8; 32]>);

impl CookieSecret {
    /// Draw a fresh secret.
    ///
    /// # Errors
    ///
    /// `os entropy failed` when the OS RNG fails.
    pub fn generate() -> Result<Self> {
        let mut secret = Secret::new([0u8; 32]);
        getrandom::fill(secret.expose_mut()).map_err(|_| anyhow!("os entropy failed"))?;
        Ok(Self(secret))
    }
}

/// A stateless puzzle cookie.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cookie {
    pub difficulty: u8,
    pub issued_ms: u64,
    pub mac: [u8; 32],
}

fn hmac(key: &[u8]) -> Result<HmacSha256> {
    HmacSha256::new_from_slice(key).map_err(|_| anyhow!("mac key"))
}

/// The gate tag over the hello body.
///
/// # Errors
///
/// `mac key` when the key is rejected by HMAC (never for a 32-byte key).
pub fn gate_tag(key: &Secret<[u8; 32]>, body: &[u8]) -> Result<[u8; GATE_TAG_LEN]> {
    let mut mac = hmac(key.expose())?;
    mac.update(DOMAIN_GATE);
    mac.update(body);
    Ok(mac.finalize().into_bytes().into())
}

/// Accept a hello only when its timestamp is fresh and its tag verifies under
/// one of `keys`. All keys are tried, so the time taken does not say which
/// one matched.
///
/// # Errors
///
/// `handshake failed` for every failure.
pub fn check_gate(
    keys: &[Secret<[u8; 32]>],
    body: &[u8],
    tag: &[u8; GATE_TAG_LEN],
    timestamp_ms: u64,
    now_ms: u64,
) -> Result<()> {
    if timestamp_ms.abs_diff(now_ms) > GATE_WINDOW_MS {
        return Err(failed());
    }
    let mut matched = false;
    for key in keys {
        matched |= ct_eq_32(&gate_tag(key, body)?, tag);
    }
    if matched {
        Ok(())
    } else {
        Err(failed())
    }
}

/// Identifies one hello; the puzzle and the cookie are bound to it.
#[must_use]
pub fn hello_hash(hello: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN_HELLO)
        .chain_update(hello)
        .finalize()
        .into()
}

fn cookie_mac(
    secret: &CookieSecret,
    hello: &[u8; 32],
    difficulty: u8,
    issued_ms: u64,
) -> Result<[u8; 32]> {
    let mut mac = hmac(secret.0.expose())?;
    mac.update(DOMAIN_COOKIE);
    mac.update(hello);
    mac.update(&[difficulty]);
    mac.update(&issued_ms.to_be_bytes());
    Ok(mac.finalize().into_bytes().into())
}

/// Issue a cookie for `hello` at the given difficulty.
///
/// # Errors
///
/// `mac key` as for [`gate_tag`].
pub fn issue_cookie(
    secret: &CookieSecret,
    hello: &[u8; 32],
    difficulty: u8,
    now_ms: u64,
) -> Result<Cookie> {
    let difficulty = difficulty.min(MAX_DIFFICULTY);
    Ok(Cookie {
        difficulty,
        issued_ms: now_ms,
        mac: cookie_mac(secret, hello, difficulty, now_ms)?,
    })
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
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

fn pow_hash(cookie: &Cookie, hello: &[u8; 32], counter: u64) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN_POW)
        .chain_update(cookie.mac)
        .chain_update(hello)
        .chain_update(counter.to_be_bytes())
        .finalize()
        .into()
}

/// Find a counter whose hash has the cookie's number of leading zero bits.
///
/// # Errors
///
/// `puzzle too hard` when the cookie asks for more than [`MAX_DIFFICULTY`].
pub fn solve(cookie: &Cookie, hello: &[u8; 32]) -> Result<u64> {
    if cookie.difficulty > MAX_DIFFICULTY {
        return Err(anyhow!("puzzle too hard"));
    }
    let need = u32::from(cookie.difficulty);
    (0..u64::MAX)
        .find(|counter| leading_zero_bits(&pow_hash(cookie, hello, *counter)) >= need)
        .ok_or_else(|| anyhow!("puzzle too hard"))
}

/// Check a solved cookie: our MAC, a fresh issue time, at least the
/// `required` difficulty, and a valid solution. One HMAC and one SHA-256.
///
/// # Errors
///
/// `handshake failed` for every failure.
pub fn check_cookie(
    secret: &CookieSecret,
    hello: &[u8; 32],
    cookie: &Cookie,
    counter: u64,
    required: u8,
    now_ms: u64,
) -> Result<()> {
    let fresh = now_ms >= cookie.issued_ms.saturating_sub(GATE_WINDOW_MS)
        && now_ms <= cookie.issued_ms.saturating_add(COOKIE_WINDOW_MS);
    let expected = cookie_mac(secret, hello, cookie.difficulty, cookie.issued_ms)?;
    let authentic = ct_eq_32(&expected, &cookie.mac);
    let hard_enough = cookie.difficulty >= required.min(MAX_DIFFICULTY);
    let solved =
        leading_zero_bits(&pow_hash(cookie, hello, counter)) >= u32::from(cookie.difficulty);
    if fresh && authentic && hard_enough && solved {
        Ok(())
    } else {
        Err(failed())
    }
}
