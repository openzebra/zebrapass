//! Short codes two people compare out loud, because a pasted key or
//! invitation travels over a channel nobody authenticated.

use std::fmt::{self, Write as _};

use pq::SYNC_VK_LEN;
use sha2::{Digest, Sha256};

const DOMAIN_ACCOUNT: &[u8] = b"brby/v2/account-fingerprint";
const DOMAIN_VAULT: &[u8] = b"brby/v2/vault-fingerprint";

/// 160 bits of a SHA-256, shown as ten groups of four hex digits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fingerprint([u8; 20]);

impl Fingerprint {
    /// Hash of the parts, each preceded by its `u32` big-endian length so
    /// no two part lists collide.
    fn of(parts: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize();
        let mut out = [0u8; 20];
        for (dst, src) in out.iter_mut().zip(digest.iter()) {
            *dst = *src;
        }
        Self(out)
    }

    /// The raw 20 bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (at, pair) in self.0.chunks(2).enumerate() {
            if at > 0 {
                f.write_str(" ")?;
            }
            for byte in pair {
                write!(f, "{byte:02X}")?;
            }
        }
        Ok(())
    }
}

/// The code of an account: what both people compare before trusting a card
/// or an invitation. It covers the account id and the root key, so it is the
/// same on every card of the account.
#[must_use]
pub fn account_fingerprint(client_id: &[u8; 64], root_vk: &[u8; SYNC_VK_LEN]) -> Fingerprint {
    Fingerprint::of(&[DOMAIN_ACCOUNT, client_id, root_vk])
}

/// The code of a shared vault: its id and the hash of its first log entry.
#[must_use]
pub fn vault_fingerprint(vault_id: &[u8; 16], anchor: &[u8; 32]) -> Fingerprint {
    Fingerprint::of(&[DOMAIN_VAULT, vault_id, anchor])
}

/// The vault number as people read and type it: 32 hex digits in eight
/// groups of four.
#[must_use]
pub fn vault_number(vault_id: &[u8; 16]) -> String {
    let mut out = String::with_capacity(39);
    for (at, pair) in vault_id.chunks(2).enumerate() {
        if at > 0 {
            out.push(' ');
        }
        for byte in pair {
            // Writing to a String cannot fail.
            let _ = write!(out, "{byte:02X}");
        }
    }
    out
}
