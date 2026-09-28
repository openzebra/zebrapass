//! Platform backend for a hardware-held device factor.
//!
//! Terminal apps cannot use the Secure Enclave, so the desktop device factor
//! keeps its keys in a PIN-sealed file (`local::DeviceKey`) instead; this
//! seam is for native apps that can.
//!
//! [`ChipBackend`] — a secure chip that owns a non-exportable P-256 key
//! per alias (`iOS` Secure Enclave, `Android` `StrongBox`). The
//! implementation computes ECDH inside the chip and hands out only shared
//! secrets; the private key never leaves the platform.
//!
//! The trait is consumed through static dispatch (generics or `impl Trait`
//! in argument position); there is no `dyn` in this crate.
//!
//! Real native bridges (Swift/Kotlin) live in the mobile apps. This crate
//! ships [`SoftwareChip`] for tests and examples.
//!
//! # Contract for a native `ChipBackend`
//!
//! A native implementation must keep the private key in platform secure
//! storage (`zp/{vault_id_hex}` alias, non-exportable, Secure Enclave /
//! `StrongBox`), compute `ECDH(chip_sk, peer)` on-device, and return the raw
//! 32-byte X9.63 shared secret. Bare P-256 without the PQ half is not a
//! valid grant: sealing always adds the software ML-KEM-768 half, so opening
//! needs both.
//!
//! !todo!: physical-key (`YubiKey` PRF) support was removed. To restore it:
//! a `PrfBackend` trait here (`enroll`/`prf`/`prf_with`/`remove`) over a
//! fixed `CTAP` client — `ctap-fido2` 0.1.3 has a PIN-v1 `alg` bug (wrong
//! `-25` label, `PinAuthInvalid` with a correct PIN; reported upstream
//! 2026-09) — plus the `session` side: `UnlockCreds::with_prf`,
//! `add_prf_unlock` / `remove_prf_unlock`, the `prfs` parameter of
//! `reencrypt_body`. The vault format already reserves wrap kind `0x0004`
//! and `wraps::prf` still compiles, so files stay forward-compatible.

use std::collections::HashMap;
use std::sync::Mutex;

use ec::{decode_pub, encode_pub, fresh_pair, shared};
use p256::SecretKey;
use zeroize::Zeroizing;

/// What a backend can offer right now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    /// The hardware is available on this device.
    pub present: bool,
    /// Using it needs a user gesture (Touch ID prompt, PIN, tap).
    pub gated: bool,
    /// Backend label, e.g. `"secure-enclave"` or `"software"`.
    pub kind: &'static str,
}

/// A secure chip that owns a non-exportable P-256 key per alias.
pub trait ChipBackend {
    /// Probe the platform.
    fn capability(&self) -> Capability;

    /// Create a fresh non-exportable key pair under `alias` and return the
    /// uncompressed public key (65 bytes, `0x04`-prefixed).
    ///
    /// # Errors
    ///
    /// Backend-specific: key generation or storage failures.
    fn generate_pair(&self, alias: &str) -> anyhow::Result<[u8; 65]>;

    /// Compute `ECDH(sk(alias), peer)` inside the chip.
    ///
    /// # Errors
    ///
    /// `no such key` when `alias` was never generated or was deleted.
    /// `kem length` when `peer` does not decode as an uncompressed P-256
    /// point.
    fn ecdh(&self, alias: &str, peer_pub: &[u8; 65]) -> anyhow::Result<[u8; 32]>;

    /// Delete the key under `alias`.
    ///
    /// # Errors
    ///
    /// Backend-specific: storage failures.
    fn delete(&self, alias: &str) -> anyhow::Result<()>;
}

/// In-memory chip for tests and examples. Not for production.
#[derive(Default)]
pub struct SoftwareChip {
    keys: Mutex<HashMap<String, Zeroizing<[u8; 32]>>>,
}

impl SoftwareChip {
    /// An empty chip.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ChipBackend for SoftwareChip {
    fn capability(&self) -> Capability {
        Capability {
            present: true,
            gated: false,
            kind: "software",
        }
    }

    fn generate_pair(&self, alias: &str) -> anyhow::Result<[u8; 65]> {
        let (sk, pk) = fresh_pair()?;
        let encoded = encode_pub(&pk)?;
        self.keys
            .lock()
            .map_err(|_| anyhow::anyhow!("chip store poisoned"))?
            .insert(alias.to_owned(), Zeroizing::new(sk.to_bytes().into()));
        Ok(encoded)
    }

    fn ecdh(&self, alias: &str, peer_pub: &[u8; 65]) -> anyhow::Result<[u8; 32]> {
        // Copy the secret out and release the store before computing, so the
        // lock guard does not live across the ECDH.
        let sk_bytes = {
            let store = self
                .keys
                .lock()
                .map_err(|_| anyhow::anyhow!("chip store poisoned"))?;
            store.get(alias).cloned()
        };
        let sk_bytes = sk_bytes.ok_or_else(|| anyhow::anyhow!("no such key"))?;
        let field: p256::elliptic_curve::FieldBytes<p256::NistP256> = (*sk_bytes).into();
        let sk = SecretKey::from_bytes(&field).map_err(|_| anyhow::anyhow!("kem length"))?;
        let peer = decode_pub(peer_pub)?;
        Ok(shared(&sk, &peer))
    }

    fn delete(&self, alias: &str) -> anyhow::Result<()> {
        self.keys
            .lock()
            .map_err(|_| anyhow::anyhow!("chip store poisoned"))?
            .remove(alias);
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result
)]
mod tests {
    use ec::{decode_pub, encode_pub, fresh_pair, shared};

    use super::{ChipBackend, SoftwareChip};

    #[test]
    fn software_chip_ecdh_round_trip() {
        let chip = SoftwareChip::new();
        assert!(chip.capability().present);
        let chip_pub = chip.generate_pair("zp/abc").unwrap();
        let (peer_secret, peer_key) = fresh_pair().unwrap();
        let peer_pub = encode_pub(&peer_key).unwrap();
        let from_chip = chip.ecdh("zp/abc", &peer_pub).unwrap();
        let peer_view = shared(&peer_secret, &decode_pub(&chip_pub).unwrap());
        // Both sides derive the same 32-byte secret.
        assert_eq!(from_chip, peer_view);
        chip.delete("zp/abc").unwrap();
        assert_eq!(
            chip.ecdh("zp/abc", &peer_pub).unwrap_err().to_string(),
            "no such key"
        );
    }

    #[test]
    fn software_chip_rejects_bad_peer() {
        let chip = SoftwareChip::new();
        chip.generate_pair("zp/xyz").unwrap();
        let mut bad = [0u8; 65];
        bad[0] = 0x04;
        assert_eq!(
            chip.ecdh("zp/xyz", &bad).unwrap_err().to_string(),
            "kem length"
        );
    }
}
