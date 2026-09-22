//! Platform backends for fast unlock factors.
//!
//! Two traits cover the phone-side hardware:
//!
//! - [`ChipBackend`] — a secure chip that owns a non-exportable P-256 key
//!   (`iOS` Secure Enclave, `Android` `StrongBox`). The implementation computes
//!   ECDH inside the chip and hands out only shared secrets.
//! - [`PrfBackend`] — a FIDO2 authenticator exposing CTAP2.1 `hmac-secret`
//!   (`YubiKey`). The PRF output never leaves the token as a key.
//!
//! Both traits are consumed through static dispatch (generics or
//! `impl Trait`); there is no `dyn` in this crate.
//!
//! Real native bridges (Swift/Kotlin) live in the mobile apps. This crate
//! ships [`SoftwareChip`] for tests and examples, and [`CtapPrf`] as the
//! working USB/NFC token backend.
//!
//! # Contract for a native `ChipBackend`
//!
//! A native implementation must keep the private key in platform secure
//! storage (`zp/{vault_id_hex}` alias, non-exportable, Secure Enclave /
//! `StrongBox`), compute `ECDH(chip_sk, peer)` on-device, and return the raw
//! 32-byte X9.63 shared secret. Bare P-256 without the PQ half is not a
//! valid grant: sealing always adds the software `ntrulp` half, so opening
//! needs both.

use std::collections::HashMap;
use std::sync::Mutex;

use ctap_fido2::cmd::get_assertion::HmacSecretRequest;
use ctap_fido2::cmd::{Algorithm, Authenticator, MakeCredentialOptions};
use ctap_fido2::device::{list_devices, DeviceInfo};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

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

/// A FIDO2 authenticator with the CTAP2.1 `hmac-secret` extension.
pub trait PrfBackend {
    /// Create a non-discoverable `hmac-secret` credential.
    ///
    /// Returns the credential id to store in a [`wraps`](#) grant and the
    /// stable 16-byte grant id derived from it. `dev` is the HID device path
    /// from [`list_devices`]; pass an empty slice to use the first token.
    ///
    /// # Errors
    ///
    /// CTAP errors: PIN required or wrong, touch timeout, no token.
    fn enroll(
        &self,
        rp_id: &str,
        user: &[u8],
        dev: &str,
        pin: Option<&str>,
    ) -> anyhow::Result<(Vec<u8>, [u8; 16])>;

    /// Compute the PRF output for `salt`. Touch only; no PIN.
    ///
    /// # Errors
    ///
    /// CTAP errors as in [`Self::prf_with`].
    fn prf(&self, cred_id: &[u8], salt: &[u8; 32], dev: &str) -> anyhow::Result<[u8; 32]> {
        self.prf_with(cred_id, salt, dev, None)
    }

    /// Compute the PRF output for `salt`, optionally with a PIN.
    ///
    /// # Errors
    ///
    /// `device not found` when `dev` matches no token.
    /// CTAP errors from the token: PIN required or wrong, touch timeout,
    /// missing `hmac-secret` extension, unknown credential.
    fn prf_with(
        &self,
        cred_id: &[u8],
        salt: &[u8; 32],
        dev: &str,
        pin: Option<&str>,
    ) -> anyhow::Result<[u8; 32]>;

    /// Drop the binding locally. CTAP2.1 has no per-credential delete for
    /// non-discoverable credentials; the token-side secret becomes
    /// unreachable once the vault wrap is removed by the session layer.
    ///
    /// # Errors
    ///
    /// Always succeeds. Kept for trait symmetry with native backends that
    /// can clean device-side state.
    fn remove(&self, cred_id: &[u8]) -> anyhow::Result<()> {
        let _ = cred_id;
        Ok(())
    }
}

/// In-memory chip for tests and examples. Not for production.
#[derive(Default)]
pub struct SoftwareChip {
    keys: Mutex<HashMap<String, zeroize::Zeroizing<[u8; 32]>>>,
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
        self.keys
            .lock()
            .map_err(|_| anyhow::anyhow!("chip store poisoned"))?
            .insert(alias.to_owned(), zeroize::Zeroizing::new(sk.to_bytes().into()));
        Ok(pk)
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
        let sk_bytes =
            sk_bytes.ok_or_else(|| anyhow::anyhow!("no such key"))?;
        let field: p256::elliptic_curve::FieldBytes<p256::NistP256> =
            (*sk_bytes).into();
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

/// `YubiKey` PRF backend over real CTAP2.1 `hmac-secret` (crate `ctap-fido2`).
#[derive(Clone, Copy, Debug, Default)]
pub struct CtapPrf;

impl CtapPrf {
    /// A backend handle. The token is opened per call.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn open(dev: &str) -> anyhow::Result<Authenticator> {
        let devices = list_devices().map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let info: &DeviceInfo = if dev.is_empty() {
            devices
                .first()
                .ok_or_else(|| anyhow::anyhow!("device not found"))?
        } else {
            devices
                .iter()
                .find(|item| item.path == dev)
                .ok_or_else(|| anyhow::anyhow!("device not found"))?
        };
        Authenticator::open(info).map_err(|err| anyhow::anyhow!(err.to_string()))
    }
}

impl PrfBackend for CtapPrf {
    fn enroll(
        &self,
        rp_id: &str,
        user: &[u8],
        dev: &str,
        pin: Option<&str>,
    ) -> anyhow::Result<(Vec<u8>, [u8; 16])> {
        let mut auth = Self::open(dev)?;
        let hash = Sha256::new()
            .chain_update(b"zp/vault/enroll/v1")
            .chain_update(user)
            .finalize();
        let mut seed = [0u8; 32];
        for (dst, src) in seed.iter_mut().zip(hash.iter()) {
            *dst = *src;
        }
        let opts = MakeCredentialOptions {
            algorithm: Algorithm::Es256,
            pin,
            ..MakeCredentialOptions::default()
        };
        let credential = auth
            .make_credential(rp_id, &seed, &opts)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let id = grant_id(&credential.id);
        Ok((credential.id, id))
    }

    fn prf_with(
        &self,
        cred_id: &[u8],
        salt: &[u8; 32],
        dev: &str,
        pin: Option<&str>,
    ) -> anyhow::Result<[u8; 32]> {
        let mut auth = Self::open(dev)?;
        let mut client_hash = [0u8; 32];
        getrandom::fill(&mut client_hash).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
        // A random nonce, not secret material; `request` borrows it and is
        // dropped right after the call.
        let request = HmacSecretRequest {
            rp_id: ZP_RP_ID,
            client_data_hash: &client_hash,
            cred_id,
            salt,
            salt2: None,
            pin,
            public_key: None,
            request_cred_blob: false,
        };
        let response = auth
            .get_hmac_secret(&request)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        Ok(response.secret.0)
    }
}

/// Relying party id used for every zebrapass credential.
pub const ZP_RP_ID: &str = "zebrapass.local";

/// Stable grant id: `SHA-256(cred_id)[..16]`.
fn grant_id(cred_id: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(cred_id);
    let mut id = [0u8; 16];
    for (slot, byte) in id.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    id
}

/// Draw a software P-256 key pair from the OS RNG.
fn fresh_pair() -> anyhow::Result<(SecretKey, [u8; 65])> {
    // Scalars are 32 random bytes; almost every draw is a valid secret key.
    for _ in 0..8 {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
        let key = {
            let field: p256::elliptic_curve::FieldBytes<p256::NistP256> = bytes.into();
            SecretKey::from_bytes(&field)
        };
        bytes.zeroize();
        if let Ok(sk) = key {
            let pk = encode_pub(&sk.public_key())?;
            return Ok((sk, pk));
        }
    }
    Err(anyhow::anyhow!("os entropy failed"))
}

/// Decode an uncompressed 65-byte P-256 public key.
fn decode_pub(bytes: &[u8; 65]) -> anyhow::Result<PublicKey> {
    PublicKey::from_sec1_bytes(bytes).map_err(|_| anyhow::anyhow!("kem length"))
}

fn shared(sk: &SecretKey, pk: &PublicKey) -> [u8; 32] {
    let ss = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let raw = ss.raw_secret_bytes();
    let mut out = [0u8; 32];
    for (dst, src) in out.iter_mut().zip(raw.iter()) {
        *dst = *src;
    }
    out
}

fn encode_pub(key: &PublicKey) -> anyhow::Result<[u8; 65]> {
    let point = key.to_encoded_point(false);
    let bytes = point.as_bytes();
    let mut out = [0u8; 65];
    if bytes.len() != 65 {
        return Err(anyhow::anyhow!("kem length"));
    }
    out.copy_from_slice(bytes);
    Ok(out)
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
    use super::{decode_pub, fresh_pair, shared, ChipBackend, SoftwareChip};

    #[test]
    fn software_chip_ecdh_round_trip() {
        let chip = SoftwareChip::new();
        assert!(chip.capability().present);
        let chip_pub = chip.generate_pair("zp/abc").unwrap();
        let (peer_secret, peer_key) = fresh_pair().unwrap();
        let from_chip = chip.ecdh("zp/abc", &peer_key).unwrap();
        let peer_view = shared(&peer_secret, &decode_pub(&chip_pub).unwrap());
        // Both sides derive the same 32-byte secret.
        assert_eq!(from_chip, peer_view);
        chip.delete("zp/abc").unwrap();
        assert_eq!(
            chip.ecdh("zp/abc", &peer_key).unwrap_err().to_string(),
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
