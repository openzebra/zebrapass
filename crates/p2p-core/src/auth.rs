//! Authentication proofs: a device certificate plus an ML-DSA signature over
//! the handshake transcript.
//!
//! Every failure here is the same error, so a peer cannot tell a bad
//! certificate from a bad signature or from the wrong account.

use anyhow::{anyhow, Result};
use pq::{sync_sign, sync_verify, P2P_AUTH_CTX, SYNC_SIG_LEN, SYNC_VK_LEN};
use secret::Secret;
use session::{frame_parts, DeviceCert, DeviceSignKey, Revocation};
use sha2::{Digest, Sha256};
use syncwire::{decode_cert, encode_cert, CERT_WIRE_LEN};

use crate::suite::{PROOF_LEN, SUITE};

const DOMAIN_AUTH: &[u8] = b"brby/v2/p2p-auth";

/// An account whose devices this vault trusts: its id and root key. A
/// personal vault trusts one account, a shared vault one per member.
#[derive(Clone, Debug)]
pub struct Account {
    /// Account id every certificate of this account carries.
    pub client_id: [u8; 64],
    /// Root verifying key those certificates chain to.
    pub root_vk: Box<[u8; SYNC_VK_LEN]>,
}

/// What this device presents and trusts.
pub struct Local<'a> {
    /// The vault being synced; salts every derived key.
    pub vault_id: [u8; 16],
    /// This device's certificate.
    pub cert: &'a DeviceCert,
    /// This device's signing key.
    pub sign: &'a DeviceSignKey,
    /// The accounts whose devices may connect.
    pub accounts: &'a [Account],
    /// Revocations already verified and accepted for this vault.
    pub revoked: &'a [Revocation],
    /// Keys a hello may be gated under: the one this device sends with
    /// first, then older ones, so a device that missed a key rotation can
    /// still reconnect and receive it.
    pub gate_keys: &'a [Secret<[u8; 32]>],
}

/// Which side of the handshake produced a signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Initiator => b"initiator",
            Self::Responder => b"responder",
        }
    }
}

pub fn failed() -> anyhow::Error {
    anyhow!("handshake failed")
}

fn auth_message(
    role: Role,
    transcript: &[u8; 32],
    cert_hash: &[u8; 32],
    client_id: &[u8; 64],
) -> Result<Vec<u8>> {
    frame_parts(&[
        DOMAIN_AUTH,
        role.label(),
        &SUITE.to_be_bytes(),
        transcript,
        cert_hash,
        client_id,
    ])
}

/// This device's certificate and a signature binding it to `transcript` in
/// `role`.
pub fn prove(local: &Local<'_>, role: Role, transcript: &[u8; 32]) -> Result<Vec<u8>> {
    let cert_bytes = encode_cert(local.cert)?;
    let cert_hash: [u8; 32] = Sha256::digest(&cert_bytes).into();
    let message = auth_message(role, transcript, &cert_hash, &local.cert.client_id)?;
    let signature = sync_sign(local.sign.seed(), P2P_AUTH_CTX, &message)?;
    let mut proof = Vec::with_capacity(PROOF_LEN);
    proof.extend_from_slice(&cert_bytes);
    proof.extend_from_slice(&signature);
    Ok(proof)
}

/// Check a peer's proof and return its certificate. The certificate must
/// chain to the root of a trusted account, be unexpired, not be revoked and
/// name another device; the signature must verify under the certified key.
pub fn verify_proof(
    local: &Local<'_>,
    role: Role,
    transcript: &[u8; 32],
    proof: &[u8],
    now_ms: u64,
) -> Result<DeviceCert> {
    if proof.len() != PROOF_LEN {
        return Err(failed());
    }
    let (cert_bytes, signature) = proof.split_at_checked(CERT_WIRE_LEN).ok_or_else(failed)?;
    if signature.len() != SYNC_SIG_LEN {
        return Err(failed());
    }
    let cert = decode_cert(cert_bytes).map_err(|_| failed())?;
    let account = local
        .accounts
        .iter()
        .find(|account| secret::ct_eq(&account.client_id, &cert.client_id))
        .ok_or_else(failed)?;
    cert.verify(&account.root_vk, now_ms)
        .map_err(|_| failed())?;
    let revoked = local
        .revoked
        .iter()
        .any(|revocation| revocation.covers(&cert));
    if revoked || cert.device_id == local.cert.device_id {
        return Err(failed());
    }
    let cert_hash: [u8; 32] = Sha256::digest(cert_bytes).into();
    let message = auth_message(role, transcript, &cert_hash, &cert.client_id)?;
    sync_verify(&cert.device_vk, P2P_AUTH_CTX, &message, signature).map_err(|_| failed())?;
    Ok(cert)
}
