// Module name shadows the `hkdf` crate.
extern crate hkdf as hkdf_impl;

use hkdf_impl::Hkdf;
use secret::Secret;
use sha2::Sha512;

use crate::error::KdfError;

/// HKDF info for the device wrap key (`k_dev`).
pub const INFO_DEVICE_WRAP: &[u8] = b"brby/v2/device-wrap";

const INFO_BODY_ENC: &[u8] = b"brby/v2/body-enc";
const INFO_BODY_MAC: &[u8] = b"brby/v2/body-mac";
const INFO_COMMIT: &[u8] = b"brby/v2/commit";

const OUTPUT_LEN: usize = 32;

/// Expands `ikm` to 32 bytes with HKDF-SHA512.
///
/// `salt` is the 16-byte `vault_id`. It is not a secret.
///
/// # Errors
///
/// [`KdfError::KdfParamsRejected`] when HKDF-Expand rejects the output length.
pub fn hkdf_sha512(
    ikm: &[u8],
    salt: &[u8; 16],
    info: &[u8],
) -> Result<Secret<[u8; OUTPUT_LEN]>, KdfError> {
    let hk = Hkdf::<Sha512>::new(Some(salt.as_slice()), ikm);
    let mut okm = [0u8; OUTPUT_LEN];
    hk.expand(info, &mut okm)
        .map_err(|_| KdfError::KdfParamsRejected)?;
    Ok(Secret::new(okm))
}

/// Derives `(k_body, k_bmac, k_commit)` from the vault key.
///
/// Infos are `brby/v2/body-enc`, `brby/v2/body-mac`, and `brby/v2/commit`.
/// Salt is `vault_id`. Each output is 32 bytes.
///
/// # Errors
///
/// [`KdfError::KdfParamsRejected`] when HKDF-Expand fails.
#[allow(
    clippy::type_complexity,
    reason = "the cross-crate signature is the three derived keys"
)]
pub fn derive_vault_keys(
    vk: &[u8; 32],
    vault_id: &[u8; 16],
) -> Result<
    (
        Secret<[u8; OUTPUT_LEN]>,
        Secret<[u8; OUTPUT_LEN]>,
        Secret<[u8; OUTPUT_LEN]>,
    ),
    KdfError,
> {
    let k_body = hkdf_sha512(vk, vault_id, INFO_BODY_ENC)?;
    let k_bmac = hkdf_sha512(vk, vault_id, INFO_BODY_MAC)?;
    let k_commit = hkdf_sha512(vk, vault_id, INFO_COMMIT)?;
    Ok((k_body, k_bmac, k_commit))
}
