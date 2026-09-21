//! AEGIS-256 with a 32-byte tag.

use ::aegis::aegis256::Aegis256;

use crate::error::{copy_array, split_packed, AeadError};

const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 32;

pub fn seal(k_body: &[u8; 32], nonce: &[u8], ad: &[u8], pt: &[u8]) -> Result<Vec<u8>, AeadError> {
    let nonce: [u8; NONCE_LEN] = copy_array(nonce)?;
    // `<32>` is a const tag length. `new` panics only when that const is not 16 or 32.
    let (ct, tag) = Aegis256::<32>::new(k_body, &nonce).encrypt(pt, ad);
    let mut packed = Vec::with_capacity(NONCE_LEN + ct.len() + TAG_LEN);
    packed.extend_from_slice(&nonce);
    packed.extend_from_slice(&ct);
    packed.extend_from_slice(&tag);
    Ok(packed)
}

pub fn open(k_body: &[u8; 32], packed: &[u8], ad: &[u8]) -> Result<Vec<u8>, AeadError> {
    let (nonce, ct, tag) = split_packed(packed, NONCE_LEN, TAG_LEN)?;
    let nonce: [u8; NONCE_LEN] = copy_array(nonce)?;
    let tag: [u8; TAG_LEN] = copy_array(tag)?;
    // Decrypt reports every failure, including a bad tag, as one error.
    Aegis256::<32>::new(k_body, &nonce)
        .decrypt(ct, &tag, ad)
        .map_err(|_err| AeadError::BodyAuthFailed)
}
