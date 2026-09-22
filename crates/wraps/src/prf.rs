//! `YubiKey` PRF wrap: the hmac-secret output seals the vault key directly.
//!
//! !todo!: physical-key support is removed from `session`/`platform` for
//! now; the wire kind `0x0004` and this module stay so the format slot is
//! reserved and files stay forward-compatible.

use container::{encode_prf_entry, PrfWrap, StaticHeader};
use kdf::{hkdf_sha512, INFO_PRF_WRAP};
use secret::Secret;

use crate::wad::{self, prf_wad};

/// Public identity accepted by [`seal_prf`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrfPublics {
    /// Grant id. A caller-chosen label.
    pub id: [u8; 16],
    /// CTAP credential id, `16..=64` bytes. The `YubiKey` finds its key by it.
    pub cred_id: Vec<u8>,
    /// PRF salt bound into the associated data.
    pub salt: [u8; 32],
}

/// Owned grant. It is not a vault file and it does not include the commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrfGrant {
    bytes: Vec<u8>,
}

impl PrfGrant {
    /// Borrow the grant encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// Seal `vk` to a PRF output.
///
/// `prf_out` is the 32-byte hmac-secret response the `YubiKey` computes from
/// `prf.salt`; it is already uniformly random, so the wrap key is
/// `HKDF(prf_out, vault_id)` with no extra KDF step. The salt is bound into
/// the associated data, so a record sealed for one salt never opens with
/// another.
///
/// Returns the PRF record and the grant. The grant is the static header, the
/// id, the credential id, the salt, the nonce, and the AEGIS ciphertext and
/// tag. It does not include the record kind.
///
/// # Errors
///
/// `corrupted length` when `prf.cred_id` is outside `16..=64` bytes.
/// `os entropy failed` when the OS RNG fails.
/// `kdf parameters rejected` when HKDF rejects the output length.
pub fn seal_prf(
    header: &StaticHeader,
    prf: &PrfPublics,
    prf_out: &[u8; 32],
    vk: &[u8; 32],
) -> anyhow::Result<(Vec<u8>, PrfGrant)> {
    let k_prf = hkdf_sha512(prf_out, &header.vault_id, INFO_PRF_WRAP)?;
    let nonce = wad::random_array::<32>()?;
    let ad = prf_wad(header, &prf.id, &prf.cred_id, &prf.salt, &nonce);
    let (ct, tag) = wad::seal_vk(k_prf.expose(), &nonce, &ad, vk);
    drop(k_prf);
    let record = encode_prf_entry(prf.id, &prf.cred_id, prf.salt, nonce, ct, tag)?;
    let grant = assemble_prf(header, &prf.id, &prf.cred_id, &prf.salt, &nonce, &ct, &tag);
    Ok((record, grant))
}

/// Open a PRF wrap.
///
/// # Errors
///
/// `kdf parameters rejected` when HKDF rejects the output length.
/// `wrap authentication failed` when `prf_out` is wrong or the AEGIS-256 tag
/// does not match.
pub fn open_prf(
    header: &StaticHeader,
    wrap: &PrfWrap<'_>,
    prf_out: &[u8; 32],
) -> anyhow::Result<Secret<[u8; 32]>> {
    let k_prf = hkdf_sha512(prf_out, &header.vault_id, INFO_PRF_WRAP)?;
    let ad = prf_wad(header, &wrap.id, wrap.cred_id, &wrap.salt, &wrap.nonce);
    let vk = wad::open_vk(k_prf.expose(), &wrap.nonce, &ad, &wrap.ct, &wrap.tag);
    drop(k_prf);
    vk
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument is one grant field, in wire order"
)]
fn assemble_prf(
    header: &StaticHeader,
    prf_id: &[u8; 16],
    cred_id: &[u8],
    salt: &[u8; 32],
    nonce: &[u8; 32],
    ct: &[u8; 32],
    tag: &[u8; 32],
) -> PrfGrant {
    let header_bytes = header.to_bytes();
    let mut bytes = Vec::with_capacity(
        header_bytes.len()
            + prf_id.len()
            + cred_id.len()
            + salt.len()
            + nonce.len()
            + ct.len()
            + tag.len(),
    );
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(prf_id);
    bytes.extend_from_slice(cred_id);
    bytes.extend_from_slice(salt);
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(ct);
    bytes.extend_from_slice(tag);
    PrfGrant { bytes }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result,
    clippy::large_stack_arrays
)]
mod tests {
    use container::{
        StaticHeader, WrapEntry, BODY_AEGIS256, KDF_ARGON2ID, KDF_M_KIB_MIN, KDF_P_MIN, KDF_T_MIN,
        WRAP_AEGIS256,
    };

    use super::{open_prf, seal_prf, PrfPublics};

    fn floor_header() -> StaticHeader {
        StaticHeader {
            kdf_alg: KDF_ARGON2ID,
            kdf_m_kib: KDF_M_KIB_MIN,
            kdf_t: KDF_T_MIN,
            kdf_p: KDF_P_MIN,
            kdf_salt: [0x5A; 32],
            vault_id: [0x22; 16],
            body_alg: BODY_AEGIS256,
            wrap_alg: WRAP_AEGIS256,
        }
    }

    #[test]
    fn prf_wrap_round_trip() {
        let header = floor_header();
        let vk = [0x24u8; 32];
        let prf = PrfPublics {
            id: [0x22; 16],
            cred_id: vec![0x77; 32],
            salt: [0x33; 32],
        };
        let prf_out = [0x44u8; 32];
        let (record, grant) = seal_prf(&header, &prf, &prf_out, &vk).unwrap();
        assert!(!grant.as_bytes().is_empty());
        let WrapEntry::Prf(wrap) = WrapEntry::try_from(record.as_slice()).unwrap() else {
            panic!("expected a prf entry");
        };
        let opened = open_prf(&header, &wrap, &prf_out).unwrap();
        assert_eq!(opened.expose(), &vk);
        // A foreign PRF output fails authentication.
        assert_eq!(
            open_prf(&header, &wrap, &[0x45; 32])
                .unwrap_err()
                .to_string(),
            "wrap authentication failed"
        );
        // The salt binds the associated data.
        let mut wrong_salt = wrap;
        wrong_salt.salt = [0xFF; 32];
        assert_eq!(
            open_prf(&header, &wrong_salt, &prf_out)
                .unwrap_err()
                .to_string(),
            "wrap authentication failed"
        );
    }

    #[test]
    fn prf_rejects_bad_credential_length() {
        let header = floor_header();
        let prf = PrfPublics {
            id: [0x22; 16],
            cred_id: vec![0x77; 15],
            salt: [0x33; 32],
        };
        assert_eq!(
            seal_prf(&header, &prf, &[0x44; 32], &[0x24; 32])
                .unwrap_err()
                .to_string(),
            "corrupted length"
        );
    }
}
