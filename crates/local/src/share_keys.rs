//! The key pair this device receives shared-vault invitations with: ML-KEM
//! and P-256, the same hybrid as a device wrap, so an invitation stays closed
//! unless both are broken. The secrets live in the sealed sync identity and
//! never leave it.

use secret::Secret;

/// ML-KEM-768 decapsulation seed length.
const KEM_SEED_LEN: usize = pq::PQ_SK_LEN;

/// Length of a P-256 scalar.
const EC_SCALAR_LEN: usize = 32;

/// Bytes the keys take in the sealed payload.
pub const SHARE_KEYS_LEN: usize = KEM_SEED_LEN + EC_SCALAR_LEN;

/// The public halves, as put on a contact card.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharePublics {
    /// Uncompressed P-256 point.
    pub ec_pub: [u8; 65],
    /// ML-KEM-768 encapsulation key.
    pub kem_ek: Box<[u8; pq::PQ_PK_LEN]>,
}

/// This device's invitation keys.
#[derive(Debug)]
pub struct ShareKeys {
    kem_seed: Secret<[u8; KEM_SEED_LEN]>,
    ec_scalar: Secret<[u8; EC_SCALAR_LEN]>,
}

impl ShareKeys {
    /// Draw fresh keys from the OS RNG.
    ///
    /// # Errors
    ///
    /// `os entropy failed` when the RNG fails or draws no valid scalar.
    pub fn generate() -> anyhow::Result<Self> {
        let mut kem_seed = Secret::new([0u8; KEM_SEED_LEN]);
        getrandom::fill(kem_seed.expose_mut())?;
        let mut ec_scalar = Secret::new([0u8; EC_SCALAR_LEN]);
        for _ in 0..8 {
            getrandom::fill(ec_scalar.expose_mut())?;
            if ec::pair_from_scalar(&ec_scalar).is_ok() {
                return Ok(Self {
                    kem_seed,
                    ec_scalar,
                });
            }
        }
        Err(anyhow::anyhow!("os entropy failed"))
    }

    /// The public halves.
    ///
    /// # Errors
    ///
    /// The stored scalar is not a valid key (a corrupted file).
    pub fn publics(&self) -> anyhow::Result<SharePublics> {
        let (secret, _) = ec::pair_from_scalar(&self.ec_scalar)?;
        let ec_pub = ec::encode_pub(&secret.public_key())?;
        let (ek, _) = pq::keypair_from_seed(self.kem_seed.expose());
        let kem_ek = Box::new(
            <[u8; pq::PQ_PK_LEN]>::try_from(ek).map_err(|_| anyhow::anyhow!("corrupted length"))?,
        );
        Ok(SharePublics { ec_pub, kem_ek })
    }

    /// The P-256 secret key.
    ///
    /// # Errors
    ///
    /// The stored scalar is not a valid key (a corrupted file).
    pub fn ec_secret(&self) -> anyhow::Result<ec::SecretKey> {
        Ok(ec::pair_from_scalar(&self.ec_scalar)?.0)
    }

    /// The ML-KEM decapsulation seed.
    #[must_use]
    pub const fn kem_seed(&self) -> &Secret<[u8; KEM_SEED_LEN]> {
        &self.kem_seed
    }

    pub(crate) fn append_to(&self, payload: &mut Vec<u8>) {
        payload.extend_from_slice(self.kem_seed.expose());
        payload.extend_from_slice(self.ec_scalar.expose());
    }

    pub(crate) fn split_from(bytes: &[u8]) -> anyhow::Result<(Self, &[u8])> {
        let (kem, rest) = bytes
            .split_first_chunk::<KEM_SEED_LEN>()
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let (scalar, rest) = rest
            .split_first_chunk::<EC_SCALAR_LEN>()
            .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
        let mut keys = Self {
            kem_seed: Secret::new([0u8; KEM_SEED_LEN]),
            ec_scalar: Secret::new([0u8; EC_SCALAR_LEN]),
        };
        keys.kem_seed.expose_mut().copy_from_slice(kem);
        keys.ec_scalar.expose_mut().copy_from_slice(scalar);
        ec::pair_from_scalar(&keys.ec_scalar)?;
        Ok((keys, rest))
    }
}
