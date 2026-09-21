//! v1 password migration. Compiled only with feature `legacy-v1`.
//!
//! `bearby-cipher` does not build in this workspace (`ntrulp` fails to compile),
//! so AES-256-GCM is reimplemented and Kuznechik, NTRU, and CYBER are refused.
//! Keys come from the Argon2 seed (`from_seed`), never from `KeyChain::from_bytes`.

use aead::BodyAlg;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use container::VaultFile;
use kdf::KdfProfile;
use secret::Secret;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::create::create;
use crate::error::VaultV2Error;
use crate::rotate::write_records;

/// v1 `ARGON2_DEFAULT_CONFIG`: 64 MiB, one pass, one lane, 64-byte output.
/// Not the v2 floor. `t = 1` is what existing vaults were sealed with.
const MEM_KIB: u32 = 65_536;
const TIME_COST: u32 = 1;
const LANES: u32 = 1;
const SEED_LEN: usize = 64;

const GCM_NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

/// v1 `config::argon::WALLET_SALT`. Appended to the caller salt. Not logged.
const WALLET_SALT: &[u8] = b"ZILPAY:54040c2f-1ec1-4eb1-9595-6e4294d14fd6";
/// v1 `config::argon::APP_ID`. Argon2 associated data, not a secret.
const APP_ID: &[u8] = b"ZilPay-wallet-app";

/// v1 layer ciphers. Slice order for [`migrate`] is outer layer first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V1LayerKind {
    /// AES-256-GCM, nonce 12 bytes, layout `ct ‖ tag ‖ nonce`.
    AesGcm,
    /// v1 Kuznechik-OFB. Not linked in this build.
    Kuznechik,
    /// v1 `NTRUP1277` (ntrup761). Not linked in this build.
    Ntrup,
    /// v1 Kyber768 + AES-256-GCM. Not linked in this build.
    Cyber,
}

/// A new v2 vault holding the recovered record bytes.
///
/// New vault key, salt, and vault id. v1 device keys are not copied.
#[derive(Debug)]
pub struct Migrated {
    /// v2 file. Magic is `BRBY`.
    pub file: VaultFile,
    /// Session for [`Self::file`].
    pub session: crate::Session,
    /// `true` when `caller_salt` was empty, so the Argon2 salt is only the
    /// application constant. The constant itself is not stored here.
    pub shared_salt: bool,
}

/// Failure opening a v1 blob or sealing the v2 vault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrateError {
    /// Password was empty. Argon2 was not run.
    EmptyPassword,
    /// v1 key derivation or AES-GCM authentication failed.
    V1Auth,
    /// Kuznechik, NTRU, or CYBER was requested and this build cannot open it.
    UnsupportedLayer,
    /// The v2 vault could not be sealed. The v1 plaintext was not kept.
    Vault(VaultV2Error),
}

impl core::fmt::Display for MigrateError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyPassword => formatter.write_str("empty password"),
            Self::V1Auth => formatter.write_str("v1 authentication failed"),
            Self::UnsupportedLayer => formatter.write_str("unsupported v1 layer"),
            Self::Vault(err) => write!(formatter, "{err}"),
        }
    }
}

impl std::error::Error for MigrateError {}

impl From<VaultV2Error> for MigrateError {
    fn from(err: VaultV2Error) -> Self {
        Self::Vault(err)
    }
}

/// Open v1 layers and seal the plaintext in a new v2 vault.
///
/// `orders_outer_first` peels `ciphertext` from the outside in. AES-256-GCM
/// uses `SHA-256(argon2(password) ‖ [0])`. Kuznechik, NTRU, and CYBER return
/// [`MigrateError::UnsupportedLayer`] and are not skipped.
///
/// The v2 vault is [`create`] then [`write_records`] of the recovered bytes:
/// new vault key, new salt, new vault id. Generation is 2 because `create`
/// writes an empty body and `write_records` replaces it.
///
/// # Errors
///
/// [`MigrateError::EmptyPassword`] when `password` is empty, before Argon2.
/// [`MigrateError::UnsupportedLayer`] when any order is Kuznechik, NTRU, or CYBER.
/// [`MigrateError::V1Auth`] when the outer AES buffer is shorter than 28 bytes,
/// a tag does not match, or Argon2 rejects the input.
/// [`MigrateError::Vault`] when the password is not UTF-8 or v2 sealing fails.
pub fn migrate(
    password: &[u8],
    caller_salt: &[u8],
    ciphertext: &[u8],
    orders_outer_first: &[V1LayerKind],
    profile: KdfProfile,
    body_alg: BodyAlg,
) -> Result<Migrated, MigrateError> {
    if password.is_empty() {
        return Err(MigrateError::EmptyPassword);
    }
    // `create` seals with `&str`. Reject non-UTF-8 before either Argon2.
    let pw = core::str::from_utf8(password)
        .map_err(|_| MigrateError::Vault(VaultV2Error::CorruptedLength))?;
    reject_unsupported(orders_outer_first)?;
    // One outer buffer. Inner lengths are only known after that layer opens.
    reject_short_outer(ciphertext, orders_outer_first)?;
    let shared_salt = caller_salt.is_empty();
    let mut records = if orders_outer_first.is_empty() {
        ciphertext.to_vec()
    } else {
        decrypt_layers(password, caller_salt, ciphertext, orders_outer_first)?
    };
    let sealed = seal_recovered(pw, profile, body_alg, &records, shared_salt);
    records.zeroize();
    sealed
}

fn reject_unsupported(orders: &[V1LayerKind]) -> Result<(), MigrateError> {
    for order in orders {
        match order {
            V1LayerKind::AesGcm => {}
            // Do not peel an outer AES layer and pretend an inner one opened.
            V1LayerKind::Kuznechik | V1LayerKind::Ntrup | V1LayerKind::Cyber => {
                return Err(MigrateError::UnsupportedLayer);
            }
        }
    }
    Ok(())
}

/// The outside AES layer needs a 16-byte tag and a 12-byte nonce before Argon2.
const fn reject_short_outer(ciphertext: &[u8], orders: &[V1LayerKind]) -> Result<(), MigrateError> {
    let Some(V1LayerKind::AesGcm) = orders.first().copied() else {
        return Ok(());
    };
    if ciphertext.len() < GCM_NONCE_LEN + GCM_TAG_LEN {
        return Err(MigrateError::V1Auth);
    }
    Ok(())
}

fn decrypt_layers(
    password: &[u8],
    caller_salt: &[u8],
    ciphertext: &[u8],
    orders: &[V1LayerKind],
) -> Result<Vec<u8>, MigrateError> {
    let seed = derive_seed(password, caller_salt)?;
    // Index byte 0 is AES. Other orders already failed before Argon2.
    let aes_key = Secret::new(indexed_key(seed.expose(), 0)?);
    peel(aes_key.expose(), ciphertext, orders)
}

fn seal_recovered(
    pw: &str,
    profile: KdfProfile,
    body_alg: BodyAlg,
    records: &[u8],
    shared_salt: bool,
) -> Result<Migrated, MigrateError> {
    let (mut file, mut session) = create(pw, profile, body_alg)?;
    write_records(&mut session, &mut file, records)?;
    Ok(Migrated {
        file,
        session,
        shared_salt,
    })
}

fn derive_seed(
    password: &[u8],
    caller_salt: &[u8],
) -> Result<Secret<[u8; SEED_LEN]>, MigrateError> {
    let ad = AssociatedData::new(APP_ID).map_err(|_| MigrateError::V1Auth)?;
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(MEM_KIB)
        .t_cost(TIME_COST)
        .p_cost(LANES)
        .output_len(SEED_LEN)
        .data(ad);
    let params = builder.build().map_err(|_| MigrateError::V1Auth)?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salt = legacy_salt(caller_salt)?;
    let mut raw = [0u8; SEED_LEN];
    let argon_out = hasher.hash_password_into(password, &salt, &mut raw);
    salt.zeroize();
    if argon_out.is_err() {
        raw.zeroize();
        return Err(MigrateError::V1Auth);
    }
    let seed = Secret::new(raw);
    raw.zeroize();
    Ok(seed)
}

/// `caller_salt ‖ WALLET_SALT`. Empty caller salt is exactly the constant.
fn legacy_salt(caller_salt: &[u8]) -> Result<Vec<u8>, MigrateError> {
    let cap = caller_salt
        .len()
        .checked_add(WALLET_SALT.len())
        .ok_or(MigrateError::V1Auth)?;
    let mut salt = Vec::with_capacity(cap);
    salt.extend_from_slice(caller_salt);
    salt.extend_from_slice(WALLET_SALT);
    Ok(salt)
}

/// `SHA-256(seed ‖ [idx])`, the v1 `derive_key_from_seed` step.
fn indexed_key(seed: &[u8], idx: u8) -> Result<[u8; 32], MigrateError> {
    let digest = Sha256::new()
        .chain_update(seed)
        .chain_update([idx])
        .finalize();
    <[u8; 32]>::try_from(digest.as_slice()).map_err(|_| MigrateError::V1Auth)
}

fn peel(
    aes_key: &[u8; 32],
    ciphertext: &[u8],
    orders: &[V1LayerKind],
) -> Result<Vec<u8>, MigrateError> {
    let mut current = ciphertext.to_vec();
    for order in orders {
        let next = match order {
            V1LayerKind::AesGcm => open_aes_gcm(aes_key, &current)?,
            V1LayerKind::Kuznechik | V1LayerKind::Ntrup | V1LayerKind::Cyber => {
                return Err(MigrateError::UnsupportedLayer);
            }
        };
        current = next;
    }
    Ok(current)
}

fn open_aes_gcm(key: &[u8; 32], packed: &[u8]) -> Result<Vec<u8>, MigrateError> {
    let min_len = GCM_NONCE_LEN + GCM_TAG_LEN;
    if packed.len() < min_len {
        return Err(MigrateError::V1Auth);
    }
    let nonce_at = packed
        .len()
        .checked_sub(GCM_NONCE_LEN)
        .ok_or(MigrateError::V1Auth)?;
    // `get` after the length check. v1 sliced the tail with no check.
    let ct_and_tag = packed.get(..nonce_at).ok_or(MigrateError::V1Auth)?;
    let nonce_bytes = packed.get(nonce_at..).ok_or(MigrateError::V1Auth)?;
    let nonce_array: [u8; GCM_NONCE_LEN] =
        nonce_bytes.try_into().map_err(|_| MigrateError::V1Auth)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| MigrateError::V1Auth)?;
    cipher
        .decrypt(&Nonce::from(nonce_array), ct_and_tag)
        .map_err(|_| MigrateError::V1Auth)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        indexed_key, legacy_salt, open_aes_gcm, peel, GCM_NONCE_LEN, GCM_TAG_LEN, MEM_KIB,
        WALLET_SALT,
    };
    use crate::create::body_ad;
    use crate::migrate::{migrate, MigrateError, V1LayerKind};
    use crate::VaultV2Error;
    use aead::{decrypt_body, BodyAlg};
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use container::WrapEntry;
    use kdf::KdfProfile;

    #[test]
    fn layout_salt_and_rejections_do_not_hash() {
        assert_eq!(
            migrate(b"", b"", b"", &[], KdfProfile::Mobile, BodyAlg::Aegis256).unwrap_err(),
            MigrateError::EmptyPassword
        );
        let short = [0u8; GCM_NONCE_LEN + GCM_TAG_LEN - 1];
        assert_eq!(
            migrate(
                b"pw",
                b"",
                &short,
                &[V1LayerKind::AesGcm],
                KdfProfile::Mobile,
                BodyAlg::Aegis256
            )
            .unwrap_err(),
            MigrateError::V1Auth
        );
        for kind in [
            V1LayerKind::Kuznechik,
            V1LayerKind::Ntrup,
            V1LayerKind::Cyber,
        ] {
            assert_eq!(
                migrate(
                    b"pw",
                    b"fp",
                    &[0; 64],
                    &[kind],
                    KdfProfile::Mobile,
                    BodyAlg::Aegis256
                )
                .unwrap_err(),
                MigrateError::UnsupportedLayer
            );
        }
        // An inner NTRU order must fail closed, not be sealed as the v2 body.
        assert_eq!(
            migrate(
                b"pw",
                b"",
                &[0; 64],
                &[V1LayerKind::AesGcm, V1LayerKind::Ntrup],
                KdfProfile::Mobile,
                BodyAlg::Aegis256
            )
            .unwrap_err(),
            MigrateError::UnsupportedLayer
        );
        assert_eq!(
            migrate(
                b"\xff",
                b"",
                b"",
                &[],
                KdfProfile::Mobile,
                BodyAlg::Aegis256
            )
            .unwrap_err(),
            MigrateError::Vault(VaultV2Error::CorruptedLength)
        );

        let salt = legacy_salt(b"").unwrap();
        assert_eq!(salt.as_slice(), WALLET_SALT);
        let mixed = legacy_salt(b"fp").unwrap();
        assert_eq!(mixed.len(), 2 + WALLET_SALT.len());
        assert!(mixed.starts_with(b"fp"));
        assert!(mixed.ends_with(WALLET_SALT));

        let seed = b"seed-bytes";
        let aes = indexed_key(seed, 0).unwrap();
        let kuz = indexed_key(seed, 1).unwrap();
        let cyber = indexed_key(seed, 2).unwrap();
        assert_ne!(aes, kuz);
        assert_ne!(kuz, cyber);
        // from_bytes would hash the AES key, not the seed, for the other layers.
        assert_ne!(kuz, indexed_key(&aes, 1).unwrap());

        let key = [9u8; 32];
        let nonce = [7u8; GCM_NONCE_LEN];
        let outer_pt = b"record-bytes";
        let blob = seal_aes(&key, outer_pt, nonce);
        assert_eq!(blob.len(), outer_pt.len() + GCM_TAG_LEN + GCM_NONCE_LEN);
        assert_eq!(
            blob.get(blob.len() - GCM_NONCE_LEN..),
            Some(nonce.as_slice())
        );
        assert_eq!(open_aes_gcm(&key, &blob).unwrap(), outer_pt);
        assert_eq!(
            open_aes_gcm(&key, &[0; 27]).unwrap_err(),
            MigrateError::V1Auth
        );
        let mut tampered = blob;
        let first = tampered.first_mut().unwrap();
        *first ^= 0x01;
        assert_eq!(
            open_aes_gcm(&key, &tampered).unwrap_err(),
            MigrateError::V1Auth
        );

        let inner = seal_aes(&key, outer_pt, nonce);
        let outer = seal_aes(&key, &inner, [8u8; GCM_NONCE_LEN]);
        assert_eq!(
            peel(&key, &outer, &[V1LayerKind::AesGcm, V1LayerKind::AesGcm]).unwrap(),
            outer_pt
        );
        assert_eq!(MEM_KIB, 65_536);
    }

    #[test]
    fn migrate_one_mobile_hash() {
        // Argon2 lives in this one test. The vector is v1's published lanes=2 hash.
        // `create` has no floor profile, so the vault uses Mobile once.
        assert_v1_argon_vector();
        // v1 Argon2id is the legacy 64 MiB / t = 1 default, not a second Mobile.
        let password = b"migrate-password";
        let records = b"v1-records";
        let key = super::derive_seed(password, b"").unwrap();
        let aes = indexed_key(key.expose(), 0).unwrap();
        let blob = seal_aes(&aes, records, [3u8; GCM_NONCE_LEN]);
        let migrated = migrate(
            password,
            b"",
            &blob,
            &[V1LayerKind::AesGcm],
            KdfProfile::Mobile,
            BodyAlg::Aegis256,
        )
        .unwrap();
        assert!(migrated.shared_salt);
        assert_eq!(migrated.session.generation(), 2);
        assert!(migrated.file.as_bytes().starts_with(b"BRBY"));
        let parsed = migrated.file.parse().unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert!(matches!(
            parsed.entries.first(),
            Some(WrapEntry::Password(_))
        ));
        let ad = body_ad(&parsed.header);
        let opened = decrypt_body(
            migrated.session.body_alg,
            migrated.session.k_body.expose(),
            migrated.session.k_bmac.expose(),
            parsed.body,
            &ad,
        )
        .unwrap();
        assert_eq!(opened, records);
    }

    fn assert_v1_argon_vector() {
        use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

        let ad = AssociatedData::new(super::APP_ID).unwrap();
        let mut builder = ParamsBuilder::new();
        builder
            .m_cost(65_536)
            .t_cost(1)
            .p_cost(2)
            .output_len(64)
            .data(ad);
        let params = builder.build().unwrap();
        let context = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut salt = b"some_salt".to_vec();
        salt.extend_from_slice(WALLET_SALT);
        let mut raw = [0u8; 64];
        context
            .hash_password_into(b"test_password", &salt, &mut raw)
            .unwrap();
        assert_eq!(
            raw,
            [
                241, 5, 105, 168, 214, 152, 5, 38, 199, 60, 34, 215, 245, 198, 217, 49, 108, 140,
                86, 183, 92, 152, 168, 92, 64, 48, 241, 204, 238, 247, 198, 88, 18, 126, 75, 177,
                211, 74, 244, 234, 39, 92, 32, 255, 148, 131, 9, 175, 213, 251, 48, 220, 238, 146,
                16, 147, 132, 15, 46, 51, 176, 134, 238, 69
            ]
        );
    }

    fn seal_aes(key: &[u8; 32], plaintext: &[u8], nonce: [u8; GCM_NONCE_LEN]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(key).expect("aes key");
        let mut out = cipher
            .encrypt(&Nonce::from(nonce), plaintext)
            .expect("seal");
        out.extend_from_slice(&nonce);
        out
    }
}
