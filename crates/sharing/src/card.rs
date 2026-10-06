//! The contact card: what a person gives another so they can be added to a
//! shared vault. It names an account (id and root key), one device of it
//! with its certificate, and that device's invitation keys, all signed by the
//! device.
//!
//! A card travels over a channel nobody authenticated, so its signatures only
//! guard against damage. What authenticates it is the account fingerprint,
//! which the receiver compares with the owner out loud.

use anyhow::{anyhow, Result};
use pq::{sync_sign, sync_verify, CONTACT_CTX, SYNC_SIG_LEN, SYNC_VK_LEN};
use session::{frame_parts, DeviceCert, DeviceSignKey};
use sha2::{Digest, Sha256};
use syncwire::reader::Reader;
use syncwire::{decode_cert, encode_cert, CERT_WIRE_LEN};

use crate::fingerprint::{account_fingerprint, Fingerprint};
use crate::text;

const DOMAIN_CARD: &[u8] = b"brby/v2/contact-card";
const DOMAIN_CARD_ID: &[u8] = b"brby/v2/contact-card-id";
const MAGIC: [u8; 4] = *b"ZPCC";
const WIRE_VERSION: u16 = 1;
const EC_PUB_LEN: usize = 65;
const KEM_EK_LEN: usize = pq::PQ_PK_LEN;

/// Prefix of the text form.
pub const CARD_PREFIX: &str = "zp-card1";

/// Exact length of an encoded card.
pub const CARD_WIRE_LEN: usize =
    4 + 2 + CERT_WIRE_LEN + SYNC_VK_LEN + EC_PUB_LEN + KEM_EK_LEN + 8 + SYNC_SIG_LEN;

/// How old a card may be when it is used.
pub const MAX_CARD_AGE_MS: u64 = 30 * 24 * 3600 * 1000;

const MAX_FUTURE_MS: u64 = 24 * 3600 * 1000;

fn invalid() -> anyhow::Error {
    anyhow!("invalid contact card")
}

/// A signed contact card.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactCard {
    /// Certificate of the device that issued the card.
    pub cert: DeviceCert,
    /// Root key of the card's account.
    pub root_vk: Box<[u8; SYNC_VK_LEN]>,
    /// P-256 half of the device's invitation key.
    pub ec_pub: [u8; EC_PUB_LEN],
    /// ML-KEM half of the device's invitation key.
    pub kem_ek: Box<[u8; KEM_EK_LEN]>,
    /// When the card was made, in unix milliseconds.
    pub issued_ms: u64,
    /// ML-DSA signature by the device.
    pub signature: Vec<u8>,
}

impl ContactCard {
    fn signed_message(&self) -> Result<Vec<u8>> {
        let cert_hash: [u8; 32] = Sha256::digest(encode_cert(&self.cert)?).into();
        frame_parts(&[
            DOMAIN_CARD,
            &cert_hash,
            self.root_vk.as_slice(),
            &self.ec_pub,
            self.kem_ek.as_slice(),
            &self.issued_ms.to_be_bytes(),
        ])
    }

    /// Make a card for this device.
    ///
    /// # Errors
    ///
    /// `invalid contact card` for a key of the wrong length; signing failure.
    pub fn issue(
        sign: &DeviceSignKey,
        cert: &DeviceCert,
        root_vk: &[u8; SYNC_VK_LEN],
        ec_pub: [u8; EC_PUB_LEN],
        kem_ek: &[u8],
        issued_ms: u64,
    ) -> Result<Self> {
        let kem_ek = Box::new(<[u8; KEM_EK_LEN]>::try_from(kem_ek).map_err(|_| invalid())?);
        let unsigned = Self {
            cert: cert.clone(),
            root_vk: Box::new(*root_vk),
            ec_pub,
            kem_ek,
            issued_ms,
            signature: Vec::new(),
        };
        let signature = sync_sign(sign.seed(), CONTACT_CTX, &unsigned.signed_message()?)?;
        Ok(Self {
            signature,
            ..unsigned
        })
    }

    /// Check the card: the certificate chains to the card's root key and is
    /// unexpired, the device signed the card, and the card is neither older
    /// than [`MAX_CARD_AGE_MS`] nor from the future.
    ///
    /// # Errors
    ///
    /// `invalid contact card` for every failure.
    pub fn verify(&self, now_ms: u64) -> Result<()> {
        self.cert
            .verify(&self.root_vk, now_ms)
            .map_err(|_| invalid())?;
        let fresh = now_ms.saturating_sub(self.issued_ms) <= MAX_CARD_AGE_MS
            && self.issued_ms <= now_ms.saturating_add(MAX_FUTURE_MS);
        if !fresh {
            return Err(invalid());
        }
        sync_verify(
            &self.cert.device_vk,
            CONTACT_CTX,
            &self.signed_message().map_err(|_| invalid())?,
            &self.signature,
        )
        .map_err(|_| invalid())
    }

    /// The code both people compare: the same on every card of this account.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        account_fingerprint(&self.cert.client_id, &self.root_vk)
    }

    /// Identifies the account, device and keys the card names, not when it
    /// was signed: a card made again later for the same device has the same
    /// id, so an invitation stays valid for it. An invitation is bound to
    /// this id.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for part in [
            DOMAIN_CARD_ID,
            &self.cert.client_id[..],
            &self.cert.device_id[..],
            self.root_vk.as_slice(),
            &self.ec_pub[..],
            self.kem_ek.as_slice(),
        ] {
            hasher.update(u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
            hasher.update(part);
        }
        hasher.finalize().into()
    }

    /// Encode the card.
    ///
    /// # Errors
    ///
    /// A wrong-length signature or a certificate that does not encode.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.signature.len() != SYNC_SIG_LEN {
            return Err(invalid());
        }
        let mut out = Vec::with_capacity(CARD_WIRE_LEN);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&encode_cert(&self.cert)?);
        out.extend_from_slice(self.root_vk.as_slice());
        out.extend_from_slice(&self.ec_pub);
        out.extend_from_slice(self.kem_ek.as_slice());
        out.extend_from_slice(&self.issued_ms.to_be_bytes());
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Decode a card. Signatures are not verified here.
    ///
    /// # Errors
    ///
    /// `invalid contact card` for a wrong length, magic or version.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CARD_WIRE_LEN {
            return Err(invalid());
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != MAGIC || reader.u16()? != WIRE_VERSION {
            return Err(invalid());
        }
        let cert = decode_cert(reader.take(CERT_WIRE_LEN)?)?;
        let root_vk = Box::new(reader.array()?);
        let ec_pub = reader.array()?;
        let kem_ek = Box::new(reader.array()?);
        let issued_ms = reader.u64()?;
        let signature = reader.take(SYNC_SIG_LEN)?.to_vec();
        reader.finish()?;
        Ok(Self {
            cert,
            root_vk,
            ec_pub,
            kem_ek,
            issued_ms,
            signature,
        })
    }

    /// The text to copy.
    ///
    /// # Errors
    ///
    /// The card does not encode.
    pub fn to_text(&self) -> Result<String> {
        Ok(text::encode(CARD_PREFIX, &self.encode()?))
    }

    /// Parse pasted text.
    ///
    /// # Errors
    ///
    /// `invalid share text` or `invalid contact card`.
    pub fn from_text(pasted: &str) -> Result<Self> {
        Self::decode(&text::decode(CARD_PREFIX, pasted, CARD_WIRE_LEN)?)
    }
}
