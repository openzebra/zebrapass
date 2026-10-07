//! The invitation: what the owner gives a new member after adding them.
//!
//! It carries the vault number, the first member log entry, the hash of the
//! log's newest entry, the inviter's root key, and the vault's seed sealed to
//! the invitee's device with the same hybrid ML-KEM and P-256 exchange a
//! device wrap uses. The seed key binds the vault, the log head and the exact
//! contact card, and a device of a member signs the whole thing, so an
//! invitation cannot be redirected to another card or another vault. The rest
//! of the member log is fetched from a member after joining and has to chain
//! from the first entry to the signed head.
//!
//! The invitee still has to check the inviter's fingerprint with the inviter
//! out loud: anyone who saw the card can wrap a seed to it.

use anyhow::{anyhow, Result};
use memberlog::{Entry, MemberLog, ENTRY_WIRE_LEN};
use pq::{sync_sign, sync_verify, INVITE_CTX, SYNC_SIG_LEN, SYNC_VK_LEN};
use secret::Secret;
use session::{frame_parts, DeviceCert, DeviceSignKey};
use sha2::{Digest, Sha256};
use syncwire::reader::Reader;
use syncwire::{decode_cert, encode_cert, CERT_WIRE_LEN};

use crate::card::ContactCard;
use crate::fingerprint::{account_fingerprint, vault_fingerprint, vault_number, Fingerprint};
use crate::text;

const DOMAIN_GRANT: &[u8] = b"brby/v2/invitation-grant";
const DOMAIN_INVITE: &[u8] = b"brby/v2/invitation";
const MAGIC: [u8; 4] = *b"ZPIV";
const WIRE_VERSION: u16 = 2;
const GRANT_STREAM: u32 = 0x8000_0010;

/// Prefix of the text form.
pub const INVITE_PREFIX: &str = "zp-invite1";

/// Longest vault name.
pub const MAX_NAME: usize = 64;

/// Most address hints an invitation carries.
pub const MAX_HINTS: usize = 4;

/// Longest address hint in bytes (`host:port`).
pub const MAX_HINT: usize = 64;

const SEED_LEN: usize = 64;
const MAX_SEALED: usize = 512;
const FIXED_LEN: usize = 4 + 2 + 16 + 32 + 65 + pq::KEM_CT_LEN + CERT_WIRE_LEN + SYNC_SIG_LEN + 2;
const PROOF_LEN: usize = 32 + SYNC_VK_LEN + ENTRY_WIRE_LEN;

/// Upper bound of an encoded invitation, for the paste buffer.
pub const MAX_INVITE_WIRE_LEN: usize =
    FIXED_LEN + MAX_SEALED + 1 + MAX_HINTS * (1 + MAX_HINT) + PROOF_LEN;

fn invalid() -> anyhow::Error {
    anyhow!("invalid invitation")
}

/// The member device that signs an invitation.
#[derive(Clone, Copy, Debug)]
pub struct Inviter<'a> {
    /// The device's signing key.
    pub sign: &'a DeviceSignKey,
    /// The device's certificate.
    pub cert: &'a DeviceCert,
}

/// What an invitation hands over.
#[derive(Clone, Copy, Debug)]
pub struct Offer<'a> {
    /// The shared vault's seed.
    pub seed: &'a Secret<[u8; SEED_LEN]>,
    /// The vault's name.
    pub name: &'a str,
    /// Where the inviter's device can be reached.
    pub hints: &'a [String],
}

/// A signed invitation to one contact card.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invitation {
    /// The shared vault's number.
    pub vault_id: [u8; 16],
    /// The contact card this invitation is for.
    pub card_id: [u8; 32],
    /// Ephemeral P-256 share of the grant.
    pub eph_ec: [u8; 65],
    /// ML-KEM ciphertext of the grant.
    pub kem_ct: Box<[u8; pq::KEM_CT_LEN]>,
    /// Certificate of the member device that signed.
    pub signer: DeviceCert,
    /// ML-DSA signature by that device.
    pub signature: Vec<u8>,
    /// The seed and name, sealed under the grant key.
    pub sealed: Vec<u8>,
    /// Where the inviter's device can be reached (`host:port`), best first.
    pub hints: Vec<String>,
    /// The vault's first member log entry.
    pub genesis: Entry,
    /// Hash of the newest log entry when the invitation was issued.
    pub head: [u8; 32],
    /// Root key the signer's certificate chains to.
    pub inviter_vk: Box<[u8; SYNC_VK_LEN]>,
}

/// What an invitation holds once opened and verified.
#[derive(Debug)]
pub struct Opened {
    /// The shared vault's seed: unlock the vault with it.
    pub seed: Secret<[u8; SEED_LEN]>,
    /// The vault's name.
    pub name: String,
    /// The member log as far as the invitation proves it: the first entry.
    pub log: MemberLog,
    /// Hash of the newest log entry the inviter signed for: the log fetched
    /// from a member has to contain it.
    pub head: [u8; 32],
    /// The signing member's account id.
    pub inviter_id: [u8; 64],
    /// The signing member's root key.
    pub inviter_vk: Box<[u8; SYNC_VK_LEN]>,
    /// Where the inviter's device can be reached.
    pub hints: Vec<String>,
    /// The signing member's code: compare it with that person aloud.
    pub inviter: Fingerprint,
    /// The vault's code, from its number and first log entry.
    pub vault: Fingerprint,
    /// The vault's number as people read it.
    pub number: String,
}

fn hints_hash(hints: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for hint in hints {
        hasher.update(u32::try_from(hint.len()).unwrap_or(u32::MAX).to_be_bytes());
        hasher.update(hint.as_bytes());
    }
    hasher.finalize().into()
}

fn valid_hints(hints: &[String]) -> bool {
    hints.len() <= MAX_HINTS
        && hints
            .iter()
            .all(|hint| !hint.is_empty() && hint.len() <= MAX_HINT && hint.is_ascii())
}

fn grant_transcript(
    vault_id: &[u8; 16],
    anchor: &[u8; 32],
    head: &[u8; 32],
    card_id: &[u8; 32],
    eph_ec: &[u8; 65],
    kem_ct: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN_GRANT)
        .chain_update(vault_id)
        .chain_update(anchor)
        .chain_update(head)
        .chain_update(card_id)
        .chain_update(eph_ec)
        .chain_update(kem_ct)
        .finalize()
        .into()
}

impl Invitation {
    fn signed_message(&self) -> Result<Vec<u8>> {
        let anchor = self.genesis.hash()?;
        let sealed_hash: [u8; 32] = Sha256::digest(&self.sealed).into();
        frame_parts(&[
            DOMAIN_INVITE,
            &self.vault_id,
            &anchor,
            &self.head,
            &self.card_id,
            &self.eph_ec,
            self.kem_ct.as_slice(),
            &sealed_hash,
            &hints_hash(&self.hints),
            &self.signer.device_id,
            &self.signer.serial.to_be_bytes(),
            &self.signer.client_id,
            &Sha256::digest(self.inviter_vk.as_slice()),
        ])
    }

    /// Invite the owner of `recipient` into the vault `log` describes.
    ///
    /// The recipient's account must already be in the log with the same root
    /// key, and `cert` must belong to a member.
    ///
    /// # Errors
    ///
    /// `invalid invitation` for a card that does not verify or is not in the
    /// log, a signer who is not a member, a too-long log or name; entropy,
    /// key-exchange or signing failure.
    pub fn issue(
        inviter: &Inviter<'_>,
        log: &MemberLog,
        recipient: &ContactCard,
        offer: &Offer<'_>,
        now_ms: u64,
    ) -> Result<Self> {
        let Inviter { sign, cert } = *inviter;
        let Offer { seed, name, hints } = *offer;
        recipient.verify(now_ms)?;
        let listed = log.members().iter().any(|member| {
            member.client_id == recipient.cert.client_id && member.root_vk == recipient.root_vk
        });
        let inviter = log
            .members()
            .iter()
            .find(|member| member.client_id == cert.client_id)
            .ok_or_else(invalid)?;
        if !listed || name.len() > MAX_NAME || !valid_hints(hints) {
            return Err(invalid());
        }
        let genesis = log.entries().first().ok_or_else(invalid)?.clone();
        let anchor = *log.anchor();
        let head = *log.head();
        let card_id = recipient.id();
        let (eph_secret, eph_public) = ec::fresh_pair()?;
        let eph_ec = ec::encode_pub(&eph_public)?;
        let ss_ec = Secret::new(ec::shared(&eph_secret, &ec::decode_pub(&recipient.ec_pub)?));
        let (ss_kem, kem_ct) = pq::encrypt_shared(recipient.kem_ek.as_slice())?;
        let kem_ct = Box::new(<[u8; pq::KEM_CT_LEN]>::try_from(kem_ct).map_err(|_| invalid())?);
        let transcript = grant_transcript(
            log.vault_id(),
            &anchor,
            &head,
            &card_id,
            &eph_ec,
            kem_ct.as_slice(),
        );
        let key = kdf::share_grant_key(&ss_kem, &ss_ec, log.vault_id(), &transcript)?;

        let mut plain = Secret::new(Vec::with_capacity(SEED_LEN + 1 + name.len()));
        plain.expose_mut().extend_from_slice(seed.expose());
        plain
            .expose_mut()
            .push(u8::try_from(name.len()).map_err(|_| invalid())?);
        plain.expose_mut().extend_from_slice(name.as_bytes());
        let meta = frame::FrameMeta {
            kind: frame::KIND_REVISION,
            record_id: GRANT_STREAM,
            revision: 0,
            origin_device: cert.device_id,
            timestamp_ms: 0,
            alg: frame::ALG_CASCADE,
        };
        let sealed = frame::seal(&key, &meta, plain.expose())?;

        let unsigned = Self {
            vault_id: *log.vault_id(),
            card_id,
            eph_ec,
            kem_ct,
            signer: cert.clone(),
            signature: Vec::new(),
            sealed,
            hints: hints.to_vec(),
            genesis,
            head,
            inviter_vk: inviter.root_vk.clone(),
        };
        let signature = sync_sign(sign.seed(), INVITE_CTX, &unsigned.signed_message()?)?;
        Ok(Self {
            signature,
            ..unsigned
        })
    }

    /// Verify the invitation and open its grant with this device's keys.
    ///
    /// The member log is replayed from its first entry, the signer must be a
    /// member whose certificate chains to that member's root key, the
    /// invitation must be for `my_card`, and `my_card`'s account must be in
    /// the log. Nothing here proves the log is the vault the invitee meant:
    /// the caller must show [`Opened::inviter`] and [`Opened::vault`] and get
    /// the person's confirmation before keeping the seed.
    ///
    /// # Errors
    ///
    /// `invalid invitation` for every failure.
    pub fn open(
        &self,
        ec_secret: &ec::SecretKey,
        kem_dk: &Secret<[u8; SEED_LEN]>,
        my_card: &ContactCard,
        now_ms: u64,
    ) -> Result<Opened> {
        let anchor = self.genesis.hash()?;
        let log =
            MemberLog::from_entries(self.vault_id, std::slice::from_ref(&self.genesis), &anchor)
                .map_err(|_| invalid())?;
        self.signer
            .verify(&self.inviter_vk, now_ms)
            .map_err(|_| invalid())?;
        sync_verify(
            &self.signer.device_vk,
            INVITE_CTX,
            &self.signed_message().map_err(|_| invalid())?,
            &self.signature,
        )
        .map_err(|_| invalid())?;
        if my_card.id() != self.card_id {
            return Err(invalid());
        }

        let ss_ec = Secret::new(ec::shared(ec_secret, &ec::decode_pub(&self.eph_ec)?));
        let ss_kem = pq::decrypt_shared(kem_dk.expose(), self.kem_ct.as_slice())?;
        let transcript = grant_transcript(
            &self.vault_id,
            &anchor,
            &self.head,
            &self.card_id,
            &self.eph_ec,
            self.kem_ct.as_slice(),
        );
        let key = kdf::share_grant_key(&ss_kem, &ss_ec, &self.vault_id, &transcript)?;
        let plain = frame::open(&key, &self.sealed).map_err(|_| invalid())?;
        let (seed_bytes, rest) = plain
            .expose()
            .split_first_chunk::<SEED_LEN>()
            .ok_or_else(invalid)?;
        let (len, name_bytes) = rest.split_first().ok_or_else(invalid)?;
        if usize::from(*len) != name_bytes.len() || name_bytes.len() > MAX_NAME {
            return Err(invalid());
        }
        let name = String::from_utf8(name_bytes.to_vec()).map_err(|_| invalid())?;
        let mut seed = Secret::new([0u8; SEED_LEN]);
        seed.expose_mut().copy_from_slice(seed_bytes);
        Ok(Opened {
            seed,
            name,
            inviter: account_fingerprint(&self.signer.client_id, &self.inviter_vk),
            head: self.head,
            inviter_id: self.signer.client_id,
            inviter_vk: self.inviter_vk.clone(),
            vault: vault_fingerprint(&self.vault_id, &anchor),
            number: vault_number(&self.vault_id),
            hints: self.hints.clone(),
            log,
        })
    }

    /// Encode the invitation.
    ///
    /// # Errors
    ///
    /// A wrong-length signature, an oversized grant or log, or a part that
    /// does not encode.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.signature.len() != SYNC_SIG_LEN
            || self.sealed.len() > MAX_SEALED
            || !valid_hints(&self.hints)
        {
            return Err(invalid());
        }
        let mut out = Vec::with_capacity(MAX_INVITE_WIRE_LEN);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.card_id);
        out.extend_from_slice(&self.eph_ec);
        out.extend_from_slice(self.kem_ct.as_slice());
        out.extend_from_slice(&encode_cert(&self.signer)?);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&u16::try_from(self.sealed.len())?.to_be_bytes());
        out.extend_from_slice(&self.sealed);
        out.push(u8::try_from(self.hints.len())?);
        for hint in &self.hints {
            out.push(u8::try_from(hint.len())?);
            out.extend_from_slice(hint.as_bytes());
        }
        out.extend_from_slice(&self.head);
        out.extend_from_slice(self.inviter_vk.as_slice());
        out.extend_from_slice(&self.genesis.encode()?);
        Ok(out)
    }

    /// Decode an invitation. Nothing is verified here.
    ///
    /// # Errors
    ///
    /// `invalid invitation` for a wrong magic or version, a length over its
    /// bound, truncation or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != MAGIC || reader.u16()? != WIRE_VERSION {
            return Err(invalid());
        }
        let vault_id = reader.array()?;
        let card_id = reader.array()?;
        let eph_ec = reader.array()?;
        let kem_ct = Box::new(reader.array()?);
        let signer = decode_cert(reader.take(CERT_WIRE_LEN)?)?;
        let signature = reader.take(SYNC_SIG_LEN)?.to_vec();
        let sealed = reader.bytes_u16(MAX_SEALED)?.to_vec();
        let hint_count = usize::from(reader.array::<1>()?[0]);
        if hint_count > MAX_HINTS {
            return Err(invalid());
        }
        let hints = (0..hint_count)
            .map(|_| {
                let len = usize::from(reader.array::<1>()?[0]);
                if len > MAX_HINT {
                    return Err(invalid());
                }
                String::from_utf8(reader.take(len)?.to_vec()).map_err(|_| invalid())
            })
            .collect::<Result<Vec<_>>>()?;
        if !valid_hints(&hints) {
            return Err(invalid());
        }
        let head = reader.array()?;
        let inviter_vk = Box::new(reader.array()?);
        let genesis = Entry::decode(reader.take(ENTRY_WIRE_LEN)?)?;
        reader.finish()?;
        Ok(Self {
            vault_id,
            card_id,
            eph_ec,
            kem_ct,
            signer,
            signature,
            sealed,
            hints,
            genesis,
            head,
            inviter_vk,
        })
    }

    /// The text to copy.
    ///
    /// # Errors
    ///
    /// The invitation does not encode.
    pub fn to_text(&self) -> Result<String> {
        Ok(text::encode(INVITE_PREFIX, &self.encode()?))
    }

    /// Parse pasted text.
    ///
    /// # Errors
    ///
    /// `invalid share text` or `invalid invitation`.
    pub fn from_text(pasted: &str) -> Result<Self> {
        Self::decode(&text::decode(INVITE_PREFIX, pasted, MAX_INVITE_WIRE_LEN)?)
    }
}
