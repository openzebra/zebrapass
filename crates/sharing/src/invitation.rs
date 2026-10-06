//! The invitation: what the owner gives a new member after adding them.
//!
//! It carries the vault number, the member log, and the vault's seed sealed
//! to the invitee's device with the same hybrid ML-KEM and P-256 exchange a
//! device wrap uses. The seed key binds the vault, the log head and the exact
//! contact card, and a device of a member signs the whole thing, so an
//! invitation cannot be redirected to another card or another vault.
//!
//! The invitee still has to check the inviter's fingerprint with the inviter
//! out loud: anyone who saw the card can wrap a seed to it.

use anyhow::{anyhow, Result};
use memberlog::{Entry, MemberLog, ENTRY_WIRE_LEN};
use pq::{sync_sign, sync_verify, INVITE_CTX, SYNC_SIG_LEN};
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
const WIRE_VERSION: u16 = 1;
const GRANT_STREAM: u32 = 0x8000_0010;

/// Prefix of the text form.
pub const INVITE_PREFIX: &str = "zp-invite1";

/// Longest vault name.
pub const MAX_NAME: usize = 64;

/// Most address hints an invitation carries.
pub const MAX_HINTS: usize = 4;

/// Longest address hint in bytes (`host:port`).
pub const MAX_HINT: usize = 64;

/// Most log entries an invitation carries. A longer log has to be fetched
/// from a member over the network instead.
pub const MAX_INVITE_ENTRIES: usize = 24;

const SEED_LEN: usize = 64;
const MAX_SEALED: usize = 512;
const FIXED_LEN: usize = 4 + 2 + 16 + 32 + 65 + pq::KEM_CT_LEN + CERT_WIRE_LEN + SYNC_SIG_LEN + 2;

/// Upper bound of an encoded invitation, for the paste buffer.
pub const MAX_INVITE_WIRE_LEN: usize = FIXED_LEN
    + MAX_SEALED
    + 1
    + MAX_HINTS * (1 + MAX_HINT)
    + 2
    + MAX_INVITE_ENTRIES * ENTRY_WIRE_LEN;

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
    /// The member log, oldest first.
    pub entries: Vec<Entry>,
}

/// What an invitation holds once opened and verified.
#[derive(Debug)]
pub struct Opened {
    /// The shared vault's seed: unlock the vault with it.
    pub seed: Secret<[u8; SEED_LEN]>,
    /// The vault's name.
    pub name: String,
    /// The verified member log.
    pub log: MemberLog,
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

fn head_and_anchor(entries: &[Entry]) -> Result<([u8; 32], [u8; 32])> {
    let first = entries.first().ok_or_else(invalid)?;
    let last = entries.last().ok_or_else(invalid)?;
    Ok((first.hash()?, last.hash()?))
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
        let (anchor, head) = head_and_anchor(&self.entries)?;
        let sealed_hash: [u8; 32] = Sha256::digest(&self.sealed).into();
        frame_parts(&[
            DOMAIN_INVITE,
            &self.vault_id,
            &anchor,
            &head,
            &self.card_id,
            &self.eph_ec,
            self.kem_ct.as_slice(),
            &sealed_hash,
            &hints_hash(&self.hints),
            &self.signer.device_id,
            &self.signer.serial.to_be_bytes(),
            &self.signer.client_id,
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
        if !listed
            || log.role_of(&cert.client_id).is_none()
            || log.entries().len() > MAX_INVITE_ENTRIES
            || name.len() > MAX_NAME
            || !valid_hints(hints)
        {
            return Err(invalid());
        }
        let entries = log.entries().to_vec();
        let (anchor, head) = head_and_anchor(&entries)?;
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
            entries,
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
        let (anchor, head) = head_and_anchor(&self.entries)?;
        let log = MemberLog::from_entries(self.vault_id, &self.entries, &anchor)
            .map_err(|_| invalid())?;
        let signer = log
            .members()
            .iter()
            .find(|member| member.client_id == self.signer.client_id)
            .ok_or_else(invalid)?;
        self.signer
            .verify(&signer.root_vk, now_ms)
            .map_err(|_| invalid())?;
        sync_verify(
            &self.signer.device_vk,
            INVITE_CTX,
            &self.signed_message().map_err(|_| invalid())?,
            &self.signature,
        )
        .map_err(|_| invalid())?;
        let me_listed = log.members().iter().any(|member| {
            member.client_id == my_card.cert.client_id && member.root_vk == my_card.root_vk
        });
        if !me_listed || my_card.id() != self.card_id {
            return Err(invalid());
        }

        let ss_ec = Secret::new(ec::shared(ec_secret, &ec::decode_pub(&self.eph_ec)?));
        let ss_kem = pq::decrypt_shared(kem_dk.expose(), self.kem_ct.as_slice())?;
        let transcript = grant_transcript(
            &self.vault_id,
            &anchor,
            &head,
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
            inviter: account_fingerprint(&signer.client_id, &signer.root_vk),
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
            || self.entries.is_empty()
            || self.entries.len() > MAX_INVITE_ENTRIES
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
        out.extend_from_slice(&u16::try_from(self.entries.len())?.to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.encode()?);
        }
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
        let count = usize::from(reader.u16()?);
        if count == 0 || count > MAX_INVITE_ENTRIES {
            return Err(invalid());
        }
        let entries = (0..count)
            .map(|_| Entry::decode(reader.take(ENTRY_WIRE_LEN)?))
            .collect::<Result<Vec<_>>>()?;
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
            entries,
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
