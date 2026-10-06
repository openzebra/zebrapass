//! The three-message handshake.
//!
//! ```text
//! I -> R  hello:  EC share, ML-KEM encapsulation key, nonce
//! R -> I  reply:  EC share, ML-KEM ciphertext, nonce,
//!                 sealed{ R certificate, R signature over transcript }
//! I -> R  finish: sealed{ I certificate, I signature over transcript }
//! ```
//!
//! Both key exchanges are ephemeral, so recorded traffic stays closed even if
//! a device key is stolen later, and an attacker needs to break ML-KEM and
//! P-256 both. Certificates travel sealed: the responder reveals itself to
//! any peer that completes the key exchange, the initiator only after the
//! responder proved itself. Each signature covers the transcript so far and
//! the signer's own certificate, and names its role, so no message can be
//! replayed, reflected or spliced into another handshake.

use anyhow::Result;
use frame::{
    open, parse, seal, FrameMeta, ALG_CASCADE, HEADER_LEN as FRAME_HEADER_LEN, KIND_REVISION,
};
use kdf::{p2p_key, INFO_P2P_APP_I2R, INFO_P2P_APP_R2I, INFO_P2P_HS_I2R, INFO_P2P_HS_R2I};
use secret::Secret;
use sha2::{Digest, Sha256};

use crate::admission::{
    check_cookie, check_gate, hello_hash, issue_cookie, solve, CookieSecret, Load,
};
use crate::auth::{failed, prove, verify_proof, Local, Role};
use crate::channel::{Channel, Side, TrafficKeys};
use crate::suite::{KIND_HELLO, KIND_OFFSET, KIND_SOLVED, NONCE_LEN, SEALED_PROOF_LEN};
use crate::wire::{
    decode_challenge, decode_finish, decode_hello, decode_reply, decode_solved, encode_challenge,
    encode_finish, encode_hello, encode_reply_fixed, encode_solved,
};
use session::DeviceCert;

const DOMAIN_TH_A: &[u8] = b"brby/v2/p2p-th-a";
const DOMAIN_TH_B: &[u8] = b"brby/v2/p2p-th-b";
const DOMAIN_TH_C: &[u8] = b"brby/v2/p2p-th-c";

const PROOF_STREAM_REPLY: u32 = 0x8000_0001;
const PROOF_STREAM_FINISH: u32 = 0x8000_0002;

/// A finished handshake.
#[derive(Debug)]
pub struct Established {
    /// The peer's verified certificate.
    pub peer: DeviceCert,
    /// The encrypted channel.
    pub channel: Channel,
}

fn chain(domain: &[u8], previous: &[u8], next: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain)
        .chain_update(previous)
        .chain_update(next)
        .finalize()
        .into()
}

fn seal_proof(
    key: &Secret<[u8; 32]>,
    stream: u32,
    origin: [u8; 16],
    proof: &[u8],
) -> Result<Vec<u8>> {
    let meta = FrameMeta {
        kind: KIND_REVISION,
        record_id: stream,
        revision: 0,
        origin_device: origin,
        timestamp_ms: 0,
        alg: ALG_CASCADE,
    };
    seal(key, &meta, proof)
}

/// Open a sealed proof; returns it with the sender id its header claims.
fn open_proof(
    key: &Secret<[u8; 32]>,
    stream: u32,
    sealed: &[u8],
) -> Result<(Secret<Vec<u8>>, [u8; 16])> {
    if sealed.len() != SEALED_PROOF_LEN {
        return Err(failed());
    }
    let header = parse(sealed).map_err(|_| failed())?;
    if header.alg != ALG_CASCADE
        || header.kind != KIND_REVISION
        || header.record_id != stream
        || header.revision != 0
    {
        return Err(failed());
    }
    let proof = open(key, sealed).map_err(|_| failed())?;
    Ok((proof, header.origin_device))
}

fn traffic_keys(
    ss_kem: &Secret<[u8; 32]>,
    ss_ec: &Secret<[u8; 32]>,
    vault_id: &[u8; 16],
    transcript: &[u8; 32],
) -> Result<TrafficKeys> {
    Ok(TrafficKeys {
        i2r: p2p_key(INFO_P2P_APP_I2R, ss_kem, ss_ec, vault_id, transcript)?,
        r2i: p2p_key(INFO_P2P_APP_R2I, ss_kem, ss_ec, vault_id, transcript)?,
    })
}

fn nonce() -> Result<[u8; NONCE_LEN]> {
    let mut out = [0u8; NONCE_LEN];
    getrandom::fill(&mut out).map_err(|_| anyhow::anyhow!("os entropy failed"))?;
    Ok(out)
}

/// The dialing side, before the reply arrives.
#[derive(Debug)]
pub struct Initiator {
    ec: ec::SecretKey,
    dk: Secret<[u8; 64]>,
    hello: Vec<u8>,
}

impl Initiator {
    /// Draw fresh ephemeral keys and build the gated hello.
    ///
    /// # Errors
    ///
    /// Entropy or key-generation failure.
    pub fn start(gate_key: &Secret<[u8; 32]>, now_ms: u64) -> Result<(Self, Vec<u8>)> {
        let (ec, ec_pub) = ec::fresh_pair()?;
        let (ek, dk) = pq::keypair()?;
        let hello = encode_hello(&ec::encode_pub(&ec_pub)?, &ek, &nonce()?, now_ms, gate_key)?;
        Ok((
            Self {
                ec,
                dk,
                hello: hello.clone(),
            },
            hello,
        ))
    }

    /// Answer a puzzle challenge: the message to send in place of the hello.
    ///
    /// # Errors
    ///
    /// `malformed handshake message` for a wrongly shaped challenge;
    /// `puzzle too hard` when it asks for more work than this client does.
    pub fn solve(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        let cookie = decode_challenge(challenge)?;
        let counter = solve(&cookie, &hello_hash(&self.hello))?;
        Ok(encode_solved(&cookie, counter, &self.hello))
    }

    /// Verify the responder's reply and answer with the finish message.
    ///
    /// # Errors
    ///
    /// `malformed handshake message` for a wrongly shaped message;
    /// `handshake failed` for every authentication failure.
    pub fn finish(
        self,
        local: &Local<'_>,
        reply: &[u8],
        now_ms: u64,
    ) -> Result<(Vec<u8>, Established)> {
        let parts = decode_reply(reply)?;
        let peer_ec = ec::decode_pub(&parts.ec_pub)?;
        let ss_ec = Secret::new(ec::shared(&self.ec, &peer_ec));
        let ss_kem = pq::decrypt_shared(self.dk.expose(), parts.kem_ct)?;
        let th_a = chain(DOMAIN_TH_A, &self.hello, parts.fixed);
        let key_r2i = p2p_key(INFO_P2P_HS_R2I, &ss_kem, &ss_ec, &local.vault_id, &th_a)?;
        let (proof, sender) = open_proof(&key_r2i, PROOF_STREAM_REPLY, parts.sealed)?;
        let peer = verify_proof(local, Role::Responder, &th_a, proof.expose(), now_ms)?;
        if sender != peer.device_id {
            return Err(failed());
        }
        let th_b = chain(DOMAIN_TH_B, &th_a, parts.sealed);
        let own = prove(local, Role::Initiator, &th_b)?;
        let key_i2r = p2p_key(INFO_P2P_HS_I2R, &ss_kem, &ss_ec, &local.vault_id, &th_a)?;
        let sealed = seal_proof(&key_i2r, PROOF_STREAM_FINISH, local.cert.device_id, &own)?;
        let th_c = chain(DOMAIN_TH_C, &th_b, &sealed);
        let keys = traffic_keys(&ss_kem, &ss_ec, &local.vault_id, &th_c)?;
        let channel = Channel::new(Side::Initiator, keys, local.cert.device_id, peer.device_id);
        Ok((encode_finish(&sealed), Established { peer, channel }))
    }
}

/// The listening side, after sending the reply.
#[derive(Debug)]
pub struct Responder {
    ss_kem: Secret<[u8; 32]>,
    ss_ec: Secret<[u8; 32]>,
    key_i2r: Secret<[u8; 32]>,
    th_b: [u8; 32],
    hello_id: [u8; 32],
}

/// What the responder does with a first message.
#[derive(Debug)]
pub enum Accept {
    /// The hello passed the gate (and the puzzle, if one was due): send the
    /// reply and wait for the finish.
    Reply(Responder, Vec<u8>),
    /// The responder is busy: send this challenge and wait for the hello
    /// again with a solution. Nothing is kept.
    Challenge(Vec<u8>),
}

impl Responder {
    /// Which of several vaults a first message is for: the one whose gate
    /// keys verify its tag. The hello names no vault, so an observer learns
    /// nothing about which one a peer wants. Every vault is tried, so the
    /// time taken does not say which matched.
    ///
    /// # Errors
    ///
    /// `malformed handshake message` for a wrongly shaped message;
    /// `handshake failed` when no vault's gate accepts it.
    pub fn route(locals: &[Local<'_>], input: &[u8], now_ms: u64) -> Result<usize> {
        let (hello_bytes, reference_ms) = match input.get(KIND_OFFSET) {
            Some(&KIND_HELLO) => (input, now_ms),
            Some(&KIND_SOLVED) => {
                let solved = decode_solved(input)?;
                (solved.hello, solved.cookie.issued_ms)
            }
            _ => return Err(anyhow::anyhow!("malformed handshake message")),
        };
        let hello = decode_hello(hello_bytes)?;
        let mut found = None;
        for (index, local) in locals.iter().enumerate() {
            let accepted = check_gate(
                local.gate_keys,
                hello.body,
                &hello.tag,
                hello.timestamp_ms,
                reference_ms,
            )
            .is_ok();
            if accepted && found.is_none() {
                found = Some(index);
            }
        }
        found.ok_or_else(failed)
    }

    /// Handle the first message: a hello, or a hello with a solved puzzle.
    ///
    /// The gate is checked first, so a stranger costs one HMAC and gets no
    /// puzzle. Under load a gated hello gets a stateless challenge instead
    /// of a reply.
    ///
    /// # Errors
    ///
    /// `malformed handshake message` for a wrongly shaped message;
    /// `handshake failed` for a failed gate or puzzle; entropy, key-exchange
    /// or signing failure.
    pub fn accept(
        local: &Local<'_>,
        cookies: &CookieSecret,
        load: Load,
        input: &[u8],
        now_ms: u64,
    ) -> Result<Accept> {
        match input.get(KIND_OFFSET) {
            Some(&KIND_HELLO) => {
                let hello = decode_hello(input)?;
                check_gate(
                    local.gate_keys,
                    hello.body,
                    &hello.tag,
                    hello.timestamp_ms,
                    now_ms,
                )?;
                if load.difficulty == 0 {
                    return Self::reply(local, input, &hello);
                }
                let cookie = issue_cookie(cookies, &hello_hash(input), load.difficulty, now_ms)?;
                Ok(Accept::Challenge(encode_challenge(&cookie)))
            }
            Some(&KIND_SOLVED) => {
                let solved = decode_solved(input)?;
                let hello = decode_hello(solved.hello)?;
                // The hello was fresh when the challenge was issued; solving
                // takes time, so freshness is judged against the cookie's
                // issue time, which the cookie check below authenticates.
                check_gate(
                    local.gate_keys,
                    hello.body,
                    &hello.tag,
                    hello.timestamp_ms,
                    solved.cookie.issued_ms,
                )?;
                check_cookie(
                    cookies,
                    &hello_hash(solved.hello),
                    &solved.cookie,
                    solved.counter,
                    load.difficulty,
                    now_ms,
                )?;
                Self::reply(local, solved.hello, &hello)
            }
            _ => Err(anyhow::anyhow!("malformed handshake message")),
        }
    }

    fn reply(
        local: &Local<'_>,
        hello_bytes: &[u8],
        hello: &crate::wire::Hello<'_>,
    ) -> Result<Accept> {
        let peer_ec = ec::decode_pub(&hello.ec_pub)?;
        let (eph_secret, eph_public) = ec::fresh_pair()?;
        let ss_ec = Secret::new(ec::shared(&eph_secret, &peer_ec));
        let (ss_kem, kem_ct) = pq::encrypt_shared(hello.kem_ek)?;
        let fixed = encode_reply_fixed(&ec::encode_pub(&eph_public)?, &kem_ct, &nonce()?);
        let th_a = chain(DOMAIN_TH_A, hello_bytes, &fixed);
        let key_r2i = p2p_key(INFO_P2P_HS_R2I, &ss_kem, &ss_ec, &local.vault_id, &th_a)?;
        let key_i2r = p2p_key(INFO_P2P_HS_I2R, &ss_kem, &ss_ec, &local.vault_id, &th_a)?;
        let proof = prove(local, Role::Responder, &th_a)?;
        let sealed = seal_proof(&key_r2i, PROOF_STREAM_REPLY, local.cert.device_id, &proof)?;
        let th_b = chain(DOMAIN_TH_B, &th_a, &sealed);
        let mut reply = fixed;
        reply.extend_from_slice(&sealed);
        Ok(Accept::Reply(
            Self {
                ss_kem,
                ss_ec,
                key_i2r,
                th_b,
                hello_id: hello_hash(hello_bytes),
            },
            reply,
        ))
    }

    /// Identifies the hello this responder answered. A transport keeps
    /// recent ones to refuse a replayed hello.
    #[must_use]
    pub const fn hello_id(&self) -> &[u8; 32] {
        &self.hello_id
    }

    /// Verify the initiator's finish message.
    ///
    /// # Errors
    ///
    /// `malformed handshake message` for a wrongly shaped message;
    /// `handshake failed` for every authentication failure.
    pub fn finish(self, local: &Local<'_>, finish: &[u8], now_ms: u64) -> Result<Established> {
        let sealed = decode_finish(finish)?;
        let (proof, sender) = open_proof(&self.key_i2r, PROOF_STREAM_FINISH, sealed)?;
        let peer = verify_proof(local, Role::Initiator, &self.th_b, proof.expose(), now_ms)?;
        if sender != peer.device_id {
            return Err(failed());
        }
        let th_c = chain(DOMAIN_TH_C, &self.th_b, sealed);
        let keys = traffic_keys(&self.ss_kem, &self.ss_ec, &local.vault_id, &th_c)?;
        let channel = Channel::new(Side::Responder, keys, local.cert.device_id, peer.device_id);
        Ok(Established { peer, channel })
    }
}

const _: () = assert!(FRAME_HEADER_LEN == 75);
