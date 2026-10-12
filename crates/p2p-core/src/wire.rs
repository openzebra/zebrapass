//! Exact-length encodings of the three handshake messages.

use anyhow::{anyhow, Result};
use syncwire::reader::Reader;

use crate::admission::{gate_tag, Cookie};
use crate::suite::{
    CHALLENGE_LEN, EC_PUB_LEN, FINISH_LEN, GATE_TAG_LEN, HELLO_BODY_LEN, HELLO_LEN, KIND_CHALLENGE,
    KIND_FINISH, KIND_HELLO, KIND_REPLY, KIND_SOLVED, MAGIC, NONCE_LEN, REPLY_FIXED_LEN, REPLY_LEN,
    SEALED_PROOF_LEN, SOLVED_LEN, SUITE, WIRE_VERSION,
};
use secret::Secret;

fn malformed() -> anyhow::Error {
    anyhow!("malformed handshake message")
}

fn header(kind: u8) -> [u8; 9] {
    let mut out = [0u8; 9];
    let (magic, rest) = out.split_at_mut(4);
    magic.copy_from_slice(&MAGIC);
    let (version, rest) = rest.split_at_mut(2);
    version.copy_from_slice(&WIRE_VERSION.to_be_bytes());
    let (suite, kind_byte) = rest.split_at_mut(2);
    suite.copy_from_slice(&SUITE.to_be_bytes());
    kind_byte.copy_from_slice(&[kind]);
    out
}

fn check_header(reader: &mut Reader<'_>, kind: u8) -> Result<()> {
    if reader.array::<4>()? != MAGIC
        || reader.u16()? != WIRE_VERSION
        || reader.u16()? != SUITE
        || reader.array::<1>()? != [kind]
    {
        return Err(malformed());
    }
    Ok(())
}

/// Fields of an initiator hello.
pub struct Hello<'a> {
    pub ec_pub: [u8; EC_PUB_LEN],
    pub kem_ek: &'a [u8],
    pub timestamp_ms: u64,
    /// The bytes the gate tag covers.
    pub body: &'a [u8],
    pub tag: [u8; GATE_TAG_LEN],
}

/// Fields of the unsealed part of a reply, and its sealed proof.
pub struct Reply<'a> {
    pub ec_pub: [u8; EC_PUB_LEN],
    pub kem_ct: &'a [u8],
    pub fixed: &'a [u8],
    pub sealed: &'a [u8],
}

/// A solved puzzle with the hello it answers.
pub struct Solved<'a> {
    pub cookie: Cookie,
    pub counter: u64,
    pub hello: &'a [u8],
}

pub fn encode_hello(
    ec_pub: &[u8; EC_PUB_LEN],
    kem_ek: &[u8],
    nonce: &[u8; NONCE_LEN],
    timestamp_ms: u64,
    gate_key: &Secret<[u8; 32]>,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(HELLO_LEN);
    out.extend_from_slice(&header(KIND_HELLO));
    out.extend_from_slice(ec_pub);
    out.extend_from_slice(kem_ek);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    let tag = gate_tag(gate_key, &out)?;
    out.extend_from_slice(&tag);
    Ok(out)
}

pub fn decode_hello(bytes: &[u8]) -> Result<Hello<'_>> {
    if bytes.len() != HELLO_LEN {
        return Err(malformed());
    }
    let (body, _) = bytes
        .split_at_checked(HELLO_BODY_LEN)
        .ok_or_else(malformed)?;
    let mut reader = Reader::new(bytes);
    check_header(&mut reader, KIND_HELLO)?;
    let ec_pub = reader.array()?;
    let kem_ek =
        reader.take(HELLO_BODY_LEN - crate::suite::HEADER_LEN - EC_PUB_LEN - NONCE_LEN - 8)?;
    reader.take(NONCE_LEN)?;
    let timestamp_ms = reader.u64()?;
    let tag = reader.array()?;
    reader.finish()?;
    Ok(Hello {
        ec_pub,
        kem_ek,
        timestamp_ms,
        body,
        tag,
    })
}

fn put_cookie(out: &mut Vec<u8>, cookie: &Cookie) {
    out.push(cookie.difficulty);
    out.extend_from_slice(&cookie.issued_ms.to_be_bytes());
    out.extend_from_slice(&cookie.mac);
}

fn read_cookie(reader: &mut Reader<'_>) -> Result<Cookie> {
    Ok(Cookie {
        difficulty: reader.array::<1>()?[0],
        issued_ms: reader.u64()?,
        mac: reader.array()?,
    })
}

pub fn encode_challenge(cookie: &Cookie) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHALLENGE_LEN);
    out.extend_from_slice(&header(KIND_CHALLENGE));
    put_cookie(&mut out, cookie);
    out
}

pub fn decode_challenge(bytes: &[u8]) -> Result<Cookie> {
    if bytes.len() != CHALLENGE_LEN {
        return Err(malformed());
    }
    let mut reader = Reader::new(bytes);
    check_header(&mut reader, KIND_CHALLENGE)?;
    let cookie = read_cookie(&mut reader)?;
    reader.finish()?;
    Ok(cookie)
}

pub fn encode_solved(cookie: &Cookie, counter: u64, hello: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SOLVED_LEN);
    out.extend_from_slice(&header(KIND_SOLVED));
    put_cookie(&mut out, cookie);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(hello);
    out
}

pub fn decode_solved(bytes: &[u8]) -> Result<Solved<'_>> {
    if bytes.len() != SOLVED_LEN {
        return Err(malformed());
    }
    let mut reader = Reader::new(bytes);
    check_header(&mut reader, KIND_SOLVED)?;
    let cookie = read_cookie(&mut reader)?;
    let counter = reader.u64()?;
    let hello = reader.take(HELLO_LEN)?;
    reader.finish()?;
    Ok(Solved {
        cookie,
        counter,
        hello,
    })
}

pub fn encode_reply_fixed(
    ec_pub: &[u8; EC_PUB_LEN],
    kem_ct: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(REPLY_LEN);
    out.extend_from_slice(&header(KIND_REPLY));
    out.extend_from_slice(ec_pub);
    out.extend_from_slice(kem_ct);
    out.extend_from_slice(nonce);
    out
}

pub fn decode_reply(bytes: &[u8]) -> Result<Reply<'_>> {
    if bytes.len() != REPLY_LEN {
        return Err(malformed());
    }
    let (fixed, sealed) = bytes
        .split_at_checked(REPLY_FIXED_LEN)
        .ok_or_else(malformed)?;
    let mut reader = Reader::new(fixed);
    check_header(&mut reader, KIND_REPLY)?;
    let ec_pub = reader.array()?;
    let kem_ct =
        reader.take(REPLY_FIXED_LEN - crate::suite::HEADER_LEN - EC_PUB_LEN - NONCE_LEN)?;
    reader.take(NONCE_LEN)?;
    reader.finish()?;
    Ok(Reply {
        ec_pub,
        kem_ct,
        fixed,
        sealed,
    })
}

pub fn encode_finish(sealed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FINISH_LEN);
    out.extend_from_slice(&header(KIND_FINISH));
    out.extend_from_slice(sealed);
    out
}

pub fn decode_finish(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.len() != FINISH_LEN {
        return Err(malformed());
    }
    let mut reader = Reader::new(bytes);
    check_header(&mut reader, KIND_FINISH)?;
    let sealed = reader.take(SEALED_PROOF_LEN)?;
    reader.finish()?;
    Ok(sealed)
}
