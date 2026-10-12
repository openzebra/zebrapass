//! Wire form of a list of peer records.

use anyhow::{anyhow, Result};
use session::{PeerRecord, MAX_HINTS, MAX_HINT_LEN, SYNC_SIG_LEN};

use crate::cert::{decode_cert, encode_cert, CERT_WIRE_LEN};
use crate::reader::Reader;

/// First four bytes of an encoded list.
pub const PEER_MAGIC: [u8; 4] = *b"ZPRP";
/// Current wire version.
pub const PEER_WIRE_VERSION: u16 = 2;
/// Most records in one list.
pub const MAX_PEERS: usize = 64;

fn invalid() -> anyhow::Error {
    anyhow!("invalid sync object")
}

fn encode_one(record: &PeerRecord, out: &mut Vec<u8>) -> Result<()> {
    if record.signature.len() != SYNC_SIG_LEN || record.hints.len() > MAX_HINTS {
        return Err(invalid());
    }
    out.extend_from_slice(&record.vault_id);
    out.extend_from_slice(&record.issued_ms.to_be_bytes());
    out.push(u8::try_from(record.hints.len())?);
    for hint in &record.hints {
        out.push(u8::try_from(hint.len()).map_err(|_| invalid())?);
        out.extend_from_slice(hint.as_bytes());
    }
    out.extend_from_slice(&encode_cert(&record.signer)?);
    out.extend_from_slice(&record.signature);
    Ok(())
}

/// Encode up to [`MAX_PEERS`] records.
///
/// # Errors
///
/// Too many records, or one that does not encode.
pub fn encode_peers(records: &[PeerRecord]) -> Result<Vec<u8>> {
    if records.len() > MAX_PEERS {
        return Err(invalid());
    }
    let mut out = Vec::new();
    out.extend_from_slice(&PEER_MAGIC);
    out.extend_from_slice(&PEER_WIRE_VERSION.to_be_bytes());
    out.push(u8::try_from(records.len())?);
    for record in records {
        encode_one(record, &mut out)?;
    }
    Ok(out)
}

fn decode_one(reader: &mut Reader<'_>) -> Result<PeerRecord> {
    let vault_id = reader.array()?;
    let issued_ms = reader.u64()?;
    let count = usize::from(reader.array::<1>()?[0]);
    if count > MAX_HINTS {
        return Err(invalid());
    }
    let hints = (0..count)
        .map(|_| {
            let len = usize::from(reader.array::<1>()?[0]);
            if len == 0 || len > MAX_HINT_LEN {
                return Err(invalid());
            }
            String::from_utf8(reader.take(len)?.to_vec()).map_err(|_| invalid())
        })
        .collect::<Result<Vec<_>>>()?;
    let signer = decode_cert(reader.take(CERT_WIRE_LEN)?)?;
    let signature = reader.take(SYNC_SIG_LEN)?.to_vec();
    Ok(PeerRecord {
        vault_id,
        issued_ms,
        hints,
        signer,
        signature,
    })
}

/// Decode a list. Nothing is verified here.
///
/// # Errors
///
/// A wrong magic, version, count or length, or a malformed record.
pub fn decode_peers(bytes: &[u8]) -> Result<Vec<PeerRecord>> {
    let mut reader = Reader::new(bytes);
    if reader.array::<4>()? != PEER_MAGIC || reader.u16()? != PEER_WIRE_VERSION {
        return Err(invalid());
    }
    let count = usize::from(reader.array::<1>()?[0]);
    if count > MAX_PEERS {
        return Err(invalid());
    }
    let records = (0..count)
        .map(|_| decode_one(&mut reader))
        .collect::<Result<Vec<_>>>()?;
    reader.finish()?;
    Ok(records)
}
