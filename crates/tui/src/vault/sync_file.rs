//! Sync bundle file: signed record frames carried between devices by hand
//! until the server transport exists.
//!
//! Layout, big-endian, version 1:
//!
//! ```text
//! magic "ZPSX" ‖ version u16
//! cert:   client_id[64] ‖ device_vk[SYNC_VK_LEN] ‖ not_after u64 ‖ serial u64 ‖ sig_len u16 ‖ sig
//! count u32
//! record: origin[16] ‖ vault_id[16] ‖ record_id u32 ‖ revision u64 ‖ content_hash[32]
//!         ‖ msg_version u16 ‖ key_generation u32 ‖ frame_len u32 ‖ frame ‖ sig_len u16 ‖ sig
//! ```
//!
//! Every length and count is checked against `limits` before allocating;
//! trailing bytes are rejected. Nothing here is trusted: `accept_record`
//! verifies the certificate, the signature, and the frame AEAD.

use session::{DeviceCert, SyncRecord, SYNC_SIG_LEN, SYNC_VK_LEN};

use crate::vault::limits::{MAX_SYNC_FRAME, MAX_SYNC_RECORDS};

/// File magic.
pub const MAGIC: [u8; 4] = *b"ZPSX";
/// Current layout version.
pub const VERSION: u16 = 1;

const _: () = assert!(SYNC_SIG_LEN <= u16::MAX as usize);

/// A decoded bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncBundle {
    /// The root-issued certificate of the signing key.
    pub cert: DeviceCert,
    /// `(origin device claimed by the frame, record)`.
    pub records: Vec<([u8; 16], SyncRecord)>,
}

/// Encode `bundle`.
///
/// # Errors
///
/// `sync bundle too large` when a count or length does not fit its field or
/// passes the limits.
pub fn encode(bundle: &SyncBundle) -> anyhow::Result<Vec<u8>> {
    let too_large = || anyhow::anyhow!("sync bundle too large");
    let count = u32::try_from(bundle.records.len())
        .ok()
        .filter(|count| *count <= MAX_SYNC_RECORDS)
        .ok_or_else(too_large)?;
    let mut out = Vec::with_capacity(
        6 + 64
            + SYNC_VK_LEN
            + 18
            + bundle.cert.signature.len()
            + 4
            + bundle
                .records
                .iter()
                .map(|(_, record)| 90 + record.frame.len() + 2 + record.signature.len())
                .sum::<usize>(),
    );
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&bundle.cert.client_id);
    out.extend_from_slice(&bundle.cert.device_vk);
    out.extend_from_slice(&bundle.cert.not_after_ms.to_be_bytes());
    out.extend_from_slice(&bundle.cert.serial.to_be_bytes());
    put_sig(&mut out, &bundle.cert.signature)?;
    out.extend_from_slice(&count.to_be_bytes());
    for (origin, record) in &bundle.records {
        let frame_len = u32::try_from(record.frame.len())
            .ok()
            .filter(|len| *len <= MAX_SYNC_FRAME)
            .ok_or_else(too_large)?;
        out.extend_from_slice(origin);
        out.extend_from_slice(&record.vault_id);
        out.extend_from_slice(&record.record_id.to_be_bytes());
        out.extend_from_slice(&record.revision.to_be_bytes());
        out.extend_from_slice(&record.content_hash);
        out.extend_from_slice(&record.msg_version.to_be_bytes());
        out.extend_from_slice(&record.key_generation.to_be_bytes());
        out.extend_from_slice(&frame_len.to_be_bytes());
        out.extend_from_slice(&record.frame);
        put_sig(&mut out, &record.signature)?;
    }
    Ok(out)
}

fn put_sig(out: &mut Vec<u8>, signature: &[u8]) -> anyhow::Result<()> {
    let len = u16::try_from(signature.len())
        .ok()
        .filter(|len| usize::from(*len) <= SYNC_SIG_LEN)
        .ok_or_else(|| anyhow::anyhow!("sync bundle too large"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(signature);
    Ok(())
}

/// Decode a bundle.
///
/// # Errors
///
/// `not a sync bundle` for a wrong magic; `unsupported sync bundle version`;
/// `sync bundle corrupted` for truncation, trailing bytes, or any length
/// past the limits.
pub fn decode(bytes: &[u8]) -> anyhow::Result<SyncBundle> {
    let mut reader = Reader { bytes, pos: 0 };
    if reader.array::<4>()? != MAGIC {
        anyhow::bail!("not a sync bundle");
    }
    match reader.u16()? {
        VERSION => decode_v1(&mut reader),
        _ => anyhow::bail!("unsupported sync bundle version"),
    }
}

fn decode_v1(reader: &mut Reader<'_>) -> anyhow::Result<SyncBundle> {
    let cert = DeviceCert {
        client_id: reader.array()?,
        device_vk: reader.array()?,
        not_after_ms: reader.u64()?,
        serial: reader.u64()?,
        signature: reader.sig()?,
    };
    let count = reader.u32()?;
    if count > MAX_SYNC_RECORDS {
        return Err(corrupted());
    }
    let records = (0..count)
        .map(|_| {
            let origin = reader.array()?;
            let vault_id = reader.array()?;
            let record_id = reader.u32()?;
            let revision = reader.u64()?;
            let content_hash = reader.array()?;
            let msg_version = reader.u16()?;
            let key_generation = reader.u32()?;
            let frame_len = reader.u32()?;
            if frame_len > MAX_SYNC_FRAME {
                return Err(corrupted());
            }
            let frame = reader.take(usize::try_from(frame_len)?)?.to_vec();
            let signature = reader.sig()?;
            Ok((
                origin,
                SyncRecord {
                    vault_id,
                    record_id,
                    revision,
                    content_hash,
                    msg_version,
                    key_generation,
                    frame,
                    signature,
                },
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if reader.pos != reader.bytes.len() {
        return Err(corrupted());
    }
    Ok(SyncBundle { cert, records })
}

fn corrupted() -> anyhow::Error {
    anyhow::anyhow!("sync bundle corrupted")
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> anyhow::Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or_else(corrupted)?;
        let slice = self.bytes.get(self.pos..end).ok_or_else(corrupted)?;
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> anyhow::Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| corrupted())
    }

    fn u16(&mut self) -> anyhow::Result<u16> {
        self.array().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> anyhow::Result<u32> {
        self.array().map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> anyhow::Result<u64> {
        self.array().map(u64::from_be_bytes)
    }

    fn sig(&mut self) -> anyhow::Result<Vec<u8>> {
        let len = usize::from(self.u16()?);
        if len > SYNC_SIG_LEN {
            return Err(corrupted());
        }
        Ok(self.take(len)?.to_vec())
    }
}
