//! Fixed-length wire form of an [`Entry`]. Canonical: fields that an action
//! does not use must be zero, so one entry has exactly one encoding and one
//! hash.

use anyhow::{anyhow, Result};
use pq::{SYNC_SIG_LEN, SYNC_VK_LEN};
use syncwire::reader::Reader;
use syncwire::{decode_cert, encode_cert, CERT_WIRE_LEN};

use crate::entry::{Action, Entry};
use crate::role::Role;

/// First four bytes of an encoded entry.
pub const ENTRY_MAGIC: [u8; 4] = *b"ZPML";
/// Current entry wire version.
pub const ENTRY_WIRE_VERSION: u16 = 2;
/// Exact length of an encoded entry.
pub const ENTRY_WIRE_LEN: usize =
    4 + 2 + 16 + 8 + 32 + 8 + 1 + 1 + 64 + 32 + SYNC_VK_LEN + CERT_WIRE_LEN + SYNC_SIG_LEN;

fn malformed() -> anyhow::Error {
    anyhow!("member log rejected")
}

impl Entry {
    /// Encode this entry.
    ///
    /// # Errors
    ///
    /// The signature is not [`SYNC_SIG_LEN`] bytes, or the signer
    /// certificate does not encode.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.signature.len() != SYNC_SIG_LEN {
            return Err(malformed());
        }
        let mut out = Vec::with_capacity(ENTRY_WIRE_LEN);
        out.extend_from_slice(&ENTRY_MAGIC);
        out.extend_from_slice(&ENTRY_WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.prev_hash);
        out.extend_from_slice(&self.at_ms.to_be_bytes());
        out.push(self.action.code());
        out.push(self.action.role_code());
        out.extend_from_slice(self.action.client_id());
        out.extend_from_slice(&self.action.commit());
        match &self.action {
            Action::Add { root_vk, .. } => out.extend_from_slice(root_vk.as_slice()),
            Action::Remove { .. } | Action::SetRole { .. } | Action::Rotate { .. } => {
                out.extend_from_slice(&[0u8; SYNC_VK_LEN]);
            }
        }
        out.extend_from_slice(&encode_cert(&self.signer)?);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Decode an entry. Signatures are not verified here.
    ///
    /// # Errors
    ///
    /// `member log rejected` for a wrong length, magic, version, action or
    /// role, a non-canonical unused field, or a malformed certificate.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ENTRY_WIRE_LEN {
            return Err(malformed());
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != ENTRY_MAGIC || reader.u16()? != ENTRY_WIRE_VERSION {
            return Err(malformed());
        }
        let vault_id = reader.array()?;
        let seq = reader.u64()?;
        let prev_hash = reader.array()?;
        let at_ms = reader.u64()?;
        let code = reader.array::<1>()?[0];
        let role_code = reader.array::<1>()?[0];
        let client_id: [u8; 64] = reader.array()?;
        let commit: [u8; 32] = reader.array()?;
        let root_vk: [u8; SYNC_VK_LEN] = reader.array()?;
        let unused_vk_is_zero = root_vk.iter().all(|byte| *byte == 0);
        let no_commit = commit == [0u8; 32];
        let no_account = client_id == [0u8; 64];
        let action = match (code, role_code) {
            (1, role) if role != 0 && no_commit => Action::Add {
                client_id,
                root_vk: Box::new(root_vk),
                role: Role::try_from(role)?,
            },
            (2, 0) if unused_vk_is_zero => Action::Remove { client_id, commit },
            (4, 0) if unused_vk_is_zero && no_account && !no_commit => Action::Rotate { commit },
            (3, role) if role != 0 && unused_vk_is_zero && no_commit => Action::SetRole {
                client_id,
                role: Role::try_from(role)?,
            },
            _ => return Err(malformed()),
        };
        let signer = decode_cert(reader.take(CERT_WIRE_LEN)?)?;
        let signature = reader.take(SYNC_SIG_LEN)?.to_vec();
        reader.finish()?;
        Ok(Self {
            vault_id,
            seq,
            prev_hash,
            at_ms,
            action,
            signer,
            signature,
        })
    }
}
