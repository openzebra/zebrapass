//! The human password wrap record (kind `0x0005`).
//!
//! Layout: kid(8) salt(32) m(4) t(4) p(4) nonce(32) ct(32) tag(32). The
//! Argon2id parameters are part of the authenticated record; parsing
//! enforces the wire floor, so a malicious file cannot downgrade them.

use std::marker::PhantomData;

use crate::limits::{
    concat_array, read_array, read_u32, shift, wire_len, HUMAN_PASSWORD_PAYLOAD_LEN, KDF_M_KIB_MAX,
    KDF_M_KIB_MIN, KDF_P_MAX, KDF_P_MIN, KDF_T_MAX, KDF_T_MIN, KIND_PASSWORD_HUMAN,
};

const HPW_KID: usize = 0;
const HPW_SALT: usize = 8;
const HPW_M_KIB: usize = 40;
const HPW_T: usize = 44;
const HPW_P: usize = 48;
const HPW_NONCE: usize = 52;
const HPW_CT: usize = 84;
const HPW_TAG: usize = 116;

/// Argon2id cost profile of a human password wrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanKdf {
    /// Memory in KiB, `KDF_M_KIB_MIN..=KDF_M_KIB_MAX`.
    pub m_kib: u32,
    /// Passes, `KDF_T_MIN..=KDF_T_MAX`.
    pub t: u32,
    /// Lanes, `KDF_P_MIN..=KDF_P_MAX`.
    pub p: u32,
}

/// Human-chosen password wrap (kind `0x0005`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanPasswordWrap<'a> {
    /// Key id (key-rotation label), borrowed format field.
    pub kid: [u8; 8],
    /// Argon2id salt.
    pub salt: [u8; 32],
    /// Argon2id cost profile (floor enforced at parse time).
    pub kdf: HumanKdf,
    /// AEGIS-256 nonce.
    pub nonce: [u8; 32],
    /// Wrapped vault key ciphertext.
    pub ct: [u8; 32],
    /// AEGIS-256 tag.
    pub tag: [u8; 32],
    /// Marker for the zero-copy lifetime; `PhantomData` keeps the size at
    /// zero and `'a` documents that no field borrows the file.
    pub marker: PhantomData<&'a [u8]>,
}

/// Encode one human password record (`154` bytes).
#[must_use]
pub fn encode_human_password_entry(
    kid: [u8; 8],
    salt: [u8; 32],
    kdf: HumanKdf,
    nonce: [u8; 32],
    ct: [u8; 32],
    tag: [u8; 32],
) -> [u8; HUMAN_PASSWORD_PAYLOAD_LEN + crate::limits::ENTRY_HEADER_LEN] {
    let record_kind = KIND_PASSWORD_HUMAN.to_le_bytes();
    let entry_len = wire_len(HUMAN_PASSWORD_PAYLOAD_LEN);
    concat_array(&[
        &record_kind,
        &entry_len,
        &kid,
        &salt,
        &kdf.m_kib.to_le_bytes(),
        &kdf.t.to_le_bytes(),
        &kdf.p.to_le_bytes(),
        &nonce,
        &ct,
        &tag,
    ])
}

/// Parse the payload of a kind `0x0005` record. `entry_len` must name the
/// exact payload size, and the parameters must clear the wire floor.
///
/// # Errors
///
/// `corrupted length` on a wrong payload size or a truncated record;
/// `kdf parameters rejected` when any parameter is out of range.
pub fn parse_human_password(
    bytes: &[u8],
    payload: usize,
    entry_len: u32,
) -> anyhow::Result<(crate::WrapEntry<'_>, usize)> {
    if u32::try_from(HUMAN_PASSWORD_PAYLOAD_LEN) != Ok(entry_len) {
        return Err(anyhow::anyhow!("corrupted length"));
    }
    let end = shift(payload, HUMAN_PASSWORD_PAYLOAD_LEN)?;
    let raw = bytes
        .get(payload..end)
        .ok_or_else(|| anyhow::anyhow!("corrupted length"))?;
    let kdf = HumanKdf {
        m_kib: read_u32(raw, HPW_M_KIB)?,
        t: read_u32(raw, HPW_T)?,
        p: read_u32(raw, HPW_P)?,
    };
    // The floor is parse-enforced: a malicious file cannot hand out
    // parameters below the documented minimum.
    let in_range = (KDF_M_KIB_MIN..=KDF_M_KIB_MAX).contains(&kdf.m_kib)
        && (KDF_T_MIN..=KDF_T_MAX).contains(&kdf.t)
        && (KDF_P_MIN..=KDF_P_MAX).contains(&kdf.p);
    if !in_range {
        return Err(anyhow::anyhow!("kdf parameters rejected"));
    }
    Ok((
        crate::WrapEntry::HumanPassword(HumanPasswordWrap {
            kid: read_array(raw, HPW_KID)?,
            salt: read_array(raw, HPW_SALT)?,
            kdf,
            nonce: read_array(raw, HPW_NONCE)?,
            ct: read_array(raw, HPW_CT)?,
            tag: read_array(raw, HPW_TAG)?,
            marker: PhantomData,
        }),
        end,
    ))
}
