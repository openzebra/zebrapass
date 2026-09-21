//! Grant a device needs to rebuild wrap associated data.

use container::StaticHeader;

/// Owned grant. It is not a vault file and it does not include the commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceGrant {
    bytes: Vec<u8>,
}

impl DeviceGrant {
    /// Borrow the grant encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument is one grant field, in wire order"
)]
pub fn assemble(
    header: &StaticHeader,
    device_id: &[u8; 16],
    kem_alg: u16,
    dev_x_pk: &[u8; 32],
    eph_x_pk: &[u8; 32],
    sntrup_ct: &[u8],
    nonce: &[u8; 32],
    ct: &[u8; 32],
    tag: &[u8; 32],
) -> DeviceGrant {
    let header_bytes = header.to_bytes();
    let kem_le = kem_alg.to_le_bytes();
    let mut bytes = Vec::with_capacity(
        header_bytes.len()
            + device_id.len()
            + kem_le.len()
            + dev_x_pk.len()
            + eph_x_pk.len()
            + sntrup_ct.len()
            + nonce.len()
            + ct.len()
            + tag.len(),
    );
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(device_id);
    bytes.extend_from_slice(&kem_le);
    bytes.extend_from_slice(dev_x_pk);
    bytes.extend_from_slice(eph_x_pk);
    bytes.extend_from_slice(sntrup_ct);
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(ct);
    bytes.extend_from_slice(tag);
    DeviceGrant { bytes }
}
