//! This device's sealed sync identity: the ML-DSA signing seed, the account
//! root verifying key, the certificates of known devices and the per-record
//! last-seen table.
//!
//! The account root seed is never stored. It exists only inside [`enroll`]
//! while the phrase is at hand, signs this device's certificate, and is
//! wiped. The file is one cascade frame under `kdf::sync_identity_key`; its
//! plaintext is the 32-byte signing seed, from revision 2 on the 32-byte
//! account gate secret, and the invitation keys, followed by a document, so
//! no secret passes through a non-zeroizing document buffer. Revision 1 files
//! (no gate secret) still load; such a device cannot serve its personal vault
//! to the account's other devices until it is enrolled again.

use std::path::Path;

use frame::{seal, FrameMeta, ALG_CASCADE, KIND_REVISION};
use record::{Document, ValueType, TAG_SYNC_OWN_CERT, TAG_SYNC_PEER_MIN, TAG_SYNC_ROOT_VK};
use secret::Secret;
use session::{
    issue_device_cert, issue_revocation, sync_verifying_key, DeviceCert, DeviceSignKey, Revocation,
    SYNC_SEED_LEN, SYNC_VK_LEN,
};
use syncwire::{decode_cert, encode_cert};

use crate::last_seen::LastSeen;
use crate::limits::PEERS_MAX;
use crate::revocations::Revocations;
use crate::share_keys::{ShareKeys, SharePublics, SHARE_KEYS_LEN};

/// Signing identity of this device for one vault.
#[derive(Debug)]
pub struct SyncIdentity {
    sign_seed: Secret<[u8; SYNC_SEED_LEN]>,
    account_gate: Option<Secret<[u8; GATE_LEN]>>,
    share: ShareKeys,
    root_vk: Box<[u8; SYNC_VK_LEN]>,
    devices: Vec<DeviceCert>,
    revocations: Revocations,
    last_seen: LastSeen,
}

/// The secret parts of an identity: signing seed, account gate, invitation keys.
type SecretParts = (
    Secret<[u8; SYNC_SEED_LEN]>,
    Option<Secret<[u8; GATE_LEN]>>,
    ShareKeys,
);

/// Length of the account gate secret.
const GATE_LEN: usize = 32;

/// Frame revision of a file that holds the account gate secret.
const REVISION_WITH_GATE: u64 = 2;

/// Frame revision of a file written before the gate secret existed.
const REVISION_LEGACY: u64 = 1;

fn corrupted() -> anyhow::Error {
    anyhow::anyhow!("corrupted length")
}

impl SyncIdentity {
    /// Create this device's identity from the master seed. The account root
    /// seed is derived, signs one certificate and is wiped before return.
    ///
    /// # Errors
    ///
    /// Key derivation, randomness or signing failure.
    pub fn enroll(
        master_seed: &[u8; 64],
        client_id: &[u8; 64],
        device_id: [u8; 16],
        not_after_ms: u64,
    ) -> anyhow::Result<Self> {
        let root_seed = kdf::sync_seed(master_seed)?;
        let root_vk = Box::new(
            <[u8; SYNC_VK_LEN]>::try_from(sync_verifying_key(root_seed.expose())?)
                .map_err(|_| corrupted())?,
        );
        let mut sign_seed = Secret::new([0u8; SYNC_SEED_LEN]);
        getrandom::fill(sign_seed.expose_mut())?;
        let device_vk = DeviceSignKey::from_seed(sign_seed.expose()).verifying_key()?;
        let mut serial = [0u8; 8];
        getrandom::fill(&mut serial)?;
        let cert = issue_device_cert(
            root_seed.expose(),
            client_id,
            &device_id,
            &device_vk,
            not_after_ms,
            u64::from_le_bytes(serial),
        )?;
        Self::from_parts(
            (
                sign_seed,
                Some(kdf::account_gate_secret(master_seed)?),
                ShareKeys::generate()?,
            ),
            root_vk,
            vec![cert],
            Revocations::default(),
            LastSeen::default(),
        )
    }

    fn from_parts(
        (sign_seed, account_gate, share): SecretParts,
        root_vk: Box<[u8; SYNC_VK_LEN]>,
        devices: Vec<DeviceCert>,
        revocations: Revocations,
        last_seen: LastSeen,
    ) -> anyhow::Result<Self> {
        let own = devices.first().ok_or_else(corrupted)?;
        let own_vk = DeviceSignKey::from_seed(sign_seed.expose()).verifying_key()?;
        if own.device_vk != own_vk || own.verify(&root_vk, 0).is_err() {
            anyhow::bail!("sync identity does not match its certificate");
        }
        Ok(Self {
            sign_seed,
            account_gate,
            share,
            root_vk,
            devices,
            revocations,
            last_seen,
        })
    }

    /// The secret every device of this account derives its personal vault's
    /// hello gate from. `None` for an identity written before it existed.
    #[must_use]
    pub const fn account_gate(&self) -> Option<&Secret<[u8; GATE_LEN]>> {
        self.account_gate.as_ref()
    }

    /// Give an identity written before the gate secret existed its gate
    /// secret, in place: the same signing key, certificates and invitation
    /// keys. Only the account's phrase can do it, and it is checked first:
    /// the root key derived from `master_seed` must be the one this identity
    /// chains to. Returns `false` when there was nothing to add.
    ///
    /// # Errors
    ///
    /// `sync identity rejected` for a phrase of another account; key
    /// derivation failure.
    pub fn upgrade(&mut self, master_seed: &[u8; 64]) -> anyhow::Result<bool> {
        let root_seed = kdf::sync_seed(master_seed)?;
        let root_vk = sync_verifying_key(root_seed.expose())?;
        if !secret::ct_eq(&root_vk, &*self.root_vk) {
            anyhow::bail!("sync identity rejected");
        }
        if self.account_gate.is_some() {
            return Ok(false);
        }
        self.account_gate = Some(kdf::account_gate_secret(master_seed)?);
        Ok(true)
    }

    /// The public halves of this device's invitation keys, for a contact
    /// card.
    ///
    /// # Errors
    ///
    /// The stored keys are not valid (a corrupted file).
    pub fn share_publics(&self) -> anyhow::Result<SharePublics> {
        self.share.publics()
    }

    /// This device's invitation keys, to open an invitation with.
    #[must_use]
    pub const fn share_keys(&self) -> &ShareKeys {
        &self.share
    }

    /// The signing key of this device.
    #[must_use]
    pub fn sign_key(&self) -> DeviceSignKey {
        DeviceSignKey::from_seed(self.sign_seed.expose())
    }

    /// The account root verifying key every certificate must chain to.
    #[must_use]
    pub const fn root_vk(&self) -> &[u8; SYNC_VK_LEN] {
        &self.root_vk
    }

    /// The certificate of every known device, this one first.
    #[must_use]
    pub fn devices(&self) -> &[DeviceCert] {
        &self.devices
    }

    /// This device's id, as certified.
    #[must_use]
    pub fn device_id(&self) -> Option<[u8; 16]> {
        self.devices.first().map(|cert| cert.device_id)
    }

    /// The signed revocations this vault has accepted.
    #[must_use]
    pub const fn revocations(&self) -> &Revocations {
        &self.revocations
    }

    /// Accept a revocation signed by a device of this account. Returns
    /// `true` when it was new.
    ///
    /// # Errors
    ///
    /// As [`Revocations::add`].
    pub fn add_revocation(&mut self, revocation: Revocation, now_ms: u64) -> anyhow::Result<bool> {
        let own = self.devices.first().ok_or_else(corrupted)?;
        if revocation.client_id != own.client_id {
            anyhow::bail!("revocation rejected");
        }
        self.revocations.add(revocation, &self.root_vk, now_ms)
    }

    /// Revoke `target` with this device's key and record it. The caller
    /// sends the returned revocation to the other devices and rotates the
    /// vault key.
    ///
    /// # Errors
    ///
    /// A target of another account, a signing failure, or a full list.
    pub fn revoke_device(
        &mut self,
        target: &DeviceCert,
        now_ms: u64,
    ) -> anyhow::Result<Revocation> {
        let own = self.devices.first().ok_or_else(corrupted)?;
        let revocation = issue_revocation(&self.sign_key(), own, target, now_ms)?;
        self.add_revocation(revocation.clone(), now_ms)?;
        Ok(revocation)
    }

    /// Per-record highest accepted revision.
    #[must_use]
    pub const fn last_seen(&self) -> &LastSeen {
        &self.last_seen
    }

    /// Mutable access to the last-seen table.
    pub const fn last_seen_mut(&mut self) -> &mut LastSeen {
        &mut self.last_seen
    }

    /// Learn a peer device. The certificate must chain to the root key, be
    /// unexpired and belong to this account. A known device id may be added
    /// again only with the same key.
    ///
    /// # Errors
    ///
    /// `device cert rejected`, `device cert expired`, a zero device id, a
    /// different key for a known id, an unknown account, or a full list.
    pub fn add_peer(&mut self, cert: DeviceCert, now_ms: u64) -> anyhow::Result<()> {
        cert.verify(&self.root_vk, now_ms)?;
        let own = self.devices.first().ok_or_else(corrupted)?;
        if cert.client_id != own.client_id
            || cert.device_id == [0u8; 16]
            || self.revocations.is_revoked(&cert)
        {
            anyhow::bail!("device cert rejected");
        }
        if let Some(known) = self
            .devices
            .iter()
            .find(|known| known.device_id == cert.device_id)
        {
            return if known.device_vk == cert.device_vk && known.serial == cert.serial {
                Ok(())
            } else {
                Err(anyhow::anyhow!("device cert rejected"))
            };
        }
        if self.devices.len() > PEERS_MAX {
            anyhow::bail!("device list full");
        }
        self.devices.push(cert);
        Ok(())
    }

    /// Seal and atomically write the identity to `path`.
    ///
    /// # Errors
    ///
    /// Encoding, sealing or write failure.
    pub fn save(&self, path: &Path, key: &Secret<[u8; 32]>) -> anyhow::Result<()> {
        let own_cert = self.devices.first().ok_or_else(corrupted)?;
        let mut doc = Document::new();
        doc.set_data(TAG_SYNC_ROOT_VK, ValueType::Bytes, &*self.root_vk);
        doc.set_data(TAG_SYNC_OWN_CERT, ValueType::Bytes, &encode_cert(own_cert)?);
        for (cert, tag) in self.devices.iter().skip(1).zip(TAG_SYNC_PEER_MIN..) {
            doc.set_data(tag, ValueType::Bytes, &encode_cert(cert)?);
        }
        self.revocations.write(&mut doc)?;
        self.last_seen.write(&mut doc);
        let document = doc.encode()?;
        // Exact capacity: growing the buffer would leave a copy of the seed
        // in freed memory.
        let mut payload = Secret::new(Vec::with_capacity(
            SYNC_SEED_LEN + GATE_LEN + SHARE_KEYS_LEN + document.len(),
        ));
        payload
            .expose_mut()
            .extend_from_slice(self.sign_seed.expose());
        if let Some(gate) = self.account_gate.as_ref() {
            payload.expose_mut().extend_from_slice(gate.expose());
        }
        self.share.append_to(payload.expose_mut());
        payload.expose_mut().extend_from_slice(&document);
        let meta = FrameMeta {
            kind: KIND_REVISION,
            record_id: 0,
            revision: if self.account_gate.is_some() {
                REVISION_WITH_GATE
            } else {
                REVISION_LEGACY
            },
            origin_device: own_cert.device_id,
            timestamp_ms: 0,
            alg: ALG_CASCADE,
        };
        crate::write_atomic(path, &seal(key, &meta, payload.expose())?)
    }

    /// Read and open the identity at `path`.
    ///
    /// # Errors
    ///
    /// `sync identity unreadable` when the file cannot be read, frame
    /// authentication failure, a malformed document, or a signing seed that
    /// does not match its certificate.
    pub fn load(path: &Path, key: &Secret<[u8; 32]>) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path).map_err(|_| anyhow::anyhow!("sync identity unreadable"))?;
        let plaintext = frame::open(key, &bytes)?;
        let revision = frame::parse(&bytes)?.revision;
        let (seed, rest) = plaintext
            .expose()
            .split_first_chunk::<SYNC_SEED_LEN>()
            .ok_or_else(corrupted)?;
        let mut sign_seed = Secret::new([0u8; SYNC_SEED_LEN]);
        sign_seed.expose_mut().copy_from_slice(seed);
        let (account_gate, rest) = match revision {
            REVISION_LEGACY => (None, rest),
            REVISION_WITH_GATE => {
                let (gate, rest) = rest.split_first_chunk::<GATE_LEN>().ok_or_else(corrupted)?;
                let mut secret = Secret::new([0u8; GATE_LEN]);
                secret.expose_mut().copy_from_slice(gate);
                (Some(secret), rest)
            }
            _ => return Err(corrupted()),
        };
        let (share, rest) = ShareKeys::split_from(rest)?;
        let doc = Document::parse(rest)?;
        let root_vk: Box<[u8; SYNC_VK_LEN]> = Box::new(
            doc.data(TAG_SYNC_ROOT_VK)?
                .and_then(|b| b.try_into().ok())
                .ok_or_else(corrupted)?,
        );
        let own_cert = decode_cert(doc.data(TAG_SYNC_OWN_CERT)?.ok_or_else(corrupted)?)?;
        let mut devices = vec![own_cert];
        for tag in (TAG_SYNC_PEER_MIN..).take(PEERS_MAX) {
            let Some(bytes) = doc.data(tag)? else {
                break;
            };
            devices.push(decode_cert(bytes)?);
        }
        let stray = (TAG_SYNC_PEER_MIN..)
            .take(PEERS_MAX)
            .skip(devices.len() - 1)
            .any(|tag| doc.get(tag).is_some());
        if stray {
            return Err(corrupted());
        }
        Self::from_parts(
            (sign_seed, account_gate, share),
            root_vk,
            devices,
            Revocations::read(&doc)?,
            LastSeen::read(&doc)?,
        )
    }
}

/// Bring the identity file at `path` up to the current revision with the
/// account's phrase, keeping everything else in it. Returns whether the file
/// changed.
///
/// # Errors
///
/// The file cannot be read or opened, the phrase is not the account's, or the
/// new file cannot be written.
pub fn upgrade_sync_identity(
    path: &Path,
    key: &Secret<[u8; 32]>,
    master_seed: &[u8; 64],
) -> anyhow::Result<bool> {
    let mut identity = SyncIdentity::load(path, key)?;
    let changed = identity.upgrade(master_seed)?;
    if changed {
        identity.save(path, key)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use super::SyncIdentity;

    fn key() -> secret::Secret<[u8; 32]> {
        secret::Secret::new([5; 32])
    }

    #[test]
    fn the_gate_secret_is_kept_and_follows_the_seed() {
        let dir = std::env::temp_dir().join(format!("zp-sid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sync.id");
        let identity = SyncIdentity::enroll(&[7; 64], &[1; 64], [2; 16], u64::MAX).unwrap();
        identity.save(&path, &key()).unwrap();
        let loaded = SyncIdentity::load(&path, &key()).unwrap();
        let expected = kdf::account_gate_secret(&[7; 64]).unwrap();
        assert_eq!(loaded.account_gate().unwrap().expose(), expected.expose());
        let other = SyncIdentity::enroll(&[8; 64], &[1; 64], [2; 16], u64::MAX).unwrap();
        assert_ne!(
            other.account_gate().unwrap().expose(),
            expected.expose(),
            "another phrase has another gate"
        );
    }

    #[test]
    fn upgrading_adds_the_gate_only_for_the_accounts_own_phrase() {
        let mut identity = SyncIdentity::enroll(&[7; 64], &[1; 64], [2; 16], u64::MAX).unwrap();
        identity.account_gate = None;
        let before = identity.devices().to_vec();
        let vk = identity.sign_key().verifying_key().unwrap();
        assert!(identity.upgrade(&[8; 64]).is_err(), "another phrase");
        assert!(identity.account_gate().is_none());
        assert!(identity.upgrade(&[7; 64]).unwrap());
        let expected = kdf::account_gate_secret(&[7; 64]).unwrap();
        assert_eq!(identity.account_gate().unwrap().expose(), expected.expose());
        assert_eq!(identity.devices(), before.as_slice());
        assert_eq!(identity.sign_key().verifying_key().unwrap(), vk);
        assert!(!identity.upgrade(&[7; 64]).unwrap(), "nothing left to add");
        assert!(identity.upgrade(&[8; 64]).is_err(), "still checked");
    }

    #[test]
    fn an_identity_written_before_the_gate_existed_still_loads_without_one() {
        let dir = std::env::temp_dir().join(format!("zp-sid-legacy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sync.id");
        let mut identity = SyncIdentity::enroll(&[7; 64], &[1; 64], [2; 16], u64::MAX).unwrap();
        identity.account_gate = None;
        identity.save(&path, &key()).unwrap();
        let loaded = SyncIdentity::load(&path, &key()).unwrap();
        assert!(loaded.account_gate().is_none());
        assert_eq!(loaded.devices().len(), 1);
    }
}
