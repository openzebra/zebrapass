//! The addresses members can be reached at, learned from each other.
//!
//! Every device signs its own addresses. A device hands its own record and
//! the ones it knows to the members it talks to, and keeps a record it
//! receives only if the member log lists the signer's account, the signature
//! verifies and the record is newer than the one it holds. The invitation's
//! address is only where the search starts.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use memberlog::MemberLog;
use session::{DeviceCert, DeviceSignKey, PeerRecord, PEER_MAX_AGE_MS};
use syncwire::{decode_peers, encode_peers, RelayHint, MAX_PEERS};

use crate::dialable::{Dialing, Policy};
use crate::io::now_ms;

/// Records kept in all; the oldest are dropped first.
const MAX_KNOWN: usize = 256;

type Key = ([u8; 16], [u8; 16]);

/// What this device knows about where its fellow members are.
#[derive(Default)]
pub struct PeerBook {
    loopback: AtomicBool,
    own: Mutex<Vec<String>>,
    known: Mutex<HashMap<Key, PeerRecord>>,
}

impl PeerBook {
    /// Accept loopback addresses from other members: for tests and
    /// single-machine setups only.
    pub fn allow_loopback(&self) {
        self.loopback.store(true, Ordering::Relaxed);
    }

    /// The addresses this device can be reached at, from now on.
    pub fn set_own(&self, hints: Vec<String>) {
        if let Ok(mut own) = self.own.lock() {
            *own = hints;
        }
    }

    /// What this device may dial: loopback if allowed, and its own networks
    /// as the only private ones.
    #[must_use]
    pub fn dialing(&self) -> Dialing {
        Dialing {
            policy: Policy {
                loopback: self.loopback.load(Ordering::Relaxed),
            },
            trusted: self
                .own
                .lock()
                .map(|own| own.iter().filter_map(|hint| hint.parse().ok()).collect())
                .unwrap_or_default(),
        }
    }

    /// Own fresh record plus every record kept for `log`'s vault whose
    /// signer is still a member, ready to send.
    ///
    /// # Errors
    ///
    /// Signing and encoding errors.
    pub fn list(
        &self,
        log: &MemberLog,
        cert: &DeviceCert,
        sign: &DeviceSignKey,
    ) -> anyhow::Result<Vec<u8>> {
        let vault_id = *log.vault_id();
        let own = self.own.lock().map(|own| own.clone()).unwrap_or_default();
        let mut records = Vec::new();
        if !own.is_empty() {
            records.push(PeerRecord::sign(sign, cert, vault_id, own, now_ms())?);
        }
        if let Ok(known) = self.known.lock() {
            records.extend(
                known
                    .values()
                    .filter(|record| {
                        record.vault_id == vault_id
                            && log.role_of(&record.signer.client_id).is_some()
                    })
                    .take(MAX_PEERS.saturating_sub(records.len()))
                    .cloned(),
            );
        }
        encode_peers(&records)
    }

    /// Keep the valid, newer records in `bytes` that belong to `log`'s vault,
    /// are not this device's and name only addresses worth dialing (see
    /// [`Policy`]), trusting this device's own addresses and `anchors`.
    /// Returns how many were kept.
    pub fn accept(
        &self,
        log: &MemberLog,
        own_device: &[u8; 16],
        anchors: &[String],
        bytes: &[u8],
    ) -> usize {
        let Ok(records) = decode_peers(bytes) else {
            return 0;
        };
        let policy = Policy {
            loopback: self.loopback.load(Ordering::Relaxed),
        };
        let anchored: Vec<SocketAddr> = self
            .own
            .lock()
            .map(|own| own.clone())
            .unwrap_or_default()
            .iter()
            .chain(anchors)
            .filter_map(|hint| hint.parse().ok())
            .collect();
        let now = now_ms();
        let Ok(mut known) = self.known.lock() else {
            return 0;
        };
        let mut kept = 0;
        for record in records {
            let signer = &record.signer;
            let trusted = log
                .members()
                .iter()
                .find(|member| member.client_id == signer.client_id)
                .is_some_and(|member| record.verify(&member.root_vk, now).is_ok());
            let reachable = record.hints.iter().all(|hint| {
                hint.parse::<RelayHint>()
                    .ok()
                    .map(|relayed| relayed.relay)
                    .or_else(|| hint.parse::<SocketAddr>().ok())
                    .is_some_and(|address| policy.allows(&address, &anchored))
            });
            let key = (record.vault_id, signer.device_id);
            let newer = known
                .get(&key)
                .is_none_or(|held| held.issued_ms < record.issued_ms);
            let wanted = record.vault_id == *log.vault_id()
                && &signer.device_id != own_device
                && trusted
                && reachable
                && newer;
            if wanted {
                known.insert(key, record);
                kept += 1;
            }
        }
        while known.len() > MAX_KNOWN {
            let oldest = known
                .iter()
                .min_by_key(|(_, record)| record.issued_ms)
                .map(|(key, _)| *key);
            match oldest {
                Some(key) => known.remove(&key),
                None => break,
            };
        }
        kept
    }

    /// The records kept for `vault_id` that are still young enough to
    /// believe, newest first.
    #[must_use]
    pub fn records_of(&self, vault_id: &[u8; 16]) -> Vec<PeerRecord> {
        let floor = now_ms().saturating_sub(PEER_MAX_AGE_MS);
        let Ok(known) = self.known.lock() else {
            return Vec::new();
        };
        let mut records: Vec<PeerRecord> = known
            .values()
            .filter(|record| &record.vault_id == vault_id && record.issued_ms >= floor)
            .cloned()
            .collect();
        records.sort_by_key(|record| std::cmp::Reverse(record.issued_ms));
        records
    }

    /// Addresses of the other members' devices, newest record first.
    #[must_use]
    pub fn hints(&self, log: &MemberLog) -> Vec<String> {
        let Ok(known) = self.known.lock() else {
            return Vec::new();
        };
        let mut records: Vec<&PeerRecord> = known
            .values()
            .filter(|record| {
                record.vault_id == *log.vault_id()
                    && log.role_of(&record.signer.client_id).is_some()
            })
            .collect();
        records.sort_by_key(|record| std::cmp::Reverse(record.issued_ms));
        let mut hints: Vec<String> = Vec::new();
        for hint in records.iter().flat_map(|record| &record.hints) {
            if !hints.contains(hint) {
                hints.push(hint.clone());
            }
        }
        hints
    }
}
