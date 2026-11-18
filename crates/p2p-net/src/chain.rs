//! Three-stage fallback chain candidate ordering:
//!
//! 1. [`Stage::Lan`](crate::Stage::Lan): direct LAN peers discovered via
//!    authenticated beacons.
//! 2. [`Stage::WanDirect`](crate::Stage::WanDirect): direct public WAN or NAT-mapped
//!    socket addresses.
//! 3. [`Stage::ZpryRelay`](crate::Stage::ZpryRelay): user-configured private or
//!    self-hosted `ZPRY` TCP relays.

use std::net::SocketAddr;

use sha2::{Digest, Sha256};

use crate::RelayHint;

const DOMAIN_RELAY_SLOT: &[u8] = b"brby/v2/zpry-relay-slot";

/// Derive a deterministic 16-byte relay slot identifier on `relay`.
///
/// Uses `secret` (`account_gate` or `shared_seed`) and `context_id` (`route_id`
/// or `vault_id`), so peers find each other on a configured `ZPRY` relay
/// without prior rendezvous hints.
#[must_use]
pub fn deterministic_relay_hint(
    secret: &[u8],
    context_id: &[u8],
    relay: SocketAddr,
) -> Option<RelayHint> {
    if secret.is_empty() || context_id.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_RELAY_SLOT);
    hasher.update(
        u16::try_from(secret.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    hasher.update(secret);
    hasher.update(
        u16::try_from(context_id.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    hasher.update(context_id);
    let addr_text = relay.to_string();
    hasher.update(
        u16::try_from(addr_text.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    hasher.update(addr_text.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut slot = [0u8; 16];
    if let Some((head, _)) = digest.split_at_checked(16) {
        slot.copy_from_slice(head);
    }
    Some(RelayHint { relay, slot })
}

/// Collect ordered deduplicated connection candidates across discovered LAN
/// addresses, explicit peer hints, and configured `ZPRY` relays.
#[must_use]
pub fn expand_chain_hints(
    explicit: &[String],
    discovered: &[String],
    relays: &[String],
    secret: &[u8],
    context_id: &[u8],
) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_unique = |candidate: String| {
        if !candidate.trim().is_empty() && !out.contains(&candidate) {
            out.push(candidate);
        }
    };
    for addr in discovered {
        push_unique(addr.clone());
    }
    for addr in explicit {
        push_unique(addr.clone());
    }
    for relay_text in relays {
        push_unique(relay_text.clone());
        if let Ok(parsed) = relay_text.parse::<RelayHint>()
            && let Some(det) = deterministic_relay_hint(secret, context_id, parsed.relay)
        {
            push_unique(det.to_string());
        } else if let Ok(addr) = relay_text.parse::<SocketAddr>()
            && let Some(det) = deterministic_relay_hint(secret, context_id, addr)
        {
            push_unique(det.to_string());
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests may unwrap")]
mod tests {
    use super::{deterministic_relay_hint, expand_chain_hints};

    #[test]
    fn deterministic_relay_hint_is_stable_for_both_peers() {
        let relay = "198.51.100.10:7447".parse().unwrap();
        let a = deterministic_relay_hint(&[0x11; 32], &[0x22; 16], relay).unwrap();
        let b = deterministic_relay_hint(&[0x11; 32], &[0x22; 16], relay).unwrap();
        let c = deterministic_relay_hint(&[0x11; 32], &[0x33; 16], relay).unwrap();
        assert_eq!(a, b);
        assert_ne!(a.slot, c.slot);
    }

    #[test]
    fn expand_chain_hints_preserves_three_stages() {
        let out = expand_chain_hints(
            &["93.184.216.34:7447".to_owned()],
            &["192.168.1.10:7447".to_owned()],
            &["198.51.100.10:7447".to_owned()],
            &[0x55; 32],
            &[0x66; 16],
        );
        assert_eq!(out.first().map(String::as_str), Some("192.168.1.10:7447"));
        assert_eq!(out.get(1).map(String::as_str), Some("93.184.216.34:7447"));
        assert!(out.len() >= 3);
    }
}
