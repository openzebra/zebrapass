//! Multi-stage transport fallback chain builder and WebSocket relay holding.
//!
//! Expands peer candidates across four ordered transport stages:
//! 1. [`Stage::Lan`](crate::Stage::Lan): direct LAN peers discovered via
//!    multicast, broadcast, or `/24` unicast sweep.
//! 2. [`Stage::WanDirect`](crate::Stage::WanDirect): direct public WAN, NAT-PMP
//!    / `UPnP` / STUN, or VPN/CGNAT (`100.64/10`) endpoints.
//! 3. [`Stage::ZpryRelay`](crate::Stage::ZpryRelay): user-saved or
//!    peer-advertised `ZPRY` TCP relay slots and deterministic slots derived
//!    from the vault secret.
//! 4. [`Stage::CatalogRelay`](crate::Stage::CatalogRelay): WebSocket (`ws://`)
//!    relay tunnels on saved relays and deterministic slots across the embedded
//!    `nostr_relays.toml` catalog.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use p2p_core::CookieSecret;
use syncwire::{decode_incoming, RelayHint, RelaySide, RelayType};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

use crate::relay_client::{accept_ws, reserve, reserve_ws};
use crate::relay_dir::{default_relays, deterministic_relay_hint, embedded_relays};
use crate::relay_hold::spawn_relayed;
use crate::relay_wire::{receive, send};
use crate::service::{Event, Service, Shared};
use crate::view::Provider;

/// Longest wait between attempts to re-hold a WebSocket relay slot.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

fn slot_to_hex(slot: &[u8; 16]) -> String {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for &b in slot {
        let hi = HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
        let lo = HEX.get(usize::from(b & 0x0F)).copied().unwrap_or(b'0');
        out.push(char::from(hi));
        out.push(char::from(lo));
    }
    out
}

/// Derive a deterministic `ws://endpoint/slot` hint from a 32-byte key or gate
/// secret and a 16-byte vault/route identifier.
#[must_use]
pub fn deterministic_ws_relay_hint(
    secret: &[u8],
    context_id: &[u8; 16],
    endpoint: &str,
) -> Option<String> {
    let clean = endpoint.strip_prefix("ws://").unwrap_or(endpoint);
    let host_port = clean.split('/').next().unwrap_or(clean);
    if host_port.is_empty() {
        return None;
    }
    let slot = kdf::p2p_relay_slot(secret, context_id, host_port).ok()?;
    Some(format!("ws://{host_port}/{}", slot_to_hex(&slot)))
}

/// Derive up to `count` deterministic `ws://host:port/slot` hints from the
/// embedded relay catalog starting at `offset`.
#[must_use]
pub fn catalog_relay_hints(
    secret: &[u8],
    context_id: &[u8; 16],
    offset: usize,
    count: usize,
) -> Vec<String> {
    if count == 0 {
        return Vec::new();
    }
    let entries = if offset == 0 {
        default_relays(count)
    } else {
        let all = embedded_relays();
        if all.is_empty() {
            return Vec::new();
        }
        (0..count.min(all.len()))
            .filter_map(|i| all.get((offset + i) % all.len()))
            .collect()
    };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        if let Some(hint) = deterministic_ws_relay_hint(secret, context_id, &entry.url) {
            if !out.contains(&hint) {
                out.push(hint);
            }
        }
    }
    out
}

/// Expand explicit addresses, discovered LAN peers, and saved relays into a
/// deduplicated candidate list covering all four fallback stages for a vault or
/// account route.
#[must_use]
pub fn expand_chain_hints(
    explicit: &[String],
    discovered: &[String],
    relays: &[String],
    secret: &[u8],
    context_id: &[u8; 16],
    catalog_count: usize,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push_unique = |candidate: String| {
        if !out.contains(&candidate) {
            out.push(candidate);
        }
    };

    for addr in discovered.iter().chain(explicit.iter()) {
        push_unique(addr.clone());
    }

    for relay_text in relays {
        push_unique(relay_text.clone());
        if let Ok(parsed) = relay_text.parse::<RelayHint>() {
            if let Some(det) = deterministic_relay_hint(secret, context_id, parsed.relay) {
                push_unique(det.to_string());
            }
            if let Some(ws_det) =
                deterministic_ws_relay_hint(secret, context_id, &parsed.relay.to_string())
            {
                push_unique(ws_det);
            }
        } else if let Some(ws_det) = deterministic_ws_relay_hint(secret, context_id, relay_text) {
            push_unique(ws_det);
        }
    }

    for cat in catalog_relay_hints(secret, context_id, 0, catalog_count) {
        push_unique(cat);
    }

    out
}

impl Service {
    /// Hold a deterministic or random slot on `relay` using WebSocket upgrade
    /// framing (`ws://`), falling back to raw `ZPRY` TCP if needed.
    pub fn hold_relay_ws<P: Provider>(
        &self,
        provider: Arc<P>,
        relay: SocketAddr,
        fixed_slot: Option<[u8; 16]>,
    ) -> bool {
        let (Some(runtime), Ok(cookies)) = (self.runtime.as_ref(), CookieSecret::generate()) else {
            return false;
        };
        runtime.spawn(hold_ws_loop(
            relay,
            fixed_slot,
            provider,
            Arc::new(cookies),
            Arc::clone(&self.shared),
            self.sender.clone(),
        ));
        true
    }
}

async fn hold_ws_loop<P: Provider>(
    relay: SocketAddr,
    fixed_slot: Option<[u8; 16]>,
    provider: Arc<P>,
    cookies: Arc<CookieSecret>,
    shared: Arc<Shared>,
    events: Sender<Event>,
) {
    let host = relay.ip().to_string();
    let mut backoff = Duration::from_secs(1);
    loop {
        let slot = if let Some(chosen) = fixed_slot {
            chosen
        } else {
            let Ok(random) = p2p_core::relay_random() else {
                return;
            };
            random
        };
        let reserved = match reserve_ws(relay, &host, slot).await {
            Ok(pair) => Ok(pair),
            Err(_) => reserve(relay, slot).await,
        };
        if let Ok((stream, granted)) = reserved {
            backoff = Duration::from_secs(1);
            let hint = RelayHint { relay, slot };
            if events.send(Event::Relayed(hint)).is_err() {
                return;
            }
            let wait = Duration::from_secs(u64::from(granted.ttl_s / 3).max(1));
            keep_ws(
                relay,
                stream,
                wait,
                IpAddr::V6(Ipv6Addr::from(slot)),
                &provider,
                &cookies,
                &shared,
                &events,
            )
            .await;
        }
        let jitter = p2p_core::relay_random().map_or(0, |bytes| {
            let [first, ..] = bytes;
            u64::from(first) * 4
        });
        sleep(backoff + Duration::from_millis(jitter)).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "internal relay control loop passes shared service handles"
)]
async fn keep_ws<P: Provider>(
    relay: SocketAddr,
    stream: TcpStream,
    every: Duration,
    key: IpAddr,
    provider: &Arc<P>,
    cookies: &Arc<CookieSecret>,
    shared: &Arc<Shared>,
    events: &Sender<Event>,
) {
    let (mut read, mut write) = tokio::io::split(stream);
    let (offers, mut inbox) = mpsc::channel::<Option<[u8; 16]>>(8);
    let reader = tokio::spawn(async move {
        while let Ok((ty, payload)) = receive(&mut read, RelaySide::Relay, every * 4).await {
            match ty {
                RelayType::Incoming => {
                    let Ok(conn_id) = decode_incoming(&payload) else {
                        break;
                    };
                    if offers.send(Some(conn_id)).await.is_err() {
                        return;
                    }
                }
                RelayType::Pong => {}
                _ => break,
            }
        }
        let _ = offers.send(None).await;
    });
    let mut token = 0u64;
    let host = relay.ip().to_string();
    loop {
        match timeout(every, inbox.recv()).await {
            Ok(Some(Some(conn_id))) => {
                let (provider, cookies, shared, events, host) = (
                    Arc::clone(provider),
                    Arc::clone(cookies),
                    Arc::clone(shared),
                    events.clone(),
                    host.clone(),
                );
                tokio::spawn(async move {
                    if let Ok(tcp) = accept_ws(relay, &host, conn_id).await {
                        spawn_relayed(tcp, key, provider, cookies, shared, events);
                    }
                });
            }
            Ok(Some(None) | None) => break,
            Err(_) => {
                token = token.wrapping_add(1);
                let ping = token.to_be_bytes();
                if send(&mut write, RelaySide::Client, RelayType::Ping, &ping)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    reader.abort();
}
