//! Being reachable through a relay: hold a slot, answer when someone asks for
//! it, and serve what arrives like any direct connection.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use p2p_core::CookieSecret;
use syncwire::{decode_incoming, RelayHint, RelaySide, RelayType};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

use crate::relay_client::{accept, reserve};
use crate::relay_wire::{receive, send};
use crate::service::{connection, Event, Service, Shared, MAX_HANDSHAKES, MAX_RELAYED};
use crate::view::Provider;

/// Longest wait between attempts to hold a slot again.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

enum Control {
    Offered([u8; 16]),
    Closed,
}

impl Service {
    /// Hold a slot on `relay` for as long as the node runs, and serve the
    /// connections that arrive through it. Each time a slot is held the node
    /// reports [`Event::Relayed`] with the address to publish; when the relay
    /// is lost it holds a new slot, after a growing and jittered wait.
    /// Returns `false` for a node that has no runtime.
    pub fn hold_relay<P: Provider>(&self, provider: Arc<P>, relay: SocketAddr) -> bool {
        self.hold_relay_slot(provider, relay, None)
    }

    /// Hold a specific `fixed_slot` (or a fresh random slot when `None`) on
    /// `relay` across reconnects so peers with a saved or deterministic
    /// [`RelayHint`] can always reach this node.
    pub fn hold_relay_slot<P: Provider>(
        &self,
        provider: Arc<P>,
        relay: SocketAddr,
        fixed_slot: Option<[u8; 16]>,
    ) -> bool {
        let (Some(runtime), Ok(cookies)) = (self.runtime.as_ref(), CookieSecret::generate()) else {
            return false;
        };
        runtime.spawn(hold(
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

async fn hold<P: Provider>(
    relay: SocketAddr,
    fixed_slot: Option<[u8; 16]>,
    provider: Arc<P>,
    cookies: Arc<CookieSecret>,
    shared: Arc<Shared>,
    events: Sender<Event>,
) {
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
        if let Ok((stream, granted)) = reserve(relay, slot).await {
            backoff = Duration::from_secs(1);
            let hint = RelayHint { relay, slot };
            publish(&shared, relay, Some(hint));
            if events.send(Event::Relayed(hint)).is_err() {
                return;
            }
            let wait = Duration::from_secs(u64::from(granted.ttl_s / 3).max(1));
            keep(
                relay,
                stream,
                wait,
                &Served {
                    key: IpAddr::V6(Ipv6Addr::from(slot)),
                    provider: &provider,
                    cookies: &cookies,
                    shared: &shared,
                    events: &events,
                },
            )
            .await;
        }
        publish(&shared, relay, None);
        let jitter = p2p_core::relay_random().map_or(0, |bytes| {
            let [first, ..] = bytes;
            u64::from(first) * 4
        });
        sleep(backoff + Duration::from_millis(jitter)).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Record the slot this node holds on `relay`, or that it holds none: what a
/// beacon announces.
fn publish(shared: &Shared, relay: SocketAddr, hint: Option<RelayHint>) {
    if let Ok(mut held) = shared.relay_hints.lock() {
        held.retain(|known| known.relay != relay);
        held.extend(hint);
    }
}

struct Served<'a, P> {
    key: IpAddr,
    provider: &'a Arc<P>,
    cookies: &'a Arc<CookieSecret>,
    shared: &'a Arc<Shared>,
    events: &'a Sender<Event>,
}

/// The control connection: keepalives out, offers in, until it is lost.
async fn keep<P: Provider>(
    relay: SocketAddr,
    stream: TcpStream,
    every: Duration,
    served: &Served<'_, P>,
) {
    let (mut read, mut write) = tokio::io::split(stream);
    let (offers, mut inbox) = mpsc::channel::<Control>(8);
    let reader = tokio::spawn(async move {
        while let Ok((ty, payload)) = receive(&mut read, RelaySide::Relay, every * 4).await {
            let offered = match ty {
                RelayType::Incoming => decode_incoming(&payload).ok().map(Control::Offered),
                RelayType::Pong => continue,
                _ => None,
            };
            let Some(offer) = offered else {
                break;
            };
            if offers.send(offer).await.is_err() {
                return;
            }
        }
        let _ = offers.send(Control::Closed).await;
    });
    let mut token = 0u64;
    loop {
        match timeout(every, inbox.recv()).await {
            Ok(Some(Control::Offered(conn_id))) => {
                let (provider, cookies, shared, events) = (
                    Arc::clone(served.provider),
                    Arc::clone(served.cookies),
                    Arc::clone(served.shared),
                    served.events.clone(),
                );
                let key = served.key;
                tokio::spawn(async move {
                    if let Ok(tcp) = accept(relay, conn_id).await {
                        spawn_relayed(tcp, key, provider, cookies, shared, events);
                    }
                });
            }
            Ok(Some(Control::Closed) | None) => break,
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

/// Serve a connection that arrived through a relay, under a pool of its own:
/// the relay's address says nothing of who is on the other end, so the
/// streams of one slot are counted together and all of them are few.
fn spawn_relayed<P: Provider>(
    tcp: TcpStream,
    key: std::net::IpAddr,
    provider: Arc<P>,
    cookies: Arc<CookieSecret>,
    shared: Arc<Shared>,
    events: Sender<Event>,
) {
    if shared.handshakes.load(Ordering::Relaxed) >= MAX_HANDSHAKES
        || shared.relayed.load(Ordering::Relaxed) >= MAX_RELAYED
    {
        return;
    }
    let Some(slot) = shared.tickets.begin(key) else {
        return;
    };
    shared.handshakes.fetch_add(1, Ordering::Relaxed);
    shared.relayed.fetch_add(1, Ordering::Relaxed);
    tokio::spawn(async move {
        connection(tcp, slot, provider, cookies, Arc::clone(&shared), events).await;
        shared.relayed.fetch_sub(1, Ordering::Relaxed);
    });
}
