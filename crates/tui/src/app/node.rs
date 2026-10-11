//! The node itself: the service, what it serves, and where it tells members
//! to reach it.

pub mod log;

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use local::{Listen, Offer, SyncIdentity};
use p2p_net::{
    reachable_hints, BeaconConfig, BeaconIdentity, Event, FetchError, Service, SharedProvider,
};
use session::MAX_HINTS;

/// The port a node tries first, so an invitation stays valid across runs.
const PORT: u16 = 7447;

/// How long an open shared vault goes without trading revisions.
/// Announced addresses kept.
const MAX_DISCOVERED: usize = 8;

/// How often a node checks in with its peers: the only periodic work it has.
/// A fetch-only device sets no other timer, so between check-ins it is idle.
pub const CHECK_EVERY: Duration = Duration::from_secs(15);

const _: () = assert!(CHECK_EVERY.as_secs() >= 15, "no sub-15-second polling");

/// How the latest check-in ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckOutcome {
    /// Revisions were traded.
    Synced,
    /// The members refused what this device sent, or sent what it refused.
    RefusedChanges,
    /// The members turned this device away.
    TurnedAway,
    /// No member could be reached.
    Unreachable,
    /// A member answered improperly.
    Failed,
}

/// The latest check-in with the peers.
#[derive(Clone, Copy, Debug)]
pub struct CheckIn {
    /// When it ended.
    pub at: Instant,
    /// How it ended.
    pub outcome: CheckOutcome,
}

/// The running node and what it signs with. Dropping it stops the node and
/// wipes the identity copy it holds.
pub struct P2p {
    /// The network service.
    pub service: Service,
    /// What the node serves.
    pub provider: Arc<SharedProvider>,
    /// This device's identity.
    pub identity: Arc<SyncIdentity>,
    /// Where it was told to listen.
    pub listen: Listen,
    /// The address it tells members to use, when it sits behind a port
    /// forward.
    pub advertise: Option<Box<str>>,
    /// The addresses other devices can reach it at, best first, as found when
    /// it started.
    pub reachable: Box<[String]>,
    /// What the last member to answer said it sees this device at.
    pub observed: Option<Offer>,
    /// Addresses other devices of the account announced on the network.
    pub discovered: Vec<String>,
    /// Relay slots the person saved, as `ip:port/slot`.
    pub relays: Vec<String>,
    /// The node holds a slot on the first saved relay.
    pub holds: bool,
    /// The latest relay slot this node holds, when it holds one.
    pub relayed: Option<p2p_net::RelayHint>,
    /// How the latest check-in ended; `None` before the first.
    pub last_checkin: Option<CheckIn>,
    /// What the node reported this session.
    pub log: crate::app::node::log::EventLog,
    checked: Instant,
}

impl std::fmt::Debug for P2p {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2p")
            .field("status", &self.service.status())
            .finish_non_exhaustive()
    }
}

impl P2p {
    /// Start a node for `identity` over the shared vaults under `base`.
    ///
    /// `Listen::Off` and `Listen::Fetch` bind nothing: the node only dials
    /// out. They differ in whether anything asks for a node (see
    /// [`crate::app::personal::wants_node`]), not in what the node does once
    /// it runs.
    #[must_use]
    pub fn start(
        base: &Path,
        identity: Arc<SyncIdentity>,
        listen: Listen,
        advertise: Option<Box<str>>,
        beacon: Option<BeaconConfig>,
    ) -> Option<Box<Self>> {
        let provider = Arc::new(SharedProvider::new(
            base.to_path_buf(),
            Arc::clone(&identity),
        ));
        if matches!(listen, Listen::Local | Listen::Fetch) {
            provider.allow_loopback_peers();
        }
        let bind = |port: u16| match listen {
            Listen::Off | Listen::Fetch => None,
            Listen::Local => Some(format!("127.0.0.1:{port}")),
            Listen::Lan | Listen::Beacon => Some(format!("0.0.0.0:{port}")),
        };
        let service = Service::start(bind(PORT).as_deref(), Arc::clone(&provider))
            .or_else(|_| Service::start(bind(0).as_deref(), Arc::clone(&provider)))
            .ok()?;
        let mut node = Box::new(Self {
            service,
            provider,
            identity,
            listen,
            advertise,
            reachable: Box::default(),
            observed: None,
            discovered: Vec::new(),
            relays: Vec::new(),
            holds: false,
            relayed: None,
            last_checkin: None,
            log: crate::app::node::log::EventLog::default(),
            checked: Instant::now(),
        });
        let hints = node.hints();
        node.provider.set_hints(hints.clone());
        node.reachable = hints.into_boxed_slice();
        if matches!(listen, Listen::Beacon) {
            node.start_beacon(beacon.unwrap_or_else(BeaconConfig::lan));
        }
        Some(node)
    }

    /// Announce this node on the local network, to the account's other
    /// devices only. A device without the account gate, or a network that
    /// will not carry multicast, simply has no beacon.
    fn start_beacon(&self, config: BeaconConfig) {
        let (Some(gate), Some(device)) = (self.identity.account_gate(), self.identity.device_id())
        else {
            return;
        };
        if let Ok(identity) = BeaconIdentity::new(gate, device) {
            let _ = self
                .service
                .start_beacon(Arc::clone(&self.provider), identity, config);
        }
    }

    /// Hold a slot on the first saved relay, when the person asked for it.
    /// Dropping the node frees the slot.
    pub fn hold_saved(&self) {
        let relay = self
            .relays
            .first()
            .and_then(|text| text.parse::<p2p_net::RelayHint>().ok())
            .map(|hint| hint.relay);
        if let (true, false, Some(relay)) = (self.holds, self.listen == Listen::Fetch, relay) {
            self.service.hold_relay(Arc::clone(&self.provider), relay);
        }
    }

    /// Note the relay slot this node now holds, and offer it to members with
    /// the node's other addresses.
    pub fn note_relayed(&mut self, hint: p2p_net::RelayHint) {
        self.relayed = Some(hint);
        let mut own = self.hints();
        own.truncate(MAX_HINTS - 1);
        own.push(hint.to_string());
        self.provider.set_hints(own);
    }

    /// Record the outcome a node event reports, when it reports one.
    pub fn note_event(&mut self, event: &Event) {
        self.log.note(event);
        let outcome = match event {
            Event::Synced { refused: 0, .. } | Event::PersonalPulled { .. } => CheckOutcome::Synced,
            Event::Synced { .. } => CheckOutcome::RefusedChanges,
            Event::FetchFailed { reason, .. } => match reason {
                FetchError::Unreachable => CheckOutcome::Unreachable,
                FetchError::Refused => CheckOutcome::TurnedAway,
                FetchError::Failed => CheckOutcome::Failed,
            },
            _ => return,
        };
        self.last_checkin = Some(CheckIn {
            at: Instant::now(),
            outcome,
        });
    }

    /// Remember an address another device announced; the newest few stay.
    pub fn discover(&mut self, address: std::net::SocketAddr) {
        self.remember(address.to_string());
    }

    /// Remember a relay slot another device announced, if it passes the same
    /// rules a pasted one does.
    pub fn discover_relay(&mut self, hint: &p2p_net::RelayHint) {
        let text = hint.to_string();
        if local::parse_relay_hint(&text).is_ok() {
            self.remember(text);
        }
    }

    fn remember(&mut self, address: String) {
        self.discovered.retain(|known| known != &address);
        self.discovered.push(address);
        if self.discovered.len() > MAX_DISCOVERED {
            self.discovered.remove(0);
        }
    }

    /// Serve `vault`, the personal vault, to the other devices of this
    /// account. Call again whenever the vault key may have changed. Returns
    /// `false` for an identity that cannot be reached by them.
    pub fn serve_personal(&self, vault: &crate::vault::Vault) -> bool {
        self.provider
            .serve_personal(vault.paths.vault_file.clone(), vault.session.reopen_key())
    }

    /// Whether it is time to check in with the members again; restarts the
    /// wait when it is.
    pub fn check_due(&mut self) -> bool {
        let due = self.checked.elapsed() >= CHECK_EVERY && self.service.status().fetching == 0;
        if due {
            self.checked = Instant::now();
        }
        due
    }

    /// Make the next `check_due` fire as if `CHECK_EVERY` had passed, so a
    /// test need not wait out the real timer.
    #[doc(hidden)]
    pub fn expire_check_timer(&mut self) {
        self.checked = self
            .checked
            .checked_sub(CHECK_EVERY)
            .unwrap_or(self.checked);
    }

    /// Where other devices can reach this node; empty when it listens
    /// nowhere.
    #[must_use]
    pub fn hints(&self) -> Vec<String> {
        let Some(port) = self.service.local_addr().map(|addr| addr.port()) else {
            return Vec::new();
        };
        match self.listen {
            Listen::Off | Listen::Fetch => Vec::new(),
            Listen::Local => vec![format!("127.0.0.1:{port}")],
            Listen::Lan | Listen::Beacon => {
                let mut hints = reachable_hints(port);
                if let Some(address) = self.advertise.as_deref() {
                    hints.retain(|hint| hint != address);
                    hints.insert(0, address.to_owned());
                }
                hints.truncate(MAX_HINTS);
                hints
            }
        }
    }
}
