//! The node itself: the service, what it serves, and where it tells members
//! to reach it.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use local::{Listen, Offer, SyncIdentity};
use p2p_net::{reachable_hints, BeaconConfig, BeaconIdentity, Service, SharedProvider};
use session::MAX_HINTS;

/// The port a node tries first, so an invitation stays valid across runs.
const PORT: u16 = 7447;

/// How long an open shared vault goes without trading revisions.
/// Announced addresses kept.
const MAX_DISCOVERED: usize = 8;

const CHECK_EVERY: Duration = Duration::from_secs(15);

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
    /// TODO(client-only): a phone could run with no listener at all and only
    /// pull from the account's other devices; `Listen::Off` is the seam.
    #[must_use]
    pub fn start(
        base: &Path,
        identity: Arc<SyncIdentity>,
        listen: Listen,
        advertise: Option<Box<str>>,
    ) -> Option<Box<Self>> {
        let provider = Arc::new(SharedProvider::new(
            base.to_path_buf(),
            Arc::clone(&identity),
        ));
        if matches!(listen, Listen::Local) {
            provider.allow_loopback_peers();
        }
        let bind = |port: u16| match listen {
            Listen::Off => None,
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
            checked: Instant::now(),
        });
        let hints = node.hints();
        node.provider.set_hints(hints.clone());
        node.reachable = hints.into_boxed_slice();
        if matches!(listen, Listen::Beacon) {
            node.start_beacon();
        }
        Some(node)
    }

    /// Announce this node on the local network, to the account's other
    /// devices only. A device without the account gate, or a network that
    /// will not carry multicast, simply has no beacon.
    fn start_beacon(&self) {
        let (Some(gate), Some(device)) = (self.identity.account_gate(), self.identity.device_id())
        else {
            return;
        };
        if let Ok(identity) = BeaconIdentity::new(gate, device) {
            let _ = self.service.start_beacon(
                Arc::clone(&self.provider),
                identity,
                BeaconConfig::lan(),
            );
        }
    }

    /// Remember an address another device announced; the newest few stay.
    pub fn discover(&mut self, address: std::net::SocketAddr) {
        let address = address.to_string();
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

    /// Where other devices can reach this node; empty when it listens
    /// nowhere.
    #[must_use]
    pub fn hints(&self) -> Vec<String> {
        let Some(port) = self.service.local_addr().map(|addr| addr.port()) else {
            return Vec::new();
        };
        match self.listen {
            Listen::Off => Vec::new(),
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
