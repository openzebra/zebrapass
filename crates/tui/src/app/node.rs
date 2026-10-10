//! The node itself: the service, what it serves, and where it tells members
//! to reach it.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use local::{Listen, Offer, SyncIdentity};
use p2p_net::{reachable_hints, Service, SharedProvider};
use session::MAX_HINTS;

/// The port a node tries first, so an invitation stays valid across runs.
const PORT: u16 = 7447;

/// How long an open shared vault goes without trading revisions.
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
            Listen::Lan => Some(format!("0.0.0.0:{port}")),
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
            checked: Instant::now(),
        });
        let hints = node.hints();
        node.provider.set_hints(hints.clone());
        node.reachable = hints.into_boxed_slice();
        Some(node)
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
            Listen::Lan => {
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
