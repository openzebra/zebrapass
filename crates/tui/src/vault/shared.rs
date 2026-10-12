//! Shared vaults as the interface sees them: each one a record source of its
//! own, either waiting for its vault file (pending) or open.

use std::path::Path;
use std::sync::Arc;

use local::{is_pending, open_shared_vault, read_member_log, SharedRef, SharedVault, SyncIdentity};
use memberlog::Role;
use p2p_net::{FetchError, Known};
use session::Session;

use crate::vault::records::{build_cache, Summary};

/// Where a shared vault stands on this device.
pub enum Status {
    /// Joined, waiting for a member to send the vault file.
    Pending,
    /// The file is here but did not open or verify.
    Unavailable,
    /// Open.
    Ready(Box<SharedVault>),
}

/// One shared vault: its reference, state and record list.
pub struct SharedItem {
    /// The reference stored in the personal vault.
    pub reference: Arc<SharedRef>,
    /// Pending, unavailable or open.
    pub status: Status,
    /// Record summaries, empty until open (wiped on drop).
    pub cache: Box<[Summary]>,
    /// People in the vault, this account included.
    pub people: usize,
    /// Members who left since the key was last replaced: they still hold it.
    pub leaves: usize,
    /// What this account may do here.
    pub my_role: Option<Role>,
    /// Why the last attempt to fetch the vault file failed.
    pub waiting: Option<FetchError>,
    /// The open vault's files are behind this device's seed: a rotation is
    /// waiting to be finished.
    pub stale: bool,
}

impl std::fmt::Debug for SharedItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedItem")
            .field("name", &self.reference.name)
            .field("ready", &self.ready())
            .finish_non_exhaustive()
    }
}

impl SharedItem {
    fn new(
        base: &Path,
        reference: Arc<SharedRef>,
        identity: &SyncIdentity,
        status: Status,
    ) -> Self {
        let Membership {
            people,
            my_role,
            leaves,
        } = membership(base, &reference, identity);
        let cache = match &status {
            Status::Ready(vault) => build_cache(&vault.session).unwrap_or_default(),
            Status::Pending | Status::Unavailable => Box::default(),
        };
        let stale = matches!(&status, Status::Ready(vault) if vault.stale);
        Self {
            reference,
            status,
            cache,
            people,
            leaves,
            my_role,
            waiting: None,
            stale,
        }
    }

    /// Open the shared vault if its file is here.
    #[must_use]
    pub fn open(base: &Path, reference: Arc<SharedRef>, identity: &SyncIdentity) -> Self {
        let status = if is_pending(base, &reference) {
            Status::Pending
        } else {
            open_shared_vault(base, &reference, identity)
                .map_or(Status::Unavailable, |vault| Status::Ready(Box::new(vault)))
        };
        Self::new(base, reference, identity, status)
    }

    /// A vault this device just created.
    #[must_use]
    pub fn created(
        base: &Path,
        reference: Arc<SharedRef>,
        vault: SharedVault,
        identity: &SyncIdentity,
    ) -> Self {
        Self::new(base, reference, identity, Status::Ready(Box::new(vault)))
    }

    /// A vault this device just joined and has no file for yet.
    #[must_use]
    pub fn joined(base: &Path, reference: Arc<SharedRef>, identity: &SyncIdentity) -> Self {
        Self::new(base, reference, identity, Status::Pending)
    }

    /// The vault's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.reference.name
    }

    /// The open vault's session.
    #[must_use]
    pub fn session(&self) -> Option<&Session> {
        match &self.status {
            Status::Ready(vault) => Some(&vault.session),
            Status::Pending | Status::Unavailable => None,
        }
    }

    /// The open vault, to change it.
    pub fn vault_mut(&mut self) -> Option<&mut SharedVault> {
        match &mut self.status {
            Status::Ready(vault) => Some(vault),
            Status::Pending | Status::Unavailable => None,
        }
    }

    /// Read the vault again from disk, keeping the current state if it does
    /// not open.
    pub fn reload(&mut self, base: &Path, identity: &SyncIdentity) {
        let fresh = Self::open(base, Arc::clone(&self.reference), identity);
        if fresh.ready() {
            self.status = fresh.status;
            self.cache = fresh.cache;
            self.people = fresh.people;
            self.leaves = fresh.leaves;
            self.my_role = fresh.my_role;
            self.stale = fresh.stale;
            self.waiting = None;
        }
    }

    /// Read who is in the vault and this account's role from the stored
    /// member log, which a sync may have extended. Returns whether either
    /// changed.
    pub fn refresh_members(&mut self, base: &Path, identity: &SyncIdentity) -> bool {
        let now = membership(base, &self.reference, identity);
        let changed =
            now.people != self.people || now.my_role != self.my_role || now.leaves != self.leaves;
        if now.people > 0 {
            self.people = now.people;
            self.my_role = now.my_role;
            self.leaves = now.leaves;
        }
        changed && now.people > 0
    }

    /// Take a vault that just arrived and show its records.
    pub fn adopt(&mut self, vault: SharedVault, identity: &SyncIdentity) {
        self.cache = build_cache(&vault.session).unwrap_or_default();
        self.people = vault.log.members().len();
        self.leaves = vault.log.leaves_since_rotation();
        self.my_role = identity
            .devices()
            .first()
            .and_then(|cert| vault.log.role_of(&cert.client_id));
        self.waiting = None;
        self.stale = vault.stale;
        self.status = Status::Ready(Box::new(vault));
    }

    /// What this device knows about the vault file, for a fetch.
    #[must_use]
    pub fn known(&self) -> Option<Known> {
        self.session().map(|session| Known {
            generation: session.generation(),
            stale: self.stale,
        })
    }

    /// Whether the vault is open.
    #[must_use]
    pub const fn ready(&self) -> bool {
        matches!(self.status, Status::Ready(_))
    }
}

struct Membership {
    people: usize,
    my_role: Option<Role>,
    leaves: usize,
}

fn membership(base: &Path, reference: &SharedRef, identity: &SyncIdentity) -> Membership {
    read_member_log(base, reference).map_or(
        Membership {
            people: 0,
            my_role: None,
            leaves: 0,
        },
        |log| {
            let mine = identity.devices().first().map(|cert| cert.client_id);
            Membership {
                people: log.members().len(),
                my_role: mine.and_then(|client| log.role_of(&client)),
                leaves: log.leaves_since_rotation(),
            }
        },
    )
}

/// Every shared vault the personal vault points at.
#[must_use]
pub fn references(session: &Session) -> Vec<Arc<SharedRef>> {
    session::list_records(session)
        .unwrap_or_default()
        .iter()
        .filter_map(|row| session::open_record(session, row.id).ok())
        .filter_map(|doc| SharedRef::from_document(&doc).ok().flatten())
        .map(Arc::new)
        .collect()
}
