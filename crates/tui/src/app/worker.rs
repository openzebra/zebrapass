//! One worker thread for Argon2id, ML-KEM, and storage, so the UI never
//! blocks. Jobs are queued and run one at a time, which keeps peak memory at
//! one Argon2 instance.
//!
//! Every result carries the ticket of its job. A result whose ticket the app
//! no longer waits for (a cancelled unlock) is dropped on arrival, and with it
//! any session or secret it holds.

use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use local::Paths;
use session::KdfProfile;

use crate::vault::create::{create, restore, NewVault, RestoreVault};
use crate::vault::error::{describe, UnlockError};
use crate::vault::open::{unlock_vault, Credential, Vault};
use crate::vault::ops::{apply, Op, Outcome};

/// Work for the worker thread.
pub enum Job {
    /// Time one Argon2id run of the Fast profile (UI estimate only).
    Bench,
    /// Unlock a vault.
    Unlock(Paths, Credential),
    /// Create a vault.
    Create(Box<NewVault>),
    /// Restore a vault.
    Restore(Box<RestoreVault>),
    /// Run an op on an unlocked vault; the vault comes back in the result.
    Vault(Box<Vault>, Op),
    /// Read and parse another manager's export.
    ParseImport(Box<import::Load>),
}

/// A finished job.
pub enum JobResult {
    /// Time of one [`KdfProfile::Fast`] run, `None` when Argon2 refused.
    Bench(Option<Duration>),
    /// Unlock outcome.
    Opened(Result<Box<Vault>, UnlockError>),
    /// Create outcome; the error text holds no secret.
    Created(Result<Box<Vault>, String>),
    /// Restore outcome.
    Restored(Result<Box<Vault>, UnlockError>),
    /// Op outcome with the vault handed back.
    Vault(Box<Vault>, Result<Outcome, String>),
    /// Parsed export; the error text holds no file contents.
    ImportParsed(Result<Box<import::Parsed>, String>),
}

impl std::fmt::Debug for JobResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Bench(..) => "JobResult::Bench",
            Self::Opened(_) => "JobResult::Opened",
            Self::Created(_) => "JobResult::Created",
            Self::Restored(_) => "JobResult::Restored",
            Self::Vault(..) => "JobResult::Vault",
            Self::ImportParsed(_) => "JobResult::ImportParsed",
        })
    }
}

/// Handle to the worker thread.
pub struct Worker {
    jobs: Sender<(u64, Job)>,
    results: Receiver<(u64, JobResult)>,
    next: u64,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker")
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl Worker {
    /// Start the thread.
    ///
    /// # Errors
    ///
    /// When the OS refuses to spawn a thread.
    pub fn spawn() -> std::io::Result<Self> {
        let (jobs, inbox) = channel::<(u64, Job)>();
        let (outbox, results) = channel();
        std::thread::Builder::new()
            .name(String::from("zebrapass-worker"))
            .spawn(move || {
                while let Ok((ticket, job)) = inbox.recv() {
                    if outbox.send((ticket, run(job))).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self {
            jobs,
            results,
            next: 1,
        })
    }

    /// Queue `job`; returns its ticket. When the thread is gone the job is
    /// dropped (and its secrets with it) and the ticket never completes.
    pub fn submit(&mut self, job: Job) -> u64 {
        let ticket = self.next;
        self.next = self.next.wrapping_add(1);
        let _ = self.jobs.send((ticket, job));
        ticket
    }

    /// A finished job, if any.
    #[must_use]
    pub fn try_recv(&self) -> Option<(u64, JobResult)> {
        self.results.try_recv().ok()
    }

    /// Wait up to `timeout` for a finished job.
    #[must_use]
    pub fn recv_timeout(&self, timeout: Duration) -> Option<(u64, JobResult)> {
        self.results.recv_timeout(timeout).ok()
    }
}

fn run(job: Job) -> JobResult {
    match job {
        Job::Bench => JobResult::Bench(bench(KdfProfile::Fast)),
        Job::Unlock(paths, credential) => JobResult::Opened(unlock_vault(paths, credential)),
        Job::Create(request) => {
            JobResult::Created(create(*request).map_err(|error| describe(&error)))
        }
        Job::Restore(request) => JobResult::Restored(restore(*request)),
        Job::Vault(mut vault, op) => {
            let result = apply(&mut vault, op).map_err(|error| describe(&error));
            JobResult::Vault(vault, result)
        }
        Job::ParseImport(load) => {
            JobResult::ImportParsed(load.run().map(Box::new).map_err(|error| error.to_string()))
        }
    }
}

/// One Argon2id run over a fixed dummy input, timed.
fn bench(profile: KdfProfile) -> Option<Duration> {
    let started = Instant::now();
    kdf::argon2id(
        b"zebrapass-benchmark",
        &[0u8; 32],
        profile.m_kib(),
        profile.t(),
        profile.p(),
    )
    .ok()
    .map(|_| started.elapsed())
}
