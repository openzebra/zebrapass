//! A device that holds only the phrase asks another device of the account for
//! the personal vault: the vault file, its frontier and its records.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::panic,
    reason = "tests may unwrap and index"
)]

use std::fmt::Write as _;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

use local::{create_vault, write_atomic, Paths, SyncIdentity};
use p2p_net::{
    fetch_personal, personal_view, Conn, Dialing, FetchError, Limits, Policy, Service,
    SharedProvider,
};
use record::{Document, TAG_TITLE};
use session::{
    accept_peer_frame, frontier, latest_frame, list_records, open_record, unlock, write_record,
    BodyAlg, KdfProfile, Session, UnlockCreds, VaultFile,
};
use syncwire::{decode_announce, decode_frontier, decode_personal_frame};

const SEED: [u8; 64] = [3; 64];

fn temp_dir(tag: &str) -> PathBuf {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).unwrap();
    let mut name = format!("zp-personal-{tag}-");
    for byte in suffix {
        write!(name, "{byte:02x}").unwrap();
    }
    let dir = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn titled(text: &str) -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, text);
    doc
}

fn titles(session: &Session) -> Vec<String> {
    let mut found: Vec<String> = list_records(session)
        .unwrap()
        .iter()
        .map(|row| {
            open_record(session, row.id)
                .unwrap()
                .text(TAG_TITLE)
                .unwrap()
                .unwrap()
                .to_owned()
        })
        .collect();
    found.sort();
    found
}

/// The first device: a real personal vault on disk with two records, an
/// identity, and a node serving it.
struct First {
    paths: Paths,
    session: Session,
    file: VaultFile,
    provider: Arc<SharedProvider>,
    service: Service,
    address: String,
}

impl First {
    fn start(limits: Limits) -> Self {
        let base = temp_dir("first");
        let (paths, mut session, mut file, meta) =
            create_vault(&base, &SEED, KdfProfile::Fast, BodyAlg::Frames).unwrap();
        let identity = Arc::new(
            SyncIdentity::enroll(&SEED, &meta.client_id, session.origin_device(), u64::MAX)
                .unwrap(),
        );
        session
            .set_origin_device(identity.device_id().unwrap())
            .unwrap();
        for title in ["wifi", "bank"] {
            write_record(&mut session, &mut file, None, &titled(title)).unwrap();
        }
        write_atomic(&paths.vault_file, file.as_bytes()).unwrap();
        let provider = Arc::new(SharedProvider::new(base, identity));
        provider.allow_loopback_peers();
        assert!(provider.serve_personal(paths.vault_file.clone(), session.reopen_key()));
        let service =
            Service::start_with(Some("127.0.0.1:0"), Arc::clone(&provider), limits).unwrap();
        let address = service.local_addr().unwrap().to_string();
        Self {
            paths,
            session,
            file,
            provider,
            service,
            address,
        }
    }

    fn write(&mut self, title: &str) {
        write_record(&mut self.session, &mut self.file, None, &titled(title)).unwrap();
        write_atomic(&self.paths.vault_file, self.file.as_bytes()).unwrap();
    }
}

fn second_device(seed: &[u8; 64], device: u8) -> SyncIdentity {
    let client_id = kdf::client_id(seed).unwrap();
    SyncIdentity::enroll(seed, &client_id, [device; 16], u64::MAX).unwrap()
}

fn open_fetched(bytes: Vec<u8>) -> Session {
    unlock(&VaultFile::new(bytes), &UnlockCreds::master(&SEED), None).unwrap()
}

#[test]
fn a_device_with_the_phrase_fetches_the_vault_and_reads_the_same_records() {
    let first = First::start(Limits::default());
    let fetched = fetch_personal(&second_device(&SEED, 9), &first.address, true).unwrap();
    let parsed_id = *first.session.vault_id();
    assert_eq!(fetched.announce.vault_id, parsed_id);
    assert_eq!(fetched.announce.generation, first.session.generation());
    assert_eq!(&fetched.announce.commit_tag, first.session.commit_tag());
    assert_eq!(fetched.peer.device_id, first.session.origin_device());
    let session = open_fetched(fetched.file);
    assert_eq!(titles(&session), ["bank", "wifi"]);
    assert_eq!(titles(&first.session), titles(&session));
}

#[test]
fn the_frontier_and_a_revision_let_a_device_catch_up_one_record_at_a_time() {
    let mut first = First::start(Limits::default());
    let fetched = fetch_personal(&second_device(&SEED, 9), &first.address, true).unwrap();
    let mut file = VaultFile::new(fetched.file);
    let mut session = unlock(&file, &UnlockCreds::master(&SEED), None).unwrap();
    first.write("mail");

    let view = personal_view(
        &second_device(&SEED, 9),
        Dialing {
            policy: Policy { loopback: true },
            trusted: Vec::new(),
        },
    )
    .unwrap();
    let address = first.address.clone();
    let (theirs, frame) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut conn = Conn::connect(&view, &address).await.unwrap();
            let theirs = conn.frontier().await.unwrap();
            let newest = decode_frontier(&theirs).unwrap().last().unwrap().record_id;
            let revision = conn
                .revisions(&[(newest, 1)])
                .await
                .unwrap()
                .remove(0)
                .unwrap();
            (theirs, decode_personal_frame(&revision).unwrap())
        });
    let theirs = decode_frontier(&theirs).unwrap();
    assert_eq!(theirs, frontier(&first.session).unwrap());
    assert_eq!(theirs.len(), 3);
    let newest = theirs.last().unwrap().record_id;
    assert_eq!(frame, latest_frame(&first.session, newest).unwrap());

    accept_peer_frame(&mut session, &mut file, &frame).unwrap();
    assert_eq!(titles(&session), ["bank", "mail", "wifi"]);
    assert!(
        accept_peer_frame(&mut session, &mut file, &frame).is_err(),
        "the same revision again is stale"
    );
}

#[test]
fn the_announcement_names_the_file_that_is_served() {
    let mut first = First::start(Limits::default());
    first.write("mail");
    let fetched = fetch_personal(&second_device(&SEED, 9), &first.address, true).unwrap();
    let raw = decode_announce(&syncwire::encode_announce(&fetched.announce)).unwrap();
    assert_eq!(raw.generation, first.session.generation());
    assert_eq!(raw.vault_id, *first.session.vault_id());
}

#[test]
fn a_device_of_another_account_is_turned_away_at_the_gate() {
    let first = First::start(Limits::default());
    let stranger = second_device(&[4; 64], 9);
    let outcome = fetch_personal(&stranger, &first.address, true);
    assert_eq!(outcome.unwrap_err(), FetchError::Refused);
    drop(first.service);
    drop(first.provider);
}

#[test]
fn a_wrong_address_is_unreachable_and_loopback_needs_the_opt_in() {
    let first = First::start(Limits::default());
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    };
    let me = second_device(&SEED, 9);
    assert_eq!(
        fetch_personal(&me, &closed, true).unwrap_err(),
        FetchError::Unreachable
    );
    assert_eq!(
        fetch_personal(&me, &first.address, false).unwrap_err(),
        FetchError::Unreachable,
        "loopback is dialed only when asked for"
    );
    assert_eq!(
        fetch_personal(&me, "not an address", true).unwrap_err(),
        FetchError::Unreachable
    );
    for refused in ["169.254.169.254:80", "0.0.0.0:7447", "224.0.0.1:7447"] {
        assert_eq!(
            fetch_personal(&me, refused, true).unwrap_err(),
            FetchError::Unreachable,
            "{refused}"
        );
    }
}

#[test]
fn the_snapshot_cap_applies_to_the_personal_vault() {
    let first = First::start(Limits {
        max_snapshots: 0,
        ..Limits::default()
    });
    let me = second_device(&SEED, 9);
    assert_eq!(
        fetch_personal(&me, &first.address, true).unwrap_err(),
        FetchError::Failed
    );
}

#[test]
fn a_node_that_does_not_serve_the_personal_vault_does_not_answer_for_it() {
    let base = temp_dir("silent");
    let identity = Arc::new(second_device(&SEED, 7));
    let provider = Arc::new(SharedProvider::new(base, identity));
    provider.allow_loopback_peers();
    let service = Service::start(Some("127.0.0.1:0"), provider).unwrap();
    let address = service.local_addr().unwrap().to_string();
    let me = second_device(&SEED, 9);
    assert_eq!(
        fetch_personal(&me, &address, true).unwrap_err(),
        FetchError::Refused,
        "no view for the personal vault: the hello is not routed"
    );
}

fn personal_conn_view(address: &str, device: u8) -> p2p_net::VaultView {
    personal_view(
        &second_device(&SEED, device),
        Dialing {
            policy: Policy { loopback: true },
            trusted: vec![address.parse().unwrap()],
        },
    )
    .unwrap()
}

#[test]
fn a_device_of_the_account_can_push_a_frame_and_the_owner_takes_it_once() {
    let first = First::start(Limits::default());
    let newest = frontier(&first.session).unwrap().last().unwrap().record_id;
    let frame = latest_frame(&first.session, newest).unwrap();
    let pushed = syncwire::encode_personal_frame(&frame).unwrap();
    let view = personal_conn_view(&first.address, 9);
    let verdicts = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut conn = Conn::connect(&view, &first.address).await.unwrap();
            let good = conn.push(vec![pushed.clone()]).await.unwrap();
            let bad = conn.push(vec![vec![1, 2, 3]]).await.unwrap();
            (good, bad)
        });
    assert_eq!(verdicts.0, [p2p_net::Push::Applied]);
    assert_eq!(verdicts.1, [p2p_net::Push::Refused]);
    assert_eq!(first.provider.take_pushed(), [frame]);
    assert!(first.provider.take_pushed().is_empty());
}

#[test]
fn a_pull_also_sends_the_frames_the_other_device_lacks() {
    let mut first = First::start(Limits::default());
    let base = temp_dir("second");
    let copy = base.join("vault.bin");
    std::fs::copy(&first.paths.vault_file, &copy).unwrap();
    let identity = Arc::new(second_device(&SEED, 7));
    let provider = Arc::new(SharedProvider::new(base, identity));
    provider.allow_loopback_peers();
    assert!(provider.serve_personal(copy, first.session.reopen_key()));
    let node = Service::start(Some("127.0.0.1:0"), Arc::clone(&provider)).unwrap();
    let address = node.local_addr().unwrap().to_string();

    first.write("mail");
    let newest = frontier(&first.session).unwrap().last().unwrap().record_id;
    let wanted = latest_frame(&first.session, newest).unwrap();
    first.service.pull_personal(
        personal_conn_view(&address, 9),
        vec![address.clone()],
        frontier(&first.session).unwrap(),
        first.provider.personal_serve(),
    );
    let started = std::time::Instant::now();
    let mut pulled = None;
    while pulled.is_none() && started.elapsed() < std::time::Duration::from_secs(10) {
        pulled = first
            .service
            .events()
            .try_iter()
            .find_map(|event| match event {
                p2p_net::Event::PersonalPulled { frames, .. } => Some(frames),
                _ => None,
            });
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(pulled.unwrap(), Vec::<Vec<u8>>::new(), "nothing to pull");
    assert_eq!(provider.take_pushed(), [wanted]);
}

/// Rewrite the identity file at `path` as an older revision wrote it: the
/// same plaintext without the account gate secret, sealed as revision 1.
fn make_revision_one(path: &std::path::Path, key: &secret::Secret<[u8; 32]>) {
    let bytes = std::fs::read(path).unwrap();
    let header = frame::parse(&bytes).unwrap();
    assert_eq!(header.revision, 2);
    let plain = frame::open(key, &bytes).unwrap();
    let (seed, rest) = plain.expose().split_at(32);
    let legacy = [seed, &rest[32..]].concat();
    let meta = frame::FrameMeta {
        kind: header.kind,
        record_id: header.record_id,
        revision: 1,
        origin_device: header.origin_device,
        timestamp_ms: header.timestamp_ms,
        alg: header.alg,
    };
    write_atomic(path, &frame::seal(key, &meta, &legacy).unwrap()).unwrap();
}

#[test]
fn a_revision_one_identity_upgrades_in_place_keeps_its_device_and_then_serves() {
    let base = temp_dir("legacy");
    let (paths, session, _file, meta) =
        create_vault(&base, &SEED, KdfProfile::Fast, BodyAlg::Frames).unwrap();
    let enrolled =
        SyncIdentity::enroll(&SEED, &meta.client_id, session.origin_device(), u64::MAX).unwrap();
    let key = secret::Secret::new([9u8; 32]);
    let file = base.join("sync.id");
    enrolled.save(&file, &key).unwrap();
    make_revision_one(&file, &key);

    let legacy = SyncIdentity::load(&file, &key).unwrap();
    assert!(legacy.account_gate().is_none(), "revision 1 has no gate");
    let (device, certs, vk) = (
        legacy.device_id().unwrap(),
        legacy.devices().to_vec(),
        legacy.sign_key().verifying_key().unwrap(),
    );
    let provider = Arc::new(SharedProvider::new(base.clone(), Arc::new(legacy)));
    assert!(
        !provider.serve_personal(paths.vault_file.clone(), session.reopen_key()),
        "without the gate it cannot serve"
    );

    assert!(
        local::upgrade_sync_identity(&file, &key, &[4; 64]).is_err(),
        "another account's phrase changes nothing"
    );
    assert!(SyncIdentity::load(&file, &key)
        .unwrap()
        .account_gate()
        .is_none());
    assert!(local::upgrade_sync_identity(&file, &key, &SEED).unwrap());
    assert!(!local::upgrade_sync_identity(&file, &key, &SEED).unwrap());
    assert_eq!(
        frame::parse(&std::fs::read(&file).unwrap())
            .unwrap()
            .revision,
        2
    );

    let upgraded = SyncIdentity::load(&file, &key).unwrap();
    assert_eq!(upgraded.device_id().unwrap(), device);
    assert_eq!(upgraded.devices(), certs.as_slice());
    assert_eq!(upgraded.sign_key().verifying_key().unwrap(), vk);

    let provider2 = Arc::new(SharedProvider::new(base, Arc::new(upgraded)));
    provider2.allow_loopback_peers();
    assert!(provider2.serve_personal(paths.vault_file, session.reopen_key()));
    let service = Service::start(Some("127.0.0.1:0"), provider2).unwrap();
    let address = service.local_addr().unwrap().to_string();
    let me = second_device(&SEED, 9);
    let fetched = fetch_personal(&me, &address, true).unwrap();
    assert_eq!(fetched.announce.vault_id, *session.vault_id());
    drop(provider);
}

/// A second device holding the vault as it was: its node runs, but until
/// `unlock` it does not serve the personal vault, as when it is locked.
struct Sleeper {
    session: Session,
    file: VaultFile,
    path: PathBuf,
    provider: Arc<SharedProvider>,
    node: Service,
    address: String,
}

impl Sleeper {
    fn start(first: &First) -> Self {
        let base = temp_dir("sleeper");
        let path = base.join("vault.bin");
        std::fs::copy(&first.paths.vault_file, &path).unwrap();
        let file = VaultFile::new(std::fs::read(&path).unwrap());
        let session = open_fetched(file.as_bytes().to_vec());
        let provider = Arc::new(SharedProvider::new(base, Arc::new(second_device(&SEED, 7))));
        provider.allow_loopback_peers();
        let node = Service::start(Some("127.0.0.1:0"), Arc::clone(&provider)).unwrap();
        let address = node.local_addr().unwrap().to_string();
        Self {
            session,
            file,
            path,
            provider,
            node,
            address,
        }
    }

    fn unlock(&self) {
        assert!(self
            .provider
            .serve_personal(self.path.clone(), self.session.reopen_key()));
    }

    /// Apply frames as the open vault does, save it, and count the ones it
    /// took.
    fn apply(&mut self, frames: &[Vec<u8>]) -> usize {
        let taken = frames
            .iter()
            .filter(|frame| accept_peer_frame(&mut self.session, &mut self.file, frame).is_ok())
            .count();
        write_atomic(&self.path, self.file.as_bytes()).unwrap();
        taken
    }
}

fn next_personal_event(service: &Service) -> p2p_net::Event {
    loop {
        let event = service
            .events()
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap();
        if matches!(
            event,
            p2p_net::Event::PersonalPulled { .. } | p2p_net::Event::FetchFailed { .. }
        ) {
            return event;
        }
    }
}

#[test]
fn a_push_to_a_peer_that_was_locked_lands_on_the_next_check_in() {
    let mut first = First::start(Limits::default());
    let mut sleeper = Sleeper::start(&first);
    first.write("mail");
    let push = |first: &First, sleeper: &Sleeper| {
        first.service.pull_personal(
            personal_conn_view(&sleeper.address, 9),
            vec![sleeper.address.clone()],
            frontier(&first.session).unwrap(),
            first.provider.personal_serve(),
        );
        next_personal_event(&first.service)
    };

    // While the peer is locked the push is turned away, and nothing is kept.
    assert!(matches!(
        push(&first, &sleeper),
        p2p_net::Event::FetchFailed { .. }
    ));
    assert!(sleeper.provider.take_pushed().is_empty());
    assert_ne!(
        frontier(&sleeper.session).unwrap(),
        frontier(&first.session).unwrap()
    );

    // Once it unlocks, the next check-in delivers what it missed.
    sleeper.unlock();
    assert!(matches!(
        push(&first, &sleeper),
        p2p_net::Event::PersonalPulled { .. }
    ));
    let pushed = sleeper.provider.take_pushed();
    assert_eq!(pushed.len(), 1);
    assert_eq!(sleeper.apply(&pushed), 1);
    assert_eq!(
        frontier(&sleeper.session).unwrap(),
        frontier(&first.session).unwrap()
    );

    // A further check-in moves nothing and queues nothing.
    assert!(matches!(
        push(&first, &sleeper),
        p2p_net::Event::PersonalPulled { .. }
    ));
    assert!(sleeper.provider.take_pushed().is_empty());
    drop(sleeper.node);
}

#[test]
fn a_peer_that_was_locked_catches_up_by_pulling_when_it_unlocks() {
    let mut first = First::start(Limits::default());
    let mut sleeper = Sleeper::start(&first);
    first.write("mail");
    first.write("bank2");
    sleeper.unlock();
    sleeper.node.pull_personal(
        personal_conn_view(&first.address, 7),
        vec![first.address.clone()],
        frontier(&sleeper.session).unwrap(),
        sleeper.provider.personal_serve(),
    );
    let p2p_net::Event::PersonalPulled { frames, .. } = next_personal_event(&sleeper.node) else {
        panic!("the pull failed")
    };
    assert_eq!(frames.len(), 2);
    assert_eq!(sleeper.apply(&frames), 2);
    assert_eq!(
        frontier(&sleeper.session).unwrap(),
        frontier(&first.session).unwrap()
    );
    assert_eq!(sleeper.apply(&frames), 0, "the same frames again are stale");
}
