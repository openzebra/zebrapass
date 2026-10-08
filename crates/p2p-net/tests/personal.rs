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
            let theirs = conn
                .get("/v1/frontier", 1 << 20, false)
                .await
                .unwrap()
                .unwrap();
            let newest = decode_frontier(&theirs).unwrap().last().unwrap().record_id;
            let revision = conn
                .get(&format!("/v1/revision/{newest}"), 1 << 20, false)
                .await
                .unwrap()
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
