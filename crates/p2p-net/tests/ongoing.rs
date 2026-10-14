//! Ongoing sync between three nodes on one machine. Each check-in waits up to
//! a minute for its answer, and the crypto of a debug build is slow: on a
//! loaded machine run these with `--test-threads=4`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::panic,
    clippy::significant_drop_tightening,
    reason = "tests may unwrap and index; a relay or a node lives for the whole test"
)]

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use local::{
    adopt_shared_file, create_shared_vault, join_shared_vault, open_shared_vault, Edit, SharedRef,
    SyncIdentity,
};
use memberlog::{Action, Role};
use p2p_net::{Conn, Event, PeerBook, Provider, Push, Service, SharedProvider, SnapshotSource};
use record::{Document, TAG_TITLE};
use session::{attest_latest, list_records, open_record, write_record, KdfProfile, VaultFile};

const WAIT: Duration = Duration::from_secs(60);

fn temp_dir(tag: &str) -> PathBuf {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).unwrap();
    let mut name = format!("zp-ongoing-{tag}-");
    for byte in suffix {
        write!(name, "{byte:02x}").unwrap();
    }
    let dir = std::env::temp_dir().join(name);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[allow(clippy::unnecessary_box_returns, reason = "the edit API takes a box")]
fn titled(text: &str) -> Box<Document> {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, text);
    Box::new(doc)
}

struct Node {
    base: PathBuf,
    id: Arc<SyncIdentity>,
    reference: Arc<SharedRef>,
    provider: Arc<SharedProvider>,
    service: Service,
    addr: String,
}

impl Node {
    fn edit(&self, edit: Edit) -> anyhow::Result<u32> {
        self.provider
            .with_vault(&self.reference.vault_id, |vault, reference, identity| {
                vault.edit(reference, identity, edit)
            })
    }

    fn titles(&self) -> Vec<String> {
        let vault = open_shared_vault(&self.base, &self.reference, &self.id).unwrap();
        let mut found: Vec<String> = list_records(&vault.session)
            .unwrap()
            .iter()
            .map(|row| {
                open_record(&vault.session, row.id)
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

    /// Check in with `others` and return what moved: (pulled, pushed, refused).
    fn check_in(&self, others: &[&Self]) -> (usize, usize, usize) {
        let hints = others.iter().map(|node| node.addr.clone()).collect();
        self.service
            .check_in(Arc::clone(&self.provider), self.reference.vault_id, hints);
        loop {
            match self.service.events().recv_timeout(WAIT).unwrap() {
                Event::Synced {
                    pulled,
                    pushed,
                    refused,
                    ..
                } => return (pulled, pushed, refused),
                Event::FetchFailed { reason, .. } => panic!("check-in failed: {reason}"),
                _ => {}
            }
        }
    }
}

/// Alice (owner), Bob (writer) and Carol (reader), all online.
fn trio() -> [Node; 3] {
    let dirs = [temp_dir("a"), temp_dir("b"), temp_dir("c")];
    let ids: Vec<Arc<SyncIdentity>> = (1..=3u8)
        .map(|n| Arc::new(SyncIdentity::enroll(&[n; 64], &[n; 64], [n; 16], u64::MAX).unwrap()))
        .collect();
    let (mut alice, alice_ref) =
        create_shared_vault(&dirs[0], &ids[0], "Family", KdfProfile::Fast).unwrap();
    for (guest, role) in [(&ids[1], Role::Writer), (&ids[2], Role::Reader)] {
        let add = Action::Add {
            client_id: guest.devices()[0].client_id,
            root_vk: Box::new(*guest.root_vk()),
            role,
        };
        let entry = alice
            .log
            .propose(&ids[0].sign_key(), &ids[0].devices()[0], add, 1)
            .unwrap();
        alice.log.append(entry).unwrap();
    }
    alice.save_log(&alice_ref.seed).unwrap();
    alice.persist(&alice_ref.seed).unwrap();
    let attested = alice.attestations(&alice_ref, &ids[0]).unwrap();
    let mut nodes = Vec::new();
    for (index, id) in ids.into_iter().enumerate() {
        let reference = Arc::new(alice_ref.duplicate());
        if index > 0 {
            join_shared_vault(&dirs[index], &reference, &alice.log).unwrap();
            adopt_shared_file(
                &dirs[index],
                &reference,
                VaultFile::new(alice.file.as_bytes().to_vec()),
                &attested,
                &id,
            )
            .unwrap();
        }
        let provider = Arc::new(SharedProvider::new(dirs[index].clone(), Arc::clone(&id)));
        provider.serve(Arc::clone(&reference));
        let service = Service::start(Some("127.0.0.1:0"), Arc::clone(&provider)).unwrap();
        let addr = service.local_addr().unwrap().to_string();
        provider.allow_loopback_peers();
        provider.set_hints(vec![addr.clone()]);
        nodes.push(Node {
            base: dirs[index].clone(),
            id,
            reference,
            provider,
            service,
            addr,
        });
    }
    let mut it = nodes.into_iter();
    [it.next().unwrap(), it.next().unwrap(), it.next().unwrap()]
}

#[test]
fn a_writers_edit_reaches_the_owner_and_a_reader_who_only_talks_to_the_owner() {
    let [alice, bob, carol] = trio();
    bob.edit(Edit::Create(titled("wifi"))).unwrap();
    assert_eq!(bob.check_in(&[&alice]), (0, 1, 0));
    assert_eq!(alice.titles(), ["wifi"]);
    assert_eq!(carol.check_in(&[&alice]), (1, 0, 0));
    assert_eq!(carol.titles(), ["wifi"]);
    assert_eq!(
        carol.check_in(&[&alice]),
        (0, 0, 0),
        "nothing left to trade"
    );
}

#[test]
fn edits_and_deletions_flow_the_other_way_too() {
    let [alice, bob, _] = trio();
    let id = alice.edit(Edit::Create(titled("one"))).unwrap();
    assert_eq!(bob.check_in(&[&alice]), (1, 0, 0));
    bob.edit(Edit::Update(id, titled("two"))).unwrap();
    assert_eq!(alice.check_in(&[&bob]), (1, 0, 0));
    assert_eq!(alice.titles(), ["two"]);
    alice.edit(Edit::Delete(id)).unwrap();
    assert_eq!(bob.check_in(&[&alice]), (1, 0, 0));
    assert!(bob.titles().is_empty());
}

#[test]
fn a_readers_forged_record_is_refused_over_the_wire() {
    let [alice, _, carol] = trio();
    assert!(carol.edit(Edit::Create(titled("sneaky"))).is_err());
    carol
        .provider
        .with_vault(&carol.reference.vault_id, |vault, reference, identity| {
            write_record(
                &mut vault.session,
                &mut vault.file,
                Some(77),
                &titled("forged"),
            )?;
            let (attestation, _) = attest_latest(
                &vault.session,
                &identity.sign_key(),
                &identity.devices()[0],
                77,
            )?;
            vault.attest.put(attestation)?;
            vault.persist(&reference.seed)
        })
        .unwrap();
    let (pulled, pushed, refused) = carol.check_in(&[&alice]);
    assert_eq!((pulled, pushed), (0, 0));
    assert_eq!(refused, 1);
    assert!(alice.titles().is_empty());
}

#[test]
fn a_member_that_calls_in_is_found_again_without_being_told_where() {
    let [alice, bob, _] = trio();
    bob.edit(Edit::Create(titled("wifi"))).unwrap();
    assert_eq!(bob.check_in(&[&alice]), (0, 1, 0));
    // Alice was given no address for Bob, yet she can reach him now.
    let id = alice.edit(Edit::Create(titled("bank"))).unwrap();
    assert_ne!(id, 0);
    assert_eq!(alice.check_in(&[]), (0, 1, 0));
    assert_eq!(bob.titles(), ["bank", "wifi"]);
}

#[test]
fn a_member_learns_of_others_from_a_member_it_knows() {
    let [alice, bob, carol] = trio();
    assert_eq!(bob.check_in(&[&alice]), (0, 0, 0));
    bob.edit(Edit::Create(titled("wifi"))).unwrap();
    // Carol only knows Alice. Alice has nothing from Bob, so the record can
    // only have come from Bob himself, whom Carol found through Alice.
    assert_eq!(carol.check_in(&[&alice]), (1, 0, 0));
    assert_eq!(carol.titles(), ["wifi"]);
}

#[test]
fn addresses_signed_by_an_outsider_are_not_kept() {
    let [alice, ..] = trio();
    let outsider = SyncIdentity::enroll(&[9; 64], &[9; 64], [9; 16], u64::MAX).unwrap();
    let record = session::PeerRecord::sign(
        &outsider.sign_key(),
        &outsider.devices()[0],
        alice.reference.vault_id,
        vec!["10.6.6.6:7447".to_owned()],
        p2p_net::now_ms(),
    )
    .unwrap();
    let list = syncwire::encode_peers(&[record]).unwrap();
    let log = local::read_member_log(&alice.base, &alice.reference).unwrap();
    let book = PeerBook::default();
    assert_eq!(book.accept(&log, &[0; 16], &[], &list), 0);
    assert!(book.hints(&log).is_empty());
}

#[test]
fn a_member_cannot_aim_this_device_at_addresses_that_are_not_peers() {
    let [alice, bob, _] = trio();
    let log = local::read_member_log(&alice.base, &alice.reference).unwrap();
    let book = PeerBook::default();
    book.set_own(vec!["192.168.1.5:7447".to_owned()]);
    let offer_to = |book: &PeerBook, hint: &str| {
        let record = session::PeerRecord::sign(
            &bob.id.sign_key(),
            &bob.id.devices()[0],
            alice.reference.vault_id,
            vec![hint.to_owned()],
            p2p_net::now_ms(),
        )
        .unwrap();
        let list = syncwire::encode_peers(&[record]).unwrap();
        book.accept(&log, &[0; 16], &[], &list)
    };
    let offer = |hint: &str| offer_to(&book, hint);
    for refused in [
        "127.0.0.1:7447",
        "[::1]:7447",
        "169.254.169.254:80",
        "0.0.0.0:7447",
        "224.0.0.1:7447",
        "[ff02::1]:7447",
        "[fe80::1]:7447",
        "255.255.255.255:7447",
        "198.51.100.7:7447",
        "192.168.1.9:0",
        "10.0.0.8:7447",
        "172.16.0.9:7447",
        "[::ffff:127.0.0.1]:7447",
        "[::ffff:10.1.2.3]:7447",
        "[fd00::1]:7447",
    ] {
        assert_eq!(offer(refused), 0, "{refused} must not be dialed");
        assert!(book.hints(&log).is_empty(), "{refused}");
    }
    assert_eq!(offer("192.168.200.3:7447"), 1, "same private network");
    assert_eq!(
        offer_to(&PeerBook::default(), "93.184.216.34:7447"),
        1,
        "a public address is fine"
    );
}

#[test]
fn loopback_and_foreign_private_networks_depend_on_the_policy() {
    use p2p_net::Policy;
    let none: [std::net::SocketAddr; 0] = [];
    let lan: std::net::SocketAddr = "192.168.1.5:7447".parse().unwrap();
    let at = |text: &str| text.parse::<std::net::SocketAddr>().unwrap();
    assert!(!Policy::default().allows(&at("127.0.0.1:1"), &none));
    assert!(Policy { loopback: true }.allows(&at("127.0.0.1:1"), &none));
    assert!(Policy::default().allows(&at("93.184.216.34:443"), &none));
    assert!(Policy::default().allows(&at("[2606:2800:220:1::1]:443"), &none));
    assert!(!Policy::default().allows(&at("192.168.7.7:1"), &none));
    assert!(Policy::default().allows(&at("192.168.7.7:1"), &[lan]));
    assert!(!Policy::default().allows(&at("10.1.1.1:1"), &[lan]));
    assert!(
        !Policy::default().allows(&at("100.64.0.1:1"), &none),
        "carrier-grade NAT is shared space"
    );
    assert!(
        Policy::default().allows(&at("100.115.92.2:7447"), &[at("100.64.0.1:7447")]),
        "Tailscale / WireGuard CGNAT 100.64.0.0/10 peers share a network"
    );
    assert!(
        Policy::default().allows(&at("10.240.1.2:7447"), &[at("10.0.0.1:7447")]),
        "RFC 1918 10.0.0.0/8 peers share a network"
    );
    assert!(
        Policy::default().allows(&at("172.31.9.9:7447"), &[at("172.16.0.1:7447")]),
        "RFC 1918 172.16.0.0/12 peers share a network"
    );
    assert!(Policy::default().allows(&at("[fd12:3456:789a::2]:1"), &[at("[fd12:3456:789a::9]:1")]));
}

fn restarted(node: &Node) -> Arc<SharedProvider> {
    let provider = Arc::new(SharedProvider::new(node.base.clone(), Arc::clone(&node.id)));
    provider.allow_loopback_peers();
    provider.serve(Arc::new(node.reference.duplicate()));
    provider
}

#[test]
fn peer_addresses_survive_a_restart() {
    use p2p_net::Provider;
    let [alice, bob, _] = trio();
    assert_eq!(bob.check_in(&[&alice]), (0, 0, 0));
    let vault = alice.reference.vault_id;
    assert_eq!(
        alice.provider.peer_hints(&vault),
        std::slice::from_ref(&bob.addr)
    );

    let after = restarted(&alice);
    assert_eq!(
        after.peer_hints(&vault),
        std::slice::from_ref(&bob.addr),
        "found again without being told where"
    );
}

#[test]
fn a_damaged_or_foreign_peer_file_is_ignored_and_the_search_starts_over() {
    use p2p_net::Provider;
    let [alice, bob, _] = trio();
    assert_eq!(bob.check_in(&[&alice]), (0, 0, 0));
    let vault = alice.reference.vault_id;
    let file = local::shared_paths_for(&alice.base, &vault).peers_store();
    let good = fs::read(&file).unwrap();

    let mut flipped = good.clone();
    let middle = flipped.len() / 2;
    flipped[middle] ^= 1;
    fs::write(&file, &flipped).unwrap();
    assert!(restarted(&alice).peer_hints(&vault).is_empty());

    fs::write(&file, &good[..good.len() / 2]).unwrap();
    assert!(restarted(&alice).peer_hints(&vault).is_empty());

    fs::remove_file(&file).unwrap();
    assert!(restarted(&alice).peer_hints(&vault).is_empty());

    fs::write(&file, &good).unwrap();
    assert_eq!(
        restarted(&alice).peer_hints(&vault),
        std::slice::from_ref(&bob.addr)
    );
}

#[test]
fn stored_addresses_are_checked_again_when_they_come_back() {
    use p2p_net::Provider;
    let [alice, bob, _] = trio();
    assert_eq!(bob.check_in(&[&alice]), (0, 0, 0));
    let vault = alice.reference.vault_id;
    // The same file read by a device that does not allow loopback holds no
    // usable address, whatever was written down.
    let strict = Arc::new(SharedProvider::new(
        alice.base.clone(),
        Arc::clone(&alice.id),
    ));
    strict.serve(Arc::new(alice.reference.duplicate()));
    assert!(strict.peer_hints(&vault).is_empty());
}

#[test]
fn a_leave_counts_as_delivered_when_a_member_fetches_the_log() {
    let [alice, bob, _] = trio();
    let vault = alice.reference.vault_id;
    assert_eq!(alice.check_in(&[&bob]), (0, 0, 0));
    assert!(
        bob.provider.take_delivered().is_empty(),
        "a member that has not left delivers nothing"
    );

    bob.provider
        .with_vault(&vault, |vault, reference, identity| {
            vault.leave(reference, identity)
        })
        .unwrap();
    assert!(
        bob.provider.take_delivered().is_empty(),
        "not before it is fetched"
    );

    assert_eq!(alice.check_in(&[&bob]), (0, 0, 0));
    assert_eq!(bob.provider.take_delivered(), [vault]);
    assert!(bob.provider.take_delivered().is_empty(), "once");
    let log = local::read_member_log(&alice.base, &alice.reference).unwrap();
    assert_eq!(log.role_of(&bob.id.devices()[0].client_id), None);

    bob.provider.unserve(&vault);
    assert!(p2p_net::Provider::log(&*bob.provider, &vault).is_none());
}

fn random_below(bound: usize) -> usize {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).unwrap();
    usize::try_from(u64::from_be_bytes(bytes) % u64::try_from(bound).unwrap()).unwrap()
}

fn frontier_of(node: &Node) -> Vec<u8> {
    open_shared_vault(&node.base, &node.reference, &node.id)
        .unwrap()
        .frontier_wire()
        .unwrap()
}

/// Three nodes edit at random and trade changes for a while, then settle on
/// the same records. Run with
/// `cargo test --release -p p2p-net --test ongoing -- --ignored` (a debug build
/// does a handful of check-ins a minute);
/// `ZP_SOAK_SECS` sets how long the editing lasts (default 30).
#[test]
#[ignore = "soak test: run on request"]
fn three_nodes_editing_at_random_settle_on_the_same_vault() {
    let seconds: u64 = std::env::var("ZP_SOAK_SECS")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(30);
    let nodes = trio();
    let [alice, bob, carol] = &nodes;
    let everyone = [alice, bob, carol];
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let (mut made, mut changed, mut removed, mut rounds) = (0usize, 0usize, 0usize, 0usize);
    let mut ids: Vec<u32> = Vec::new();
    while Instant::now() < deadline {
        let writer = [alice, bob][random_below(2)];
        match random_below(10) {
            0..=4 => {
                if let Ok(id) = writer.edit(Edit::Create(titled(&format!("record {made}")))) {
                    ids.push(id);
                    made += 1;
                }
            }
            5..=7 if !ids.is_empty() => {
                let id = ids[random_below(ids.len())];
                changed += usize::from(
                    writer
                        .edit(Edit::Update(id, titled(&format!("edit {changed}"))))
                        .is_ok(),
                );
            }
            8 if !ids.is_empty() => {
                let id = ids.swap_remove(random_below(ids.len()));
                removed += usize::from(writer.edit(Edit::Delete(id)).is_ok());
            }
            _ => {}
        }
        let from = everyone[random_below(3)];
        let to: Vec<&Node> = everyone
            .iter()
            .copied()
            .filter(|node| node.addr != from.addr)
            .collect();
        from.check_in(&to);
        rounds += 1;
    }

    for _ in 0..8 {
        for node in everyone {
            let others: Vec<&Node> = everyone
                .iter()
                .copied()
                .filter(|other| other.addr != node.addr)
                .collect();
            node.check_in(&others);
        }
        if frontier_of(alice) == frontier_of(bob) && frontier_of(bob) == frontier_of(carol) {
            break;
        }
    }
    assert_eq!(frontier_of(alice), frontier_of(bob));
    assert_eq!(frontier_of(bob), frontier_of(carol));
    assert_eq!(alice.titles(), bob.titles());
    assert_eq!(bob.titles(), carol.titles());
    println!("soak: {made} created, {changed} edited, {removed} deleted, {rounds} check-ins");
    assert!(made > 0 && rounds > 0);
}

#[test]
fn an_advertised_address_reaches_the_members_ahead_of_the_others() {
    use p2p_net::Provider;
    let [alice, bob, _] = trio();
    let vault = alice.reference.vault_id;
    let public = String::from("93.184.216.34:7447");
    bob.provider
        .set_hints(vec![public.clone(), bob.addr.clone()]);
    assert_eq!(bob.check_in(&[&alice]), (0, 0, 0));
    assert_eq!(
        alice.provider.peer_hints(&vault),
        [public, bob.addr],
        "the advertised address comes first and both are kept"
    );
}

#[test]
fn a_check_in_learns_the_address_a_member_sees() {
    let [alice, bob, _] = trio();
    bob.service.check_in(
        Arc::clone(&bob.provider),
        bob.reference.vault_id,
        vec![alice.addr],
    );
    let mut seen = None;
    loop {
        match bob.service.events().recv_timeout(WAIT).unwrap() {
            Event::Observed(address) => seen = Some(address),
            Event::Synced { .. } => break,
            Event::FetchFailed { reason, .. } => panic!("check-in failed: {reason}"),
            _ => {}
        }
    }
    let seen = seen.expect("the member said what it sees");
    assert!(seen.ip().is_loopback(), "{seen}");
    assert_ne!(seen.port(), 0);
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

#[test]
fn a_stale_push_is_answered_stale_never_counts_as_a_failure_and_a_newer_one_needs_no_base() {
    let [alice, bob, _] = trio();
    let id = bob.edit(Edit::Create(titled("one"))).unwrap();
    let vault = bob.reference.vault_id;
    let first = bob.provider.revision(&vault, id).unwrap();
    let view = bob.provider.view_for(&bob.reference).unwrap();
    block_on(async {
        let mut conn = Conn::connect(&view, &alice.addr).await.unwrap();
        assert_eq!(
            conn.push(vec![first.clone()]).await.unwrap(),
            [Push::Applied]
        );
        // Far more than the failure budget (32): stale is not a failure.
        for _ in 0..40 {
            assert_eq!(conn.push(vec![first.clone()]).await.unwrap(), [Push::Stale]);
        }
        // A newer revision of the same record lands in one step: a frame
        // replaces the record whole, so there is no base to fetch first.
        bob.edit(Edit::Update(id, titled("two"))).unwrap();
        let second = bob.provider.revision(&vault, id).unwrap();
        assert_eq!(
            conn.push(vec![second.clone()]).await.unwrap(),
            [Push::Applied]
        );
        assert_eq!(conn.push(vec![first]).await.unwrap(), [Push::Stale]);
        assert_eq!(conn.push(vec![second]).await.unwrap(), [Push::Stale]);
    });
    assert_eq!(alice.titles(), ["two"]);
}

/// A peer that advertises everything and gives nothing.
struct Stubborn {
    inner: Arc<SharedProvider>,
    wanted: std::sync::atomic::AtomicUsize,
}

impl Provider for Stubborn {
    fn views(&self) -> Vec<p2p_net::VaultView> {
        self.inner.views()
    }
    fn log(&self, vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        self.inner.log(vault_id)
    }
    fn snapshot_source(&self, vault_id: &[u8; 16]) -> Option<SnapshotSource> {
        self.inner.snapshot_source(vault_id)
    }
    fn frontier(&self, vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        self.inner.frontier(vault_id)
    }
    fn revision(&self, _vault_id: &[u8; 16], _record_id: u32) -> Option<Vec<u8>> {
        self.wanted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        None
    }
    fn peers(&self, vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        self.inner.peers(vault_id)
    }
}

#[test]
fn a_stubborn_peer_is_asked_once_per_record_per_check_in_and_never_in_a_loop() {
    let [alice, bob, _] = trio();
    for title in ["a", "b", "c"] {
        alice.edit(Edit::Create(titled(title))).unwrap();
    }
    let stubborn = Arc::new(Stubborn {
        inner: Arc::clone(&alice.provider),
        wanted: std::sync::atomic::AtomicUsize::new(0),
    });
    let node = Service::start(Some("127.0.0.1:0"), Arc::clone(&stubborn)).unwrap();
    let hint = node.local_addr().unwrap().to_string();
    let ask = || {
        bob.service.check_in(
            Arc::clone(&bob.provider),
            bob.reference.vault_id,
            vec![hint.clone()],
        );
        loop {
            match bob.service.events().recv_timeout(WAIT).unwrap() {
                Event::Synced { pulled, .. } => return pulled,
                Event::FetchFailed { reason, .. } => panic!("check-in failed: {reason}"),
                _ => {}
            }
        }
    };
    // The check-in also follows the addresses it has learned, so the owner
    // supplies what the stubborn peer withholds.
    assert_eq!(ask(), 3);
    let wanted = || stubborn.wanted.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        wanted(),
        3,
        "each record asked for once, no retry in the check-in"
    );
    assert_eq!(ask(), 0);
    assert_eq!(wanted(), 3, "nothing missing, nothing asked");
    alice.edit(Edit::Create(titled("d"))).unwrap();
    assert_eq!(ask(), 1);
    assert_eq!(wanted(), 4, "the one new record, once");
    assert_eq!(frontier_of(&bob), frontier_of(&alice));
}

#[test]
fn a_member_that_was_away_ends_with_the_same_frontier_through_any_member() {
    let [alice, bob, carol] = trio();
    let one = alice.edit(Edit::Create(titled("one"))).unwrap();
    alice.edit(Edit::Create(titled("two"))).unwrap();
    assert_eq!(bob.check_in(&[&alice]), (2, 0, 0));
    bob.edit(Edit::Update(one, titled("uno"))).unwrap();
    bob.edit(Edit::Create(titled("three"))).unwrap();
    assert_eq!(alice.check_in(&[&bob]), (2, 0, 0));
    // Carol was never reachable for any of it, and now asks only Bob.
    assert_eq!(carol.check_in(&[&bob]).0, 3);
    assert_eq!(frontier_of(&carol), frontier_of(&alice));
    assert_eq!(frontier_of(&carol), frontier_of(&bob));
    assert_eq!(carol.titles(), ["three", "two", "uno"]);
}

#[test]
fn a_check_in_tries_direct_addresses_first_and_then_the_relay_slot() {
    use p2p_net::{Relay, RelayLimits};
    let [alice, bob, _] = trio();
    alice.edit(Edit::Create(titled("wifi"))).unwrap();
    let relay = Relay::start(
        "127.0.0.1:0",
        RelayLimits {
            difficulty_idle: 4,
            ..RelayLimits::default()
        },
    )
    .unwrap();
    // Alice is reachable only through a slot; the direct address in the list
    // leads nowhere.
    let behind = Service::start(None, Arc::clone(&alice.provider)).unwrap();
    assert!(behind.hold_relay(Arc::clone(&alice.provider), relay.local_addr()));
    let hint = loop {
        if let Event::Relayed(hint) = behind.events().recv_timeout(WAIT).unwrap() {
            break hint;
        }
    };
    let hints = vec![hint.to_string(), "127.0.0.1:9".to_owned()];
    bob.service
        .check_in(Arc::clone(&bob.provider), bob.reference.vault_id, hints);
    let pulled = loop {
        match bob.service.events().recv_timeout(WAIT).unwrap() {
            Event::Synced { pulled, .. } => break pulled,
            Event::FetchFailed { reason, .. } => panic!("check-in failed: {reason}"),
            _ => {}
        }
    };
    assert_eq!(pulled, 1);
    assert_eq!(bob.titles(), ["wifi"]);
    assert_eq!(frontier_of(&bob), frontier_of(&alice));
    assert!(relay.stats().spliced >= 1, "the slot was the way in");
}
