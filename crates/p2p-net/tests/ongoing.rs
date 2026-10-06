#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::panic,
    reason = "tests may unwrap and index"
)]

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use local::{
    adopt_shared_file, create_shared_vault, join_shared_vault, open_shared_vault, Edit, SharedRef,
    SyncIdentity,
};
use memberlog::{Action, Role};
use p2p_net::{Event, Service, SharedProvider};
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
    let mut nodes = Vec::new();
    for (index, id) in ids.into_iter().enumerate() {
        let reference = Arc::new(alice_ref.duplicate());
        if index > 0 {
            join_shared_vault(&dirs[index], &reference, &alice.log).unwrap();
            adopt_shared_file(
                &dirs[index],
                &reference,
                VaultFile::new(alice.file.as_bytes().to_vec()),
                &id,
            )
            .unwrap();
        }
        let provider = Arc::new(SharedProvider::new(dirs[index].clone(), Arc::clone(&id)));
        provider.serve(Arc::clone(&reference));
        let service = Service::start(Some("127.0.0.1:0"), Arc::clone(&provider)).unwrap();
        let addr = service.local_addr().unwrap().to_string();
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
