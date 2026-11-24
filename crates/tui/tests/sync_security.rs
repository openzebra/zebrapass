//! TUI security regression tests:
//! 1. Untrusted shared-vault invitation `hints` never start `ZebraSync` under
//!    `--no-server-sync` and never override personal sync endpoints.
//! 2. Deleted personal records never resurrect across snapshot merges or
//!    `Op::ClearHistory` + frame replay (`SyncIdentity.last_seen`).
//! 3. End-to-end TUI shared-vault member removal across an authenticated
//!    3-server `zsync` mesh (`Listen::Off`, zero P2P) transitions remaining
//!    members to the new key and cuts off the removed member.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "integration tests use concise setup and assertions"
)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use record::{Document, TAG_TITLE};
use secret::Secret;
use session::{SYNC_VK_LEN, sync_verifying_key};
use sharing::{ContactCard, Invitation, Inviter, Offer};
use tui::App;
use tui::app::ctx::Task;
use tui::app::flows::home::Filter;
use tui::app::flows::share::{ShareState, Step};
use tui::app::flows::unlocked::View;
use tui::app::screen::Screen;
use tui::cli::Flags;
use tui::vault::ops::Op;
use zsync::{
    MeshAuthConfig, MeshPeer, RepoStore, ZebraServerConfig, ZebraServerHandle, start_server,
};

struct TestServer {
    rt: tokio::runtime::Runtime,
    handle: Option<ZebraServerHandle>,
    endpoint: String,
    ca_path: PathBuf,
    data_dir: PathBuf,
    dir: PathBuf,
}

impl TestServer {
    fn start(
        tag: &str,
        ca_pem: &[u8],
        cert_pem: &[u8],
        key_pem: &[u8],
        mesh_seed: [u8; 32],
        allowed_vks: Vec<[u8; SYNC_VK_LEN]>,
        peers: Vec<MeshPeer>,
    ) -> Self {
        let dir = common::temp_dir(&format!("sec-srv-{tag}"));
        let ca_path = dir.join("ca.crt");
        let data_dir = dir.join("data");
        std::fs::write(&ca_path, ca_pem).unwrap();

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let handle = rt
            .block_on(start_server(ZebraServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                cert_pem: cert_pem.to_vec(),
                key_pem: Secret::new(key_pem.to_vec()),
                extra_ca_pem: Some(ca_pem.to_vec()),
                data_dir: data_dir.clone(),
                mesh: Some(MeshAuthConfig {
                    seed: Secret::new(mesh_seed),
                    peers,
                    allowed_vks,
                }),
                mesh_interval: Duration::from_millis(100),
                allow_private: true,
            }))
            .unwrap();
        let endpoint = handle.endpoint.to_string();
        Self {
            rt,
            handle: Some(handle),
            endpoint,
            ca_path,
            data_dir,
            dir,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.rt.block_on(handle.stop());
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run_openssl(args: &[&str]) {
    let out = Command::new("/usr/bin/openssl")
        .args(args)
        .output()
        .expect("run /usr/bin/openssl");
    assert!(out.status.success());
}

fn generate_test_pki(dir: &Path) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let ca_key = dir.join("ca.key");
    let ca_crt = dir.join("ca.crt");
    let ca_cnf = dir.join("ca.cnf");
    let leaf_key = dir.join("leaf.key");
    let leaf_csr = dir.join("leaf.csr");
    let leaf_ext = dir.join("leaf.ext");
    let leaf_crt = dir.join("leaf.crt");

    std::fs::write(
        &ca_cnf,
        "[req]\ndistinguished_name = dn\nx509_extensions = v3_ca\nprompt = no\n\
         [dn]\nCN = ZebraPass TUI Sec CA\n\
         [v3_ca]\nbasicConstraints = critical, CA:TRUE\n\
         keyUsage = critical, keyCertSign, cRLSign\n\
         subjectKeyIdentifier = hash\n",
    )
    .unwrap();
    run_openssl(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        ca_key.to_str().unwrap(),
    ]);
    run_openssl(&[
        "req",
        "-x509",
        "-new",
        "-nodes",
        "-key",
        ca_key.to_str().unwrap(),
        "-sha256",
        "-days",
        "7",
        "-config",
        ca_cnf.to_str().unwrap(),
        "-out",
        ca_crt.to_str().unwrap(),
    ]);
    run_openssl(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        leaf_key.to_str().unwrap(),
    ]);
    run_openssl(&[
        "req",
        "-new",
        "-key",
        leaf_key.to_str().unwrap(),
        "-subj",
        "/CN=localhost",
        "-out",
        leaf_csr.to_str().unwrap(),
    ]);
    std::fs::write(
        &leaf_ext,
        "basicConstraints = CA:FALSE\n\
         keyUsage = critical, digitalSignature, keyEncipherment\n\
         extendedKeyUsage = serverAuth\n\
         subjectAltName = DNS:localhost,IP:127.0.0.1\n",
    )
    .unwrap();
    run_openssl(&[
        "x509",
        "-req",
        "-in",
        leaf_csr.to_str().unwrap(),
        "-CA",
        ca_crt.to_str().unwrap(),
        "-CAkey",
        ca_key.to_str().unwrap(),
        "-CAcreateserial",
        "-out",
        leaf_crt.to_str().unwrap(),
        "-days",
        "7",
        "-sha256",
        "-extfile",
        leaf_ext.to_str().unwrap(),
    ]);

    (
        std::fs::read(&ca_crt).unwrap(),
        std::fs::read(&leaf_crt).unwrap(),
        std::fs::read(&leaf_key).unwrap(),
    )
}

fn titled(title: &str) -> Document {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, title);
    doc
}

fn share_state(app: &App) -> &ShareState {
    let View::Sync(share) = &common::unlocked_state(app).view else {
        panic!("not on share screen");
    };
    share
}

fn app_with_server(base: &Path, srv: &TestServer) -> App {
    let mut cfg = common::config(base);
    cfg.flags = cfg.flags.with(Flags::ALLOW_PRIVATE_SYNC, true);
    cfg.sync_servers = vec![srv.endpoint.clone().into_boxed_str()];
    cfg.extra_ca = Some(srv.ca_path.clone());
    common::app_with(&cfg, base, common::CAPS)
}

fn pump_three(
    a: &mut App,
    b: &mut App,
    c: &mut App,
    within: Duration,
    done: impl Fn(&App, &App, &App) -> bool,
) -> bool {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if done(a, b, c) {
            return true;
        }
        for app in [&mut *a, &mut *b, &mut *c] {
            common::tick(app, Duration::from_millis(220));
            if app.ctx.busy() {
                let _ = app.wait_for_job(Duration::from_millis(40));
            }
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    done(a, b, c)
}

#[test]
fn external_shared_invitation_hints_never_start_zsync_or_override_endpoints() {
    let pki_dir = common::temp_dir("hints-pki");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&pki_dir);
    let rogue_srv = TestServer::start(
        "rogue-hint",
        &ca_pem,
        &cert_pem,
        &key_pem,
        [0x81; 32],
        Vec::new(),
        Vec::new(),
    );

    let dir_victim = common::temp_dir("hints-victim");
    let dir_att = common::temp_dir("hints-att");
    common::make_vault(&dir_victim);
    common::make_vault(&dir_att);
    common::sync_off_with(&dir_victim, common::PASSWORD);
    common::sync_off_with(&dir_att, common::PASSWORD);

    // Victim runs with NET_SYNC = false (--no-server-sync) and ALLOW_PRIVATE_SYNC = true
    // + trusts rogue CA, so ONLY resolve_sync_servers prevents dialing the hint!
    let mut vic_cfg = common::config(&dir_victim);
    vic_cfg.flags = vic_cfg
        .flags
        .with(Flags::NET_SYNC, false)
        .with(Flags::ALLOW_PRIVATE_SYNC, true);
    vic_cfg.extra_ca = Some(rogue_srv.ca_path.clone());
    let mut victim = common::app_with(&vic_cfg, &dir_victim, common::CAPS);
    common::unlock(&mut victim, common::PASSWORD);
    assert!(common::unlocked_state(&victim).zsync.is_none());

    common::press(&mut victim, KeyCode::Char('S'));
    let victim_card_str = share_state(&victim).me.as_ref().unwrap().text.to_string();
    let victim_card = ContactCard::from_text(&victim_card_str).unwrap();

    // Attacker creates a shared vault and crafts an invitation embedding `https://<rogue_srv>`!
    let mut attacker = common::app(&dir_att);
    common::unlock(&mut attacker, common::PASSWORD);
    common::press(&mut attacker, KeyCode::Char('S'));
    common::press(&mut attacker, KeyCode::Char('n'));
    common::type_text(&mut attacker, "Trap Vault");
    common::press(&mut attacker, KeyCode::Enter);
    common::wait(&mut attacker);

    let att_state = common::unlocked_state(&attacker);
    let att_id = att_state.identity.as_ref().unwrap();
    let att_ref = &att_state.shared[0].reference;
    let tui::vault::shared::Status::Ready(att_sv) = &att_state.shared[0].status else {
        panic!("expected ready");
    };
    let own_cert = att_id.devices()[0].clone();
    let sign_key = att_id.sign_key();
    let mut att_log = memberlog::MemberLog::from_entries(
        att_ref.vault_id,
        att_sv.log.entries(),
        att_sv.log.anchor(),
    )
    .unwrap();
    let add_entry = att_log
        .propose(
            &sign_key,
            &own_cert,
            memberlog::Action::Add {
                client_id: victim_card.cert.client_id,
                root_vk: victim_card.root_vk.clone(),
                role: memberlog::Role::Writer,
            },
            tui::vault::create::unix_ms(),
        )
        .unwrap();
    att_log.append(add_entry).unwrap();
    let malicious_hints = vec![format!("https://{}", rogue_srv.endpoint)];
    let malicious_invite = Invitation::issue(
        &Inviter {
            sign: &sign_key,
            cert: &own_cert,
        },
        &att_log,
        &victim_card,
        &Offer {
            seed: &att_ref.seed,
            name: "Trap Vault",
            hints: &malicious_hints,
        },
        tui::vault::create::unix_ms(),
    )
    .unwrap()
    .to_text()
    .unwrap();

    // Victim pastes the invitation with the malicious `https://` hint.
    common::press(&mut victim, KeyCode::Char('j'));
    victim.on_paste(&malicious_invite);
    common::press(&mut victim, KeyCode::Enter);
    common::wait(&mut victim);
    for _ in 0..8 {
        common::tick(&mut victim, Duration::from_millis(100));
        std::thread::sleep(Duration::from_millis(30));
    }

    assert!(
        common::unlocked_state(&victim).zsync.is_none(),
        "external shared-vault hints must NEVER start ZebraSync or override --no-server-sync"
    );
    let rogue_store = RepoStore::open(&rogue_srv.data_dir).unwrap();
    assert_eq!(
        rogue_store.repo_count(),
        0,
        "rogue hint server must receive zero connections/repos from victim"
    );

    let _ = std::fs::remove_dir_all(&dir_victim);
    let _ = std::fs::remove_dir_all(&dir_att);
    let _ = std::fs::remove_dir_all(&pki_dir);
}

#[test]
fn deleted_personal_records_never_resurrect_after_clear_history_or_snapshot_sync() {
    let pki_dir = common::temp_dir("tomb-pki");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&pki_dir);
    let srv = TestServer::start(
        "tomb",
        &ca_pem,
        &cert_pem,
        &key_pem,
        [0x82; 32],
        Vec::new(),
        Vec::new(),
    );

    let dir_a = common::temp_dir("tomb-a");
    let words = common::make_vault(&dir_a);
    common::sync_off_with(&dir_a, common::PASSWORD);
    let mut app_a = app_with_server(&dir_a, &srv);
    common::unlock(&mut app_a, common::PASSWORD);

    if let Screen::Unlocked(state) = &mut app_a.screen {
        state.run(
            Op::Write {
                id: None,
                doc: Box::new(titled("Keep Alive")),
            },
            Task::Save,
            &mut app_a.ctx,
        );
    }
    common::wait(&mut app_a);
    if let Screen::Unlocked(state) = &mut app_a.screen {
        state.run(
            Op::Write {
                id: None,
                doc: Box::new(titled("Burn After Reading")),
            },
            Task::Save,
            &mut app_a.ctx,
        );
    }
    common::wait(&mut app_a);

    let burn_id = common::unlocked_state(&app_a)
        .cache
        .iter()
        .find(|r| &*r.title == "Burn After Reading")
        .unwrap()
        .id;
    let stale_frame = session::latest_frame(
        &common::unlocked_state(&app_a)
            .vault
            .as_ref()
            .unwrap()
            .session,
        burn_id,
    )
    .unwrap();

    // Clone onto Device B while "Burn After Reading" is still live.
    let until = Instant::now() + Duration::from_secs(15);
    while Instant::now() < until {
        common::tick(&mut app_a, Duration::from_millis(200));
        if common::unlocked_state(&app_a)
            .zsync
            .as_ref()
            .is_some_and(|z| z.last_sync_ms.is_some())
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(30));
    }

    let dir_b = common::temp_dir("tomb-b");
    let mut app_b = app_with_server(&dir_b, &srv);
    common::open_restore(&mut app_b);
    common::type_phrase(&mut app_b, &words);
    common::press(&mut app_b, KeyCode::Enter);
    common::type_text(&mut app_b, common::PASSWORD);
    common::press(&mut app_b, KeyCode::Tab);
    common::type_text(&mut app_b, common::PASSWORD);
    common::press(&mut app_b, KeyCode::Enter);
    common::wait(&mut app_b);

    let adopt_deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < adopt_deadline {
        common::tick(&mut app_b, Duration::from_millis(200));
        if app_b.ctx.busy() {
            let _ = app_b.wait_for_job(Duration::from_millis(40));
        }
        if !common::is_placeholder(&app_b)
            && common::titles_of(&app_b).contains(&String::from("Burn After Reading"))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    assert!(common::titles_of(&app_b).contains(&String::from("Burn After Reading")));

    // 1. Device A deletes "Burn After Reading" and syncs: Device B receives the
    //    KIND_TOMBSTONE frame over zsync and removes it.
    if let Screen::Unlocked(state) = &mut app_a.screen {
        state.run(Op::Delete(burn_id), Task::Save, &mut app_a.ctx);
    }
    common::wait(&mut app_a);

    let del_deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < del_deadline {
        common::tick(&mut app_a, Duration::from_millis(200));
        common::tick(&mut app_b, Duration::from_millis(200));
        if !common::titles_of(&app_b).contains(&String::from("Burn After Reading")) {
            break;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    assert!(
        !common::titles_of(&app_b).contains(&String::from("Burn After Reading")),
        "tombstone deletion must propagate over zsync to Device B"
    );

    // 2. Device A compacts tombstones out of vault.brby via ClearHistory, syncs
    //    again, and even if Device B triggers a new SignedHead snapshot or an
    //    attacker replays stale_frame (rev 1), "Burn After Reading" never resurrects!
    if let Screen::Unlocked(state) = &mut app_a.screen {
        state.run(Op::ClearHistory, Task::Save, &mut app_a.ctx);
    }
    common::wait(&mut app_a);
    for _ in 0..8 {
        common::tick(&mut app_a, Duration::from_millis(200));
        common::tick(&mut app_b, Duration::from_millis(200));
        std::thread::sleep(Duration::from_millis(30));
    }
    assert!(!common::titles_of(&app_a).contains(&String::from("Burn After Reading")));
    assert!(!common::titles_of(&app_b).contains(&String::from("Burn After Reading")));

    // Even after ClearHistory removed the tombstone from vault.brby on Device A,
    // replaying stale_frame via session::accept_peer_frame_seen with SyncIdentity.last_seen
    // must be rejected!
    {
        let st_a = common::unlocked_state(&app_a);
        let vault_a = st_a.vault.as_ref().unwrap();
        let id_key = vault_a.session.sync_identity_key().unwrap();
        let stored_id = local::SyncIdentity::load(&vault_a.paths.sync_identity(), &id_key).unwrap();
        assert!(
            stored_id.last_seen().get(burn_id).unwrap_or(0) >= 2,
            "SyncIdentity.last_seen must retain deleted record revision across ClearHistory"
        );
        let mut trial_file = session::VaultFile::new(vault_a.file.as_bytes().to_vec());
        let mut trial_sess =
            session::unlock_with_key(&trial_file, &vault_a.session.reopen_key(), [0x11; 16])
                .unwrap();
        assert!(
            session::accept_peer_frame_seen(&mut trial_sess, &mut trial_file, &stale_frame, |id| {
                stored_id.last_seen().get(id)
            })
            .is_err(),
            "replayed pre-deletion frame after ClearHistory must be rejected"
        );
    }

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
    let _ = std::fs::remove_dir_all(&pki_dir);
}

#[test]
fn tui_shared_vault_member_removal_over_zsync_mesh_transitions_member_and_cuts_off_removed_user() {
    let pki_dir = common::temp_dir("mesh-rm-pki");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&pki_dir);

    let seed_alpha = [0x91; 32];
    let seed_bravo = [0x92; 32];
    let seed_delta = [0x93; 32];
    let vk_alpha: [u8; SYNC_VK_LEN] = sync_verifying_key(&seed_alpha).unwrap().try_into().unwrap();
    let vk_bravo: [u8; SYNC_VK_LEN] = sync_verifying_key(&seed_bravo).unwrap().try_into().unwrap();
    let vk_delta: [u8; SYNC_VK_LEN] = sync_verifying_key(&seed_delta).unwrap().try_into().unwrap();

    let node_alpha = TestServer::start(
        "alpha",
        &ca_pem,
        &cert_pem,
        &key_pem,
        seed_alpha,
        vec![vk_bravo, vk_delta],
        Vec::new(),
    );
    let peer_alpha = MeshPeer {
        endpoint: node_alpha.endpoint.clone().into_boxed_str(),
        peer_vk: Box::new(vk_alpha),
    };
    let node_bravo = TestServer::start(
        "bravo",
        &ca_pem,
        &cert_pem,
        &key_pem,
        seed_bravo,
        vec![vk_alpha, vk_delta],
        vec![peer_alpha.clone()],
    );
    let peer_bravo = MeshPeer {
        endpoint: node_bravo.endpoint.clone().into_boxed_str(),
        peer_vk: Box::new(vk_bravo),
    };
    let node_delta = TestServer::start(
        "delta",
        &ca_pem,
        &cert_pem,
        &key_pem,
        seed_delta,
        vec![vk_alpha, vk_bravo],
        vec![peer_alpha, peer_bravo],
    );

    let dir_alice = common::temp_dir("rmz-alice");
    let dir_bob = common::temp_dir("rmz-bob");
    let dir_malloy = common::temp_dir("rmz-malloy");
    common::make_vault(&dir_alice);
    common::make_vault(&dir_bob);
    common::make_vault(&dir_malloy);
    common::sync_off_with(&dir_alice, common::PASSWORD);
    common::sync_off_with(&dir_bob, common::PASSWORD);
    common::sync_off_with(&dir_malloy, common::PASSWORD);

    let mut alice = app_with_server(&dir_alice, &node_alpha);
    let mut bob = app_with_server(&dir_bob, &node_bravo);
    let mut malloy = app_with_server(&dir_malloy, &node_delta);
    common::unlock(&mut alice, common::PASSWORD);
    common::unlock(&mut bob, common::PASSWORD);
    common::unlock(&mut malloy, common::PASSWORD);

    common::press(&mut bob, KeyCode::Char('S'));
    let bob_card = share_state(&bob).me.as_ref().unwrap().text.to_string();
    common::press(&mut bob, KeyCode::Esc);

    common::press(&mut malloy, KeyCode::Char('S'));
    let malloy_card = share_state(&malloy).me.as_ref().unwrap().text.to_string();
    let malloy_print = share_state(&malloy).me.as_ref().unwrap().print.to_string();
    common::press(&mut malloy, KeyCode::Esc);

    // Alice creates "Exec Vault", writes "Pre-Remove", and invites Bob and Malloy.
    common::press(&mut alice, KeyCode::Char('S'));
    common::press(&mut alice, KeyCode::Char('n'));
    common::type_text(&mut alice, "Exec Vault");
    common::press(&mut alice, KeyCode::Enter);
    common::wait(&mut alice);
    let exec_id = common::unlocked_state(&alice).shared[0].reference.vault_id;
    common::press(&mut alice, KeyCode::Esc);

    if let Screen::Unlocked(state) = &mut alice.screen {
        state.home.filter = Filter::Shared(exec_id, "Exec Vault".into());
        state.write_active(None, Box::new(titled("Pre-Remove")), &mut alice.ctx);
        state.home.filter = Filter::All;
    }

    for (guest, card) in [(&mut bob, &bob_card), (&mut malloy, &malloy_card)] {
        common::press(&mut alice, KeyCode::Char('S'));
        common::press(&mut alice, KeyCode::Char('a'));
        alice.on_paste(card);
        common::press(&mut alice, KeyCode::Enter);
        let Step::AddDone { invitation, .. } = &share_state(&alice).step else {
            panic!("expected AddDone");
        };
        let invite = invitation.to_string();
        common::press(&mut alice, KeyCode::Esc);
        common::press(&mut alice, KeyCode::Esc);

        common::press(guest, KeyCode::Char('S'));
        common::press(guest, KeyCode::Char('j'));
        guest.on_paste(&invite);
        common::press(guest, KeyCode::Enter);
        common::wait(guest);
        common::press(guest, KeyCode::Esc);
    }

    // Pump until Bob and Malloy both sync "Pre-Remove" AND Alice learns Bob's device key!
    assert!(
        pump_three(
            &mut alice,
            &mut bob,
            &mut malloy,
            Duration::from_secs(30),
            |a, b, m| {
                let b_ok = common::unlocked_state(b).shared.first().is_some_and(|i| {
                    i.ready() && i.cache.iter().any(|r| &*r.title == "Pre-Remove")
                });
                let m_ok = common::unlocked_state(m).shared.first().is_some_and(|i| {
                    i.ready() && i.cache.iter().any(|r| &*r.title == "Pre-Remove")
                });
                let a_knows_devs = common::unlocked_state(a)
                    .zsync
                    .as_ref()
                    .and_then(|z| z.shared_member_devices.get(&exec_id))
                    .is_some_and(|devs| devs.len() >= 2);
                b_ok && m_ok && a_knows_devs
            }
        ),
        "Bob/Malloy failed initial shared vault sync or device key announcement"
    );

    // Alice removes Malloy via UI ('S' -> 'x' -> select Malloy -> Enter -> Enter).
    common::press(&mut alice, KeyCode::Char('S'));
    common::press(&mut alice, KeyCode::Char('x'));
    let people = common::unlocked_state(&alice).people(0);
    let malloy_idx = people
        .iter()
        .position(|p| p.print.to_string() == malloy_print)
        .expect("Malloy in people list");
    for _ in 0..malloy_idx {
        common::press(&mut alice, KeyCode::Down);
    }
    common::press(&mut alice, KeyCode::Enter);
    common::press(&mut alice, KeyCode::Enter);
    assert_eq!(common::unlocked_state(&alice).shared[0].reference.epoch, 1);
    common::press(&mut alice, KeyCode::Esc);

    // Alice writes "Post-Remove Secret" under the rotated epoch-1 key!
    if let Screen::Unlocked(state) = &mut alice.screen {
        state.home.filter = Filter::Shared(exec_id, "Exec Vault".into());
        state.write_active(None, Box::new(titled("Post-Remove Secret")), &mut alice.ctx);
        state.home.filter = Filter::All;
    }

    // Bob automatically transitions to epoch 1 over zsync mesh and sees "Post-Remove Secret"!
    assert!(
        pump_three(
            &mut alice,
            &mut bob,
            &mut malloy,
            Duration::from_secs(30),
            |_, b, _| {
                common::unlocked_state(b)
                    .shared
                    .first()
                    .is_some_and(|item| {
                        item.reference.epoch == 1
                            && !item.stale
                            && item.cache.iter().any(|r| &*r.title == "Post-Remove Secret")
                    })
            }
        ),
        "Bob never transitioned to rotated shared vault epoch 1 over zsync mesh"
    );

    // Malloy MUST NOT have "Post-Remove Secret"!
    assert!(
        !common::unlocked_state(&malloy).shared[0]
            .cache
            .iter()
            .any(|r| &*r.title == "Post-Remove Secret"),
        "removed member Malloy must never receive post-removal shared vault records"
    );

    let _ = std::fs::remove_dir_all(&dir_alice);
    let _ = std::fs::remove_dir_all(&dir_bob);
    let _ = std::fs::remove_dir_all(&dir_malloy);
    let _ = std::fs::remove_dir_all(&pki_dir);
}
