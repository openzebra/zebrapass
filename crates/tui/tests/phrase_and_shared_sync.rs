//! End-to-end TUI integration tests over a 3-server `zsync` PQ TLS 1.3 mesh
//! (`srv_ru <-> srv_eu <-> srv_zh`, with `Listen::Off` so zero LAN P2P sockets
//! or broadcasts are used):
//! 1. Same BIP39 phrase cloning across devices with different local factors
//!    (Password on Device A connected to `srv_ru`, 6-digit Device PIN on Device B
//!    connected to `srv_zh`), auto-joining personal + shared vaults, live 2-way
//!    edits, and live `VK` rotation across the server mesh.
//! 2. Multi-user `SharedVault` invitation and real-time sync between two
//!    distinct BIP39 phrases connected to different servers (`srv_ru` and `srv_eu`).
//! 3. `.zpbackup` export and restore roundtrip onto a fresh directory.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "integration tests use unwrap/asserts and transitive crates pull getrandom 0.2"
)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use record::{Document, TAG_TITLE};
use secret::Secret;
use session::{SYNC_VK_LEN, sync_verifying_key};
use tui::App;
use tui::app::ctx::Task;
use tui::app::flows::home::Filter;
use tui::app::flows::share::{ShareState, Step};
use tui::app::flows::unlocked::View;
use tui::app::screen::Screen;
use tui::cli::Flags;
use tui::vault::ops::{Op, Rotation};
use zeroize::Zeroizing;
use zsync::{MeshAuthConfig, MeshPeer, ZebraServerConfig, ZebraServerHandle, start_server};

const PIN_B: &str = "482916";

struct TestServer {
    rt: tokio::runtime::Runtime,
    handle: Option<ZebraServerHandle>,
    endpoint: String,
    ca_path: PathBuf,
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
        let dir = common::temp_dir(&format!("srv-{tag}"));
        let ca_path = dir.join("ca.crt");
        std::fs::write(&ca_path, ca_pem).unwrap();

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let mesh = MeshAuthConfig {
            seed: Secret::new(mesh_seed),
            peers,
            allowed_vks,
        };
        let handle = rt
            .block_on(start_server(ZebraServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                cert_pem: cert_pem.to_vec(),
                key_pem: Secret::new(key_pem.to_vec()),
                extra_ca_pem: Some(ca_pem.to_vec()),
                data_dir: dir.join("data"),
                mesh: Some(mesh),
                mesh_interval: Duration::from_millis(120),
                allow_private: true,
            }))
            .unwrap();
        let endpoint = handle.endpoint.to_string();
        Self {
            rt,
            handle: Some(handle),
            endpoint,
            ca_path,
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

struct TestCluster {
    srv_ru: TestServer,
    srv_eu: TestServer,
    srv_zh: TestServer,
    pki_dir: PathBuf,
}

impl TestCluster {
    fn start(tag: &str) -> Self {
        let pki_dir = common::temp_dir(&format!("pki-{tag}"));
        let (ca_pem, cert_pem, key_pem) = generate_test_pki(&pki_dir, "DNS:localhost,IP:127.0.0.1");
        let seed_alpha = [0x11u8; 32];
        let seed_bravo = [0x22u8; 32];
        let seed_delta = [0x33u8; 32];
        let vk_alpha: [u8; SYNC_VK_LEN] =
            sync_verifying_key(&seed_alpha).unwrap().try_into().unwrap();
        let vk_bravo: [u8; SYNC_VK_LEN] =
            sync_verifying_key(&seed_bravo).unwrap().try_into().unwrap();
        let vk_delta: [u8; SYNC_VK_LEN] =
            sync_verifying_key(&seed_delta).unwrap().try_into().unwrap();

        let ru_hub = TestServer::start(
            "ru",
            &ca_pem,
            &cert_pem,
            &key_pem,
            seed_alpha,
            vec![vk_bravo, vk_delta],
            Vec::new(),
        );
        let peer_alpha = MeshPeer {
            endpoint: ru_hub.endpoint.clone().into_boxed_str(),
            peer_vk: Box::new(vk_alpha),
        };
        let eu_mirror = TestServer::start(
            "eu",
            &ca_pem,
            &cert_pem,
            &key_pem,
            seed_bravo,
            vec![vk_alpha, vk_delta],
            vec![peer_alpha.clone()],
        );
        let peer_bravo = MeshPeer {
            endpoint: eu_mirror.endpoint.clone().into_boxed_str(),
            peer_vk: Box::new(vk_bravo),
        };
        let zh_node = TestServer::start(
            "zh",
            &ca_pem,
            &cert_pem,
            &key_pem,
            seed_delta,
            vec![vk_alpha, vk_bravo],
            vec![peer_alpha, peer_bravo],
        );
        Self {
            srv_ru: ru_hub,
            srv_eu: eu_mirror,
            srv_zh: zh_node,
            pki_dir,
        }
    }
}

impl Drop for TestCluster {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.pki_dir);
    }
}

fn run_openssl(args: &[&str]) {
    let out = Command::new("/usr/bin/openssl")
        .args(args)
        .output()
        .expect("run /usr/bin/openssl");
    assert!(
        out.status.success(),
        "openssl {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn generate_test_pki(dir: &Path, san: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
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
         [dn]\nCN = ZebraPass Test CA\n\
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
        format!(
            "basicConstraints = CA:FALSE\n\
             keyUsage = critical, digitalSignature, keyEncipherment\n\
             extendedKeyUsage = serverAuth\n\
             subjectAltName = {san}\n"
        ),
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

fn app_with_server(base: &Path, srv: &TestServer) -> App {
    let mut cfg = common::config(base);
    cfg.flags = cfg.flags.with(Flags::ALLOW_PRIVATE_SYNC, true);
    cfg.sync_servers = vec![srv.endpoint.clone().into_boxed_str()];
    cfg.extra_ca = Some(srv.ca_path.clone());
    common::app_with(&cfg, base, common::CAPS)
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

fn pump_one(app: &mut App, within: Duration, done: impl Fn(&App) -> bool) -> bool {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if done(app) {
            return true;
        }
        common::tick(app, Duration::from_millis(250));
        if app.ctx.busy() {
            let _ = app.wait_for_job(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    done(app)
}

fn pump_pair(
    a: &mut App,
    b: &mut App,
    within: Duration,
    done: impl Fn(&App, &App) -> bool,
) -> bool {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if done(a, b) {
            return true;
        }
        common::tick(a, Duration::from_millis(250));
        common::tick(b, Duration::from_millis(250));
        if a.ctx.busy() {
            let _ = a.wait_for_job(Duration::from_millis(40));
        }
        if b.ctx.busy() {
            let _ = b.wait_for_job(Duration::from_millis(40));
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    done(a, b)
}

fn lock_and_unlock(app: &mut App, secret: &str) {
    common::press(app, KeyCode::Esc);
    common::press(app, KeyCode::Esc);
    for _ in 0..20 {
        if app.screen.name() != "unlocked" {
            break;
        }
        common::press(app, KeyCode::Char('L'));
    }
    common::press(app, KeyCode::Enter);
    assert_eq!(app.screen.name(), "unlock");
    common::type_text(app, secret);
    common::press(app, KeyCode::Enter);
    common::wait(app);
    common::press(app, KeyCode::Esc);
    assert_eq!(app.screen.name(), "unlocked");
}

#[test]
fn same_phrase_different_factors_clone_shared_autojoin_and_rekey() {
    let cluster = TestCluster::start("same-phrase");

    let dir_a = common::temp_dir("same-a");
    let words = common::make_vault(&dir_a);
    common::sync_off_with(&dir_a, common::PASSWORD);
    let mut app_a = app_with_server(&dir_a, &cluster.srv_ru);
    common::unlock(&mut app_a, common::PASSWORD);

    if let Screen::Unlocked(state) = &mut app_a.screen {
        state.run(
            Op::Write {
                id: None,
                doc: Box::new(titled("GitHub Prod")),
            },
            Task::Save,
            &mut app_a.ctx,
        );
    }
    common::wait(&mut app_a);

    common::press(&mut app_a, KeyCode::Char('S'));
    common::press(&mut app_a, KeyCode::Char('n'));
    common::type_text(&mut app_a, "Team Keys");
    common::press(&mut app_a, KeyCode::Enter);
    common::wait(&mut app_a);
    common::press(&mut app_a, KeyCode::Esc);

    let team_id = common::unlocked_state(&app_a).shared[0].reference.vault_id;
    if let Screen::Unlocked(state) = &mut app_a.screen {
        state.home.filter = Filter::Shared(team_id, "Team Keys".into());
        state.write_active(None, Box::new(titled("OPENAI_API_KEY")), &mut app_a.ctx);
        state.home.filter = Filter::All;
    }

    assert!(
        pump_one(&mut app_a, Duration::from_secs(15), |app| {
            common::unlocked_state(app).zsync.as_ref().is_some_and(|z| {
                z.last_sync_ms.is_some() && z.personal_queue == tui::app::zsync::PersonalQueue::Idle
            })
        }),
        "Device A never finished initial zsync push"
    );

    // Device B connects ONLY to srv_zh, testing automatic cross-server mesh propagation.
    let dir_b = common::temp_dir("same-b");
    let mut app_b = app_with_server(&dir_b, &cluster.srv_zh);
    common::open_restore(&mut app_b);
    common::type_phrase(&mut app_b, &words);
    common::press(&mut app_b, KeyCode::Enter);

    // Select This device (PIN-sealed key) instead of Password on Device B.
    common::press(&mut app_b, KeyCode::Up);
    common::press(&mut app_b, KeyCode::Right);
    common::press(&mut app_b, KeyCode::Enter);
    common::type_text(&mut app_b, PIN_B);
    common::press(&mut app_b, KeyCode::Tab);
    common::type_text(&mut app_b, PIN_B);
    common::press(&mut app_b, KeyCode::Enter);
    common::wait(&mut app_b);

    assert!(
        pump_pair(&mut app_a, &mut app_b, Duration::from_secs(30), |_, b| {
            b.screen.name() == "unlocked"
                && !b.ctx.busy()
                && !common::is_placeholder(b)
                && common::titles_of(b).contains(&String::from("GitHub Prod"))
        }),
        "Device B never adopted personal vault with GitHub Prod over zsync mesh: {:?}",
        common::titles_of(&app_b)
    );

    lock_and_unlock(&mut app_b, PIN_B);

    assert!(
        pump_pair(&mut app_a, &mut app_b, Duration::from_secs(30), |a, b| {
            let st_a = common::unlocked_state(a);
            let st_b = common::unlocked_state(b);
            let a_knows_b = st_a
                .zsync
                .as_ref()
                .is_some_and(|z| !z.peer_devices.is_empty());
            let b_synced_shared = st_b.shared.first().is_some_and(|item| {
                item.ready() && item.cache.iter().any(|r| &*r.title == "OPENAI_API_KEY")
            });
            a_knows_b && b_synced_shared
        }),
        "Device B failed to auto-join shared vault or announce itself to Device A"
    );

    if let Screen::Unlocked(state) = &mut app_b.screen {
        state.run(
            Op::Write {
                id: None,
                doc: Box::new(titled("Stripe Live")),
            },
            Task::Save,
            &mut app_b.ctx,
        );
    }
    common::wait(&mut app_b);

    if let Screen::Unlocked(state) = &mut app_b.screen {
        state.home.filter = Filter::Shared(team_id, "Team Keys".into());
        state.write_active(None, Box::new(titled("ANTHROPIC_API_KEY")), &mut app_b.ctx);
        state.home.filter = Filter::All;
    }

    assert!(
        pump_pair(&mut app_a, &mut app_b, Duration::from_secs(30), |a, _| {
            let has_personal = common::titles_of(a).contains(&String::from("Stripe Live"));
            let has_shared = common::unlocked_state(a)
                .shared
                .first()
                .is_some_and(|item| item.cache.iter().any(|r| &*r.title == "ANTHROPIC_API_KEY"));
            has_personal && has_shared
        }),
        "Device B edits never synced back to Device A: personal={:?}",
        common::titles_of(&app_a)
    );

    if let Screen::Unlocked(state) = &mut app_a.screen {
        state.run(
            Op::Rotate(Box::new(Rotation {
                phrase: Box::new(common::phrase(&words)),
                current: Some(Zeroizing::new(common::PASSWORD.as_bytes().to_vec())),
                revoke: None,
            })),
            Task::Rotate,
            &mut app_a.ctx,
        );
    }
    common::wait(&mut app_a);

    if let Screen::Unlocked(state) = &mut app_a.screen {
        state.run(
            Op::Write {
                id: None,
                doc: Box::new(titled("Post Rotate Key")),
            },
            Task::Save,
            &mut app_a.ctx,
        );
    }
    common::wait(&mut app_a);

    assert!(
        pump_pair(&mut app_a, &mut app_b, Duration::from_secs(30), |_, b| {
            common::titles_of(b).contains(&String::from("Post Rotate Key"))
        }),
        "Device B never adopted rotated VK and post-rotation record: {:?}",
        common::titles_of(&app_b)
    );

    lock_and_unlock(&mut app_b, PIN_B);
    assert!(common::titles_of(&app_b).contains(&String::from("Post Rotate Key")));

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[test]
fn multi_user_shared_vault_syncs_across_mesh() {
    let cluster = TestCluster::start("multi-user");

    let dir_1 = common::temp_dir("mu-1");
    let dir_2 = common::temp_dir("mu-2");
    common::make_vault(&dir_1);
    common::make_vault(&dir_2);
    common::sync_off_with(&dir_1, common::PASSWORD);
    common::sync_off_with(&dir_2, common::PASSWORD);

    // User 1 connects to srv_ru; User 2 connects to srv_eu.
    let mut app_1 = app_with_server(&dir_1, &cluster.srv_ru);
    let mut app_2 = app_with_server(&dir_2, &cluster.srv_eu);
    common::unlock(&mut app_1, common::PASSWORD);
    common::unlock(&mut app_2, common::PASSWORD);

    common::press(&mut app_2, KeyCode::Char('S'));
    let card_2 = share_state(&app_2).me.as_ref().unwrap().text.to_string();
    common::press(&mut app_2, KeyCode::Esc);

    common::press(&mut app_1, KeyCode::Char('S'));
    common::press(&mut app_1, KeyCode::Char('n'));
    common::type_text(&mut app_1, "Infra Secrets");
    common::press(&mut app_1, KeyCode::Enter);
    common::wait(&mut app_1);

    let infra_id = common::unlocked_state(&app_1).shared[0].reference.vault_id;
    common::press(&mut app_1, KeyCode::Esc);
    if let Screen::Unlocked(state) = &mut app_1.screen {
        state.home.filter = Filter::Shared(infra_id, "Infra Secrets".into());
        state.write_active(None, Box::new(titled("AWS_PROD_KEY")), &mut app_1.ctx);
        state.home.filter = Filter::All;
    }

    common::press(&mut app_1, KeyCode::Char('S'));
    common::press(&mut app_1, KeyCode::Char('a'));
    assert!(matches!(share_state(&app_1).step, Step::PasteCard));
    app_1.on_paste(&card_2);
    common::press(&mut app_1, KeyCode::Enter);
    let Step::AddDone { invitation, .. } = &share_state(&app_1).step else {
        panic!("expected AddDone");
    };
    let invite_text = invitation.to_string();
    common::press(&mut app_1, KeyCode::Esc);

    common::press(&mut app_2, KeyCode::Char('S'));
    common::press(&mut app_2, KeyCode::Char('j'));
    app_2.on_paste(&invite_text);
    common::press(&mut app_2, KeyCode::Enter);
    common::wait(&mut app_2);
    common::press(&mut app_2, KeyCode::Esc);

    assert!(
        pump_pair(&mut app_1, &mut app_2, Duration::from_secs(30), |_, u2| {
            common::unlocked_state(u2)
                .shared
                .first()
                .is_some_and(|item| {
                    item.ready() && item.cache.iter().any(|r| &*r.title == "AWS_PROD_KEY")
                })
        }),
        "User 2 never received AWS_PROD_KEY over zsync mesh"
    );

    if let Screen::Unlocked(state) = &mut app_2.screen {
        state.home.filter = Filter::Shared(infra_id, "Infra Secrets".into());
        state.write_active(None, Box::new(titled("CLOUDFLARE_TOKEN")), &mut app_2.ctx);
        state.home.filter = Filter::All;
    }

    assert!(
        pump_pair(&mut app_1, &mut app_2, Duration::from_secs(30), |u1, _| {
            common::unlocked_state(u1)
                .shared
                .first()
                .is_some_and(|item| item.cache.iter().any(|r| &*r.title == "CLOUDFLARE_TOKEN"))
        }),
        "User 1 never received CLOUDFLARE_TOKEN from User 2 across mesh"
    );

    let _ = std::fs::remove_dir_all(&dir_1);
    let _ = std::fs::remove_dir_all(&dir_2);
}

#[test]
fn backup_export_and_restore_roundtrip() {
    let dir_src = common::temp_dir("bkup-src");
    let words = common::make_vault(&dir_src);
    common::sync_off_with(&dir_src, common::PASSWORD);
    let mut app_src = common::app(&dir_src);
    common::unlock(&mut app_src, common::PASSWORD);

    if let Screen::Unlocked(state) = &mut app_src.screen {
        state.run(
            Op::Write {
                id: None,
                doc: Box::new(titled("Root SSH")),
            },
            Task::Save,
            &mut app_src.ctx,
        );
    }
    common::wait(&mut app_src);

    common::press(&mut app_src, KeyCode::Char('S'));
    common::press(&mut app_src, KeyCode::Char('n'));
    common::type_text(&mut app_src, "Ops Vault");
    common::press(&mut app_src, KeyCode::Enter);
    common::wait(&mut app_src);
    common::press(&mut app_src, KeyCode::Esc);

    let ops_id = common::unlocked_state(&app_src).shared[0]
        .reference
        .vault_id;
    if let Screen::Unlocked(state) = &mut app_src.screen {
        state.home.filter = Filter::Shared(ops_id, "Ops Vault".into());
        state.write_active(None, Box::new(titled("PG_PASS")), &mut app_src.ctx);
        state.home.filter = Filter::All;
    }

    let backup_path = dir_src.join("vault.zpbackup");
    if let Screen::Unlocked(state) = &mut app_src.screen {
        state.run(
            Op::ExportBackup(backup_path.clone()),
            Task::Save,
            &mut app_src.ctx,
        );
    }
    common::wait(&mut app_src);
    assert!(backup_path.is_file());
    drop(app_src);

    let dir_dst = common::temp_dir("bkup-dst");
    let mut app_dst = common::app(&dir_dst);
    common::open_restore(&mut app_dst);
    common::type_phrase(&mut app_dst, &words);
    common::press(&mut app_dst, KeyCode::Tab);
    app_dst.on_paste(&backup_path.to_string_lossy());
    common::press(&mut app_dst, KeyCode::Enter);
    common::type_text(&mut app_dst, "Restored-Pass-2026!");
    common::press(&mut app_dst, KeyCode::Tab);
    common::type_text(&mut app_dst, "Restored-Pass-2026!");
    common::press(&mut app_dst, KeyCode::Enter);
    common::wait(&mut app_dst);

    assert_eq!(app_dst.screen.name(), "unlocked");
    assert!(common::titles_of(&app_dst).contains(&String::from("Root SSH")));
    let shared = &common::unlocked_state(&app_dst).shared;
    assert_eq!(shared.len(), 1);
    assert!(shared[0].ready());
    assert_eq!(shared[0].name(), "Ops Vault");
    assert!(shared[0].cache.iter().any(|r| &*r.title == "PG_PASS"));

    let _ = std::fs::remove_dir_all(&dir_src);
    let _ = std::fs::remove_dir_all(&dir_dst);
}
