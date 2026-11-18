//! End-to-end tests for PQ TLS 1.3 (`X25519MLKEM768`), `WebTunnel` HTTP camouflage,
//! TSPU 15.5 KiB TCP curtain + WSS blocking fallback to `SplitHTTP`, `socks5h://`
//! remote DNS + failover, and envelope tamper / device revocation / reader ACLs.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "integration tests use unwrap/asserts and transitive crates pull getrandom 0.2"
)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kdf::personal_mailbox_id;
use local::{SyncIdentity, create_shared_vault, encode_personal_head};
use memberlog::{Action, Role};
use rustls::pki_types::ServerName;
use secret::Secret;
use session::KdfProfile;
use sync_https::http_wire::read_http_response;
use sync_https::tls::client_config;
use sync_https::{
    EnvelopePurpose, MailboxKind, ServerSyncWorker, SyncClient, SyncServerConfig, WatchedBox,
    WorkerEvent, WorkerTransport, open_envelope, seal_envelope, start_server,
};
use syncwire::encode_snapshot;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsConnector;

const SLUG: &str = "zp-secret-camo-slug-2026";

fn temp_dir(tag: &str) -> PathBuf {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).unwrap();
    let mut name = format!("zp-https-it-{tag}-");
    for byte in suffix {
        let _ = write!(name, "{byte:02x}");
    }
    let dir = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn make_identity(account_byte: u8, device_byte: u8) -> SyncIdentity {
    SyncIdentity::enroll(
        &[account_byte; 64],
        &[account_byte; 64],
        [device_byte; 16],
        u64::MAX,
    )
    .unwrap()
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

async fn raw_tls_http_probe(
    addr: std::net::SocketAddr,
    ca_pem: &[u8],
    request: &str,
) -> sync_https::http_wire::HttpResponse {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let cfg = client_config(Some(ca_pem)).unwrap();
    let sni = ServerName::try_from("localhost").unwrap();
    let mut tls = TlsConnector::from(cfg).connect(sni, tcp).await.unwrap();
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
    read_http_response(&mut tls).await.unwrap()
}

async fn pump_capped(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    mut writer: impl tokio::io::AsyncWrite + Unpin,
    total: Arc<AtomicUsize>,
    max_conn_bytes: Arc<AtomicUsize>,
    abort_tx: watch::Sender<bool>,
    abort_rx: watch::Receiver<bool>,
) {
    let mut buf = [0u8; 4_096];
    while !*abort_rx.borrow() {
        let Ok(res) = tokio::time::timeout(Duration::from_millis(25), reader.read(&mut buf)).await
        else {
            continue;
        };
        let n = match res {
            Ok(0) => {
                let _ = writer.shutdown().await;
                break;
            }
            Ok(n) => n,
            Err(_) => break,
        };
        let next = total.fetch_add(n, Ordering::SeqCst).saturating_add(n);
        if next > 15_500 {
            let _ = abort_tx.send(true);
            break;
        }
        max_conn_bytes.fetch_max(next, Ordering::SeqCst);
        if writer.write_all(&buf[..n]).await.is_err() {
            let _ = abort_tx.send(true);
            break;
        }
    }
}

fn run_async(fut: impl std::future::Future<Output = ()>) {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut);
}

#[test]
fn pq_tls13_x25519_mlkem768_and_webtunnel_camouflage() {
    run_async(pq_tls13_x25519_mlkem768_and_webtunnel_camouflage_async());
}

async fn pq_tls13_x25519_mlkem768_and_webtunnel_camouflage_async() {
    let dir = temp_dir("pq-camo");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&dir, "DNS:localhost,IP:127.0.0.1");
    let srv = start_server(SyncServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        cert_pem,
        key_pem,
        data_dir: dir.join("srv"),
        secret_slug: SLUG.into(),
        public_origin: "https://localhost:0".into(),
    })
    .await
    .unwrap();

    let id = make_identity(1, 1);
    let client = SyncClient::new(&[srv.endpoint_url(SLUG)], None, Some(&ca_pem), true).unwrap();
    client
        .push_personal_snapshot(&id, b"snap-v1", b"head-v1", 1)
        .await
        .unwrap();
    let pulled = client.pull_personal_state(&id, 0).await.unwrap().unwrap();
    assert_eq!(pulled.snapshot.unwrap().0.as_slice(), b"snap-v1");
    assert!(
        client
            .last_negotiated_tls()
            .expect("TLS info recorded")
            .is_pq_tls13()
    );

    let home = raw_tls_http_probe(
        srv.local_addr,
        &ca_pem,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(home.status, 200);
    let home_body = String::from_utf8_lossy(&home.body);
    assert!(home_body.contains("Static Mirror"), "{home_body}");
    assert!(!home_body.to_ascii_lowercase().contains("zebrapass"));
    for (k, v) in &home.headers {
        assert!(!k.to_ascii_lowercase().contains("zebrapass"));
        assert!(!v.to_ascii_lowercase().contains("zebrapass"));
    }

    let wrong = raw_tls_http_probe(
        srv.local_addr,
        &ca_pem,
        "POST /wrong-slug-1234567890/v1/state HTTP/1.1\r\n\
         Host: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(wrong.status, 404);

    let bad_ws = raw_tls_http_probe(
        srv.local_addr,
        &ca_pem,
        &format!(
            "GET /{SLUG}/v1/ws HTTP/1.1\r\n\
             Host: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Origin: https://evil.example\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(bad_ws.status, 403);

    srv.stop().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hostile_tspu_15kb_curtain_and_ws_block_falls_back_to_split_http() {
    run_async(hostile_tspu_15kb_curtain_and_ws_block_falls_back_to_split_http_async());
}

async fn hostile_tspu_15kb_curtain_and_ws_block_falls_back_to_split_http_async() {
    let dir = temp_dir("tspu-curtain");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&dir, "DNS:localhost,IP:127.0.0.1");

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let public_origin: Box<str> = format!("https://localhost:{proxy_port}").into();

    let srv = start_server(SyncServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        cert_pem,
        key_pem,
        data_dir: dir.join("srv"),
        secret_slug: SLUG.into(),
        public_origin: public_origin.clone(),
    })
    .await
    .unwrap();
    let server_addr = srv.local_addr;

    let max_conn_bytes = Arc::new(AtomicUsize::new(0));
    let (stop_tx, stop_rx) = watch::channel(false);
    let max_ref = Arc::clone(&max_conn_bytes);
    let proxy_task = tokio::spawn(async move {
        while !*stop_rx.borrow() {
            let Ok(Ok((client_tcp, _))) =
                tokio::time::timeout(Duration::from_millis(50), proxy_listener.accept()).await
            else {
                continue;
            };
            let max_conn = Arc::clone(&max_ref);
            tokio::spawn(async move {
                let Ok(server_tcp) = TcpStream::connect(server_addr).await else {
                    return;
                };
                let (cr, cw) = tokio::io::split(client_tcp);
                let (sr, sw) = tokio::io::split(server_tcp);
                let total = Arc::new(AtomicUsize::new(0));
                let (abort_tx, abort_rx) = watch::channel(false);
                let h1 = tokio::spawn(pump_capped(
                    cr,
                    sw,
                    Arc::clone(&total),
                    Arc::clone(&max_conn),
                    abort_tx.clone(),
                    abort_rx.clone(),
                ));
                let h2 = tokio::spawn(pump_capped(
                    sr,
                    cw,
                    total,
                    max_conn,
                    abort_tx.clone(),
                    abort_rx,
                ));
                let a1 = h1.abort_handle();
                let a2 = h2.abort_handle();
                let _ = tokio::time::timeout(Duration::from_millis(350), async {
                    let _ = h1.await;
                    let _ = h2.await;
                })
                .await;
                let _ = abort_tx.send(true);
                a1.abort();
                a2.abort();
            });
        }
    });

    let id_a = make_identity(3, 1);
    let id_b = Arc::new(make_identity(3, 2));
    let url = format!("{public_origin}/{SLUG}");
    let client_a =
        Arc::new(SyncClient::new(std::slice::from_ref(&url), None, Some(&ca_pem), true).unwrap());
    let client_b = Arc::new(SyncClient::new(&[url], None, Some(&ca_pem), true).unwrap());

    let gate = id_b.account_gate().unwrap();
    let box_id = personal_mailbox_id(gate.expose(), &public_origin).unwrap();
    let (mut worker, mut ev_rx) = ServerSyncWorker::spawn(
        &tokio::runtime::Handle::current(),
        Arc::clone(&client_b),
        Arc::clone(&id_b),
        vec![WatchedBox {
            kind: MailboxKind::Personal,
            box_id,
            vault_id: [0u8; 16],
        }],
        Duration::from_millis(250),
    );

    let mut saw_fallback = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(200), ev_rx.recv()).await
            && matches!(
                ev,
                WorkerEvent::TransportChanged(WorkerTransport::SplitHttpFallback)
            )
        {
            saw_fallback = true;
            break;
        }
    }
    assert!(saw_fallback, "expected SplitHTTP fallback when WSS drops");

    let snap_payload = vec![0xAB; 18_000];
    let frame_payload = vec![0xCD; 24_000];
    let backup_payload = vec![0xEF; 32_000];

    client_a
        .push_personal_snapshot(&id_a, &snap_payload, b"head-meta", 1)
        .await
        .unwrap();
    client_a
        .append_personal_frame(&id_a, &frame_payload, 1)
        .await
        .unwrap();
    client_a
        .push_cloud_backup(&id_a, &backup_payload)
        .await
        .unwrap();

    let mut saw_update = false;
    let update_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < update_deadline {
        if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(200), ev_rx.recv()).await
            && matches!(
                ev,
                WorkerEvent::MailboxUpdated {
                    kind: MailboxKind::Personal,
                    ..
                }
            )
        {
            saw_update = true;
            break;
        }
    }
    assert!(
        saw_update,
        "expected MailboxUpdated event via SplitHTTP poll"
    );

    let pulled = client_b
        .pull_personal_state(&id_b, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pulled.snapshot.unwrap().0.as_slice(), &snap_payload);
    assert_eq!(pulled.frames[0].1.as_slice(), &frame_payload);
    let pulled_backup = client_b.pull_cloud_backup(&id_b).await.unwrap().unwrap();
    assert_eq!(pulled_backup.as_slice(), &backup_payload);

    let sv_dir = dir.join("sv");
    std::fs::create_dir_all(&sv_dir).unwrap();
    let (mut sv, sref) = create_shared_vault(&sv_dir, &id_a, "Team", KdfProfile::Fast).unwrap();
    let att = sv.attestations(&sref, &id_a).unwrap();
    let sv_snap = encode_snapshot(sv.file.as_bytes(), &att).unwrap();
    let sv_head = encode_personal_head(
        sv.session.vault_id(),
        sv.session.commit_tag(),
        sv.session.generation(),
    );
    client_a
        .push_shared_state(
            &id_a,
            sref.seed.expose(),
            sref.vault_id,
            sref.anchor,
            sv.log.entries(),
            &sv_snap,
            &sv_head,
            sv.session.generation(),
        )
        .await
        .unwrap();
    let shared_frame = vec![0x55; 10_000];
    client_a
        .append_shared_frame(&id_a, sref.seed.expose(), sref.vault_id, &shared_frame, 1)
        .await
        .unwrap();
    let pulled_shared = client_b
        .pull_shared_state(&id_b, sref.seed.expose(), sref.vault_id, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pulled_shared.snapshot.unwrap().0.as_slice(), &sv_snap);
    assert_eq!(pulled_shared.frames[0].1.as_slice(), &shared_frame);

    let observed_max = max_conn_bytes.load(Ordering::SeqCst);
    assert!(
        observed_max > 6_000 && observed_max <= 15_500,
        "unexpected max per-connection bytes: {observed_max}"
    );

    worker.stop();
    let _ = stop_tx.send(true);
    let _ = proxy_task.await;
    srv.stop().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn socks5h_remote_dns_and_multi_endpoint_failover() {
    run_async(socks5h_remote_dns_and_multi_endpoint_failover_async());
}

async fn socks5h_remote_dns_and_multi_endpoint_failover_async() {
    let dir = temp_dir("socks5h");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(
        &dir,
        "DNS:sync.zebrapass-test.invalid,DNS:localhost,IP:127.0.0.1",
    );
    let srv = start_server(SyncServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        cert_pem,
        key_pem,
        data_dir: dir.join("srv"),
        secret_slug: SLUG.into(),
        public_origin: "https://sync.zebrapass-test.invalid:8443".into(),
    })
    .await
    .unwrap();
    let server_addr = srv.local_addr;

    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_port = socks_listener.local_addr().unwrap().port();
    let dead_attempts = Arc::new(AtomicUsize::new(0));
    let saw_remote_dns = Arc::new(AtomicBool::new(false));
    let (stop_tx, stop_rx) = watch::channel(false);

    let dead_ref = Arc::clone(&dead_attempts);
    let dns_ref = Arc::clone(&saw_remote_dns);
    let socks_task = tokio::spawn(async move {
        while !*stop_rx.borrow() {
            let Ok(Ok((mut client, _))) =
                tokio::time::timeout(Duration::from_millis(50), socks_listener.accept()).await
            else {
                continue;
            };
            let dead_cnt = Arc::clone(&dead_ref);
            let dns_ok = Arc::clone(&dns_ref);
            tokio::spawn(async move {
                let mut hdr = [0u8; 2];
                client.read_exact(&mut hdr).await.unwrap();
                assert_eq!(hdr[0], 0x05);
                let mut methods = vec![0u8; usize::from(hdr[1])];
                client.read_exact(&mut methods).await.unwrap();
                assert!(methods.contains(&0x02));
                client.write_all(&[0x05, 0x02]).await.unwrap();

                let mut auth_ver = [0u8; 2];
                client.read_exact(&mut auth_ver).await.unwrap();
                assert_eq!(auth_ver[0], 0x01);
                let mut uname = vec![0u8; usize::from(auth_ver[1])];
                client.read_exact(&mut uname).await.unwrap();
                let mut plen = [0u8; 1];
                client.read_exact(&mut plen).await.unwrap();
                let mut pass = vec![0u8; usize::from(plen[0])];
                client.read_exact(&mut pass).await.unwrap();
                assert_eq!(uname, b"zpuser");
                assert_eq!(pass, b"zppass");
                client.write_all(&[0x01, 0x00]).await.unwrap();

                let mut req = [0u8; 5];
                client.read_exact(&mut req).await.unwrap();
                assert_eq!(&req[..4], &[0x05, 0x01, 0x00, 0x03]);
                let mut host_bytes = vec![0u8; usize::from(req[4])];
                client.read_exact(&mut host_bytes).await.unwrap();
                let mut port_bytes = [0u8; 2];
                client.read_exact(&mut port_bytes).await.unwrap();
                let host = std::str::from_utf8(&host_bytes).unwrap();
                let port = u16::from_be_bytes(port_bytes);

                if host == "dead.zebrapass-test.invalid" {
                    dead_cnt.fetch_add(1, Ordering::SeqCst);
                    let _ = client
                        .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                }
                assert_eq!(host, "sync.zebrapass-test.invalid");
                assert_eq!(port, 8443);
                dns_ok.store(true, Ordering::SeqCst);

                let mut upstream = TcpStream::connect(server_addr).await.unwrap();
                client
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });

    let client = SyncClient::new(
        &[
            format!("https://dead.zebrapass-test.invalid:9443/{SLUG}"),
            format!("https://sync.zebrapass-test.invalid:8443/{SLUG}"),
        ],
        Some(&format!("socks5h://zpuser:zppass@127.0.0.1:{socks_port}")),
        Some(&ca_pem),
        false,
    )
    .unwrap();
    let id = make_identity(5, 1);
    client
        .push_personal_snapshot(&id, b"proxied-snap", b"proxied-head", 1)
        .await
        .unwrap();
    let pulled = client.pull_personal_state(&id, 0).await.unwrap().unwrap();
    assert_eq!(pulled.snapshot.unwrap().0.as_slice(), b"proxied-snap");
    assert!(dead_attempts.load(Ordering::SeqCst) >= 1);
    assert!(saw_remote_dns.load(Ordering::SeqCst));

    let _ = stop_tx.send(true);
    let _ = socks_task.await;
    srv.stop().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tamper_revocation_and_shared_reader_enforcement() {
    run_async(tamper_revocation_and_shared_reader_enforcement_async());
}

async fn tamper_revocation_and_shared_reader_enforcement_async() {
    let dir = temp_dir("sec-invariants");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&dir, "DNS:localhost,IP:127.0.0.1");
    let srv = start_server(SyncServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        cert_pem,
        key_pem,
        data_dir: dir.join("srv"),
        secret_slug: SLUG.into(),
        public_origin: "https://localhost:0".into(),
    })
    .await
    .unwrap();

    let key = Secret::new([9u8; 32]);
    let box_id = [4u8; 32];
    let mut env =
        seal_envelope(&key, &box_id, EnvelopePurpose::PersonalFrame, 1, b"secret").unwrap();
    let flip = env.len() - 5;
    env[flip] ^= 0x01;
    assert!(open_envelope(&key, &box_id, EnvelopePurpose::PersonalFrame, &env).is_err());

    let client = SyncClient::new(&[srv.endpoint_url(SLUG)], None, Some(&ca_pem), true).unwrap();

    let mut dev1 = make_identity(7, 1);
    let dev2 = make_identity(7, 2);
    client
        .push_personal_snapshot(&dev1, b"dev1-snap", b"dev1-head", 1)
        .await
        .unwrap();
    client.pull_personal_state(&dev2, 0).await.unwrap();
    client
        .append_personal_frame(&dev2, b"dev2-before-revoke", 1)
        .await
        .unwrap();
    let rev = dev1.revoke_device(&dev2.devices()[0], now_ms()).unwrap();
    client.push_personal_revocation(&dev1, &rev).await.unwrap();
    assert!(
        client
            .append_personal_frame(&dev2, b"dev2-after-revoke", 2)
            .await
            .is_err()
    );

    let owner = make_identity(11, 1);
    let reader = make_identity(12, 2);
    let writer = make_identity(13, 3);
    let sv_dir = dir.join("sv");
    std::fs::create_dir_all(&sv_dir).unwrap();
    let (mut sv, sref) =
        create_shared_vault(&sv_dir, &owner, "ACL Vault", KdfProfile::Fast).unwrap();

    for (acct, role) in [(&reader, Role::Reader), (&writer, Role::Writer)] {
        let entry = sv
            .log
            .propose(
                &owner.sign_key(),
                &owner.devices()[0],
                Action::Add {
                    client_id: acct.devices()[0].client_id,
                    root_vk: Box::new(*acct.root_vk()),
                    role,
                },
                now_ms(),
            )
            .unwrap();
        sv.log.append(entry).unwrap();
    }
    sv.save_log(&sref.seed).unwrap();

    let att = sv.attestations(&sref, &owner).unwrap();
    let snap = encode_snapshot(sv.file.as_bytes(), &att).unwrap();
    let head = encode_personal_head(
        sv.session.vault_id(),
        sv.session.commit_tag(),
        sv.session.generation(),
    );
    client
        .push_shared_state(
            &owner,
            sref.seed.expose(),
            sref.vault_id,
            sref.anchor,
            sv.log.entries(),
            &snap,
            &head,
            sv.session.generation(),
        )
        .await
        .unwrap();

    assert!(
        client
            .pull_shared_state(&reader, sref.seed.expose(), sref.vault_id, 0)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        client
            .append_shared_frame(
                &reader,
                sref.seed.expose(),
                sref.vault_id,
                b"forged-by-reader",
                2,
            )
            .await
            .is_err()
    );

    client
        .append_shared_frame(
            &writer,
            sref.seed.expose(),
            sref.vault_id,
            b"writer-valid-bundle",
            2,
        )
        .await
        .unwrap();
    let pulled = client
        .pull_shared_state(&owner, sref.seed.expose(), sref.vault_id, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pulled.frames.len(), 1);
    assert_eq!(pulled.frames[0].1.as_slice(), b"writer-valid-bundle");

    srv.stop().await;
    let _ = std::fs::remove_dir_all(&dir);
}
