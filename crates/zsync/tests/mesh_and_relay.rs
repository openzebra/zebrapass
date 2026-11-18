//! Integration tests for `zsync`:
//! 1. Git-like frontier delta-only sync across a 3-server mesh (`srv_0 <-> srv_1 <-> srv_2`),
//!    refusing stale revisions and pushing only updated `RecordCommit`s.
//! 2. Parallel bidirectional mesh convergence under concurrent opposite-direction writes.
//! 3. Zero-storage live P2P relay over TLS 1.3 (`hold_relay_slot` + `connect_relay_slot`),
//!    verifying the relay server persists zero files in `repos/`.
//! 4. Tamper and device revocation + rotated `VK` adoption regressions.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "integration tests may unwrap and use concise inline setup"
)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use kdf::zsync_relay_slot;
use local::{
    SyncIdentity, create_vault, encode_personal_head, open_personal_rekey, seal_personal_rekey,
};
use record::{Document, TAG_TITLE};
use seed::SeedPhrase;
use session::{
    BodyAlg, KdfProfile, RotateCreds, VaultFile, accept_peer_frame, open_record, rotate_vault_key,
    unlock_with_key, write_record,
};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};
use zsync::{
    PersonalStateInput, ZebraClient, ZebraServerConfig, ZebraServerHandle, connect_relay_slot,
    hold_relay_slot, personal_storage_id, relay_sync_initiator, relay_sync_responder, start_server,
};

fn temp_dir(tag: &str) -> PathBuf {
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).unwrap();
    let hex = rnd.iter().fold(String::with_capacity(16), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    });
    let dir = std::env::temp_dir().join(format!("zp-zsync-{tag}-{hex}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
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
         [dn]\nCN = ZebraPass ZSync Test CA\n\
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

fn collect_records(sess: &session::Session) -> Vec<(u32, u64, [u8; 16], Vec<u8>)> {
    session::list_records(sess)
        .unwrap()
        .into_iter()
        .map(|row| {
            let raw = session::latest_frame(sess, row.id).unwrap();
            let hdr = frame::parse(&raw).unwrap();
            (row.id, hdr.revision, hdr.origin_device, raw)
        })
        .collect()
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}

async fn start_mesh_cluster(
    root: &Path,
    ca_pem: &[u8],
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Vec<ZebraServerHandle> {
    let srv_0 = start_server(ZebraServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        cert_pem: cert_pem.to_vec(),
        key_pem: key_pem.to_vec(),
        extra_ca_pem: Some(ca_pem.to_vec()),
        data_dir: root.join("srv0"),
        peers: Vec::new(),
        mesh_interval: Duration::from_millis(120),
        allow_loopback: true,
    })
    .await
    .unwrap();
    let srv_1 = start_server(ZebraServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        cert_pem: cert_pem.to_vec(),
        key_pem: key_pem.to_vec(),
        extra_ca_pem: Some(ca_pem.to_vec()),
        data_dir: root.join("srv1"),
        peers: vec![srv_0.endpoint.clone()],
        mesh_interval: Duration::from_millis(120),
        allow_loopback: true,
    })
    .await
    .unwrap();
    let srv_2 = start_server(ZebraServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        cert_pem: cert_pem.to_vec(),
        key_pem: key_pem.to_vec(),
        extra_ca_pem: Some(ca_pem.to_vec()),
        data_dir: root.join("srv2"),
        peers: vec![srv_0.endpoint.clone(), srv_1.endpoint.clone()],
        mesh_interval: Duration::from_millis(120),
        allow_loopback: true,
    })
    .await
    .unwrap();
    vec![srv_0, srv_1, srv_2]
}

#[test]
fn git_frontier_delta_only_and_three_server_mesh() {
    let dir = temp_dir("delta-mesh");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&dir);

    block_on(async {
        let cluster = start_mesh_cluster(&dir, &ca_pem, &cert_pem, &key_pem).await;
        let phrase = SeedPhrase::generate_24().unwrap();
        let client_id = kdf::client_id(phrase.seed()).unwrap();
        let dev1 = [0x11u8; 16];
        let dev2 = [0x22u8; 16];
        let id1 = SyncIdentity::enroll(phrase.seed(), &client_id, dev1, u64::MAX).unwrap();
        let id2 = SyncIdentity::enroll(phrase.seed(), &client_id, dev2, u64::MAX).unwrap();

        let (paths1, mut sess1, mut file1, _) = create_vault(
            &dir.join("d1"),
            phrase.seed(),
            KdfProfile::Fast,
            BodyAlg::Frames,
        )
        .unwrap();
        sess1.set_origin_device(dev1).unwrap();
        let _ = paths1;
        let rec1 = write_record(&mut sess1, &mut file1, None, &titled("Initial Key")).unwrap();

        let c0 = ZebraClient::new(&[cluster[0].endpoint.to_string()], Some(&ca_pem), true).unwrap();
        let c1 = ZebraClient::new(&[cluster[1].endpoint.to_string()], Some(&ca_pem), true).unwrap();
        let c2 = ZebraClient::new(&[cluster[2].endpoint.to_string()], Some(&ca_pem), true).unwrap();

        let head1 = encode_personal_head(sess1.vault_id(), sess1.commit_tag(), sess1.generation());
        let rows_1 = collect_records(&sess1);
        let p0 = c0
            .reconcile_personal(
                &id1,
                PersonalStateInput {
                    vault_bytes: file1.as_bytes(),
                    head_meta_plain: &head1,
                    generation: sess1.generation(),
                    head_epoch: 1,
                    records: &rows_1,
                    revocations: &[],
                    rekeys: &[],
                    push_head_always: false,
                },
            )
            .await
            .unwrap();
        assert!(p0.pushed_head);
        assert_eq!(p0.pushed_records, 1);

        // Wait for mesh replication to srv_2, then adopt on device_2 from srv_2 only.
        let mut p2_pull = None;
        for _ in 0..40 {
            let pull = c2
                .reconcile_personal(
                    &id2,
                    PersonalStateInput {
                        vault_bytes: &[],
                        head_meta_plain: &[],
                        generation: 0,
                        head_epoch: 0,
                        records: &[],
                        revocations: &[],
                        rekeys: &[],
                        push_head_always: false,
                    },
                )
                .await
                .unwrap();
            if pull.snapshot.is_some() && !pull.frames.is_empty() {
                p2_pull = Some(pull);
                break;
            }
            sleep(Duration::from_millis(80)).await;
        }
        let p2_pull = p2_pull.expect("srv_2 never received replicated snapshot/frames");
        let (snap2, _, _) = p2_pull.snapshot.unwrap();
        let mut file2 = VaultFile::new(snap2.to_vec());
        let mut sess2 = unlock_with_key(&file2, &sess1.reopen_key(), dev2).unwrap();
        for f in &p2_pull.frames {
            let _ = accept_peer_frame(&mut sess2, &mut file2, f);
        }
        assert_eq!(
            open_record(&sess2, rec1).unwrap().text(TAG_TITLE).unwrap(),
            Some("Initial Key")
        );

        // Device 1 edits record 1 (rev 2) and creates record 2 (rev 1): must push deltas ONLY!
        write_record(&mut sess1, &mut file1, Some(rec1), &titled("Edited Key v2")).unwrap();
        let rec2 = write_record(&mut sess1, &mut file1, None, &titled("Second Record")).unwrap();
        let head1b = encode_personal_head(sess1.vault_id(), sess1.commit_tag(), sess1.generation());
        let rows_1b = collect_records(&sess1);
        let delta_push = c0
            .reconcile_personal(
                &id1,
                PersonalStateInput {
                    vault_bytes: file1.as_bytes(),
                    head_meta_plain: &head1b,
                    generation: sess1.generation(),
                    head_epoch: 1,
                    records: &rows_1b,
                    revocations: &[],
                    rekeys: &[],
                    push_head_always: false,
                },
            )
            .await
            .unwrap();
        assert!(
            !delta_push.pushed_head,
            "normal record edits must not re-upload SignedHead"
        );
        assert_eq!(delta_push.pushed_records, 2);

        // Device 2 offers its stale rev 1 for rec1 to srv_1: srv_1 keeps dev1's newer rev 2 and returns it.
        let mut stale_accepted = false;
        for _ in 0..40 {
            let head2 =
                encode_personal_head(sess2.vault_id(), sess2.commit_tag(), sess2.generation());
            let rows_2 = collect_records(&sess2);
            let res = c1
                .reconcile_personal(
                    &id2,
                    PersonalStateInput {
                        vault_bytes: file2.as_bytes(),
                        head_meta_plain: &head2,
                        generation: sess2.generation(),
                        head_epoch: 1,
                        records: &rows_2,
                        revocations: &[],
                        rekeys: &[],
                        push_head_always: false,
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                res.pushed_records, 0,
                "stale rev 1 must never overwrite rev 2"
            );
            if res.frames.len() == 2 {
                for f in &res.frames {
                    let _ = accept_peer_frame(&mut sess2, &mut file2, f);
                }
                if open_record(&sess2, rec1).unwrap().text(TAG_TITLE).unwrap()
                    == Some("Edited Key v2")
                    && open_record(&sess2, rec2).unwrap().text(TAG_TITLE).unwrap()
                        == Some("Second Record")
                {
                    stale_accepted = true;
                    break;
                }
            }
            sleep(Duration::from_millis(80)).await;
        }
        assert!(
            stale_accepted,
            "srv_1 failed to deliver newer rev 2 / rec2 to device_2"
        );

        for h in cluster {
            h.stop().await;
        }
    });

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parallel_bidirectional_mesh_convergence() {
    let dir = temp_dir("bidir-mesh");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&dir);

    block_on(async {
        let cluster = start_mesh_cluster(&dir, &ca_pem, &cert_pem, &key_pem).await;
        let phrase = SeedPhrase::generate_24().unwrap();
        let client_id = kdf::client_id(phrase.seed()).unwrap();
        let devs = [[0x01u8; 16], [0x02u8; 16], [0x03u8; 16]];
        let (_, base_sess, base_file, _) = create_vault(
            &dir.join("seed"),
            phrase.seed(),
            KdfProfile::Fast,
            BodyAlg::Frames,
        )
        .unwrap();
        let base_vk = base_sess.reopen_key();

        let id0 =
            Arc::new(SyncIdentity::enroll(phrase.seed(), &client_id, devs[0], u64::MAX).unwrap());
        let id1 =
            Arc::new(SyncIdentity::enroll(phrase.seed(), &client_id, devs[1], u64::MAX).unwrap());
        let id2 =
            Arc::new(SyncIdentity::enroll(phrase.seed(), &client_id, devs[2], u64::MAX).unwrap());

        let c0 = ZebraClient::new(&[cluster[0].endpoint.to_string()], Some(&ca_pem), true).unwrap();
        let c1 = ZebraClient::new(&[cluster[1].endpoint.to_string()], Some(&ca_pem), true).unwrap();
        let c2 = ZebraClient::new(&[cluster[2].endpoint.to_string()], Some(&ca_pem), true).unwrap();

        let titles = ["From-RU", "From-EU", "From-ZH"];
        let mut tasks = Vec::new();
        for (idx, ((cli, id), title)) in [(c0, &id0), (c1, &id1), (c2, &id2)]
            .into_iter()
            .zip(titles)
            .enumerate()
        {
            let f_bytes = base_file.as_bytes().to_vec();
            let id_arc = Arc::clone(id);
            let dev = devs[idx];
            let vk = SecretCopy(&base_vk);
            let mut file = VaultFile::new(f_bytes);
            let mut sess = unlock_with_key(&file, vk.0, dev).unwrap();
            let rec_id = u32::try_from(idx + 1).unwrap();
            let raw = write_distinct_frame(&mut sess, &mut file, rec_id, title);
            let hdr = frame::parse(&raw).unwrap();
            let head = encode_personal_head(sess.vault_id(), sess.commit_tag(), sess.generation());
            tasks.push(tokio::spawn(async move {
                cli.reconcile_personal(
                    &id_arc,
                    PersonalStateInput {
                        vault_bytes: file.as_bytes(),
                        head_meta_plain: &head,
                        generation: sess.generation(),
                        head_epoch: 1,
                        records: &[(rec_id, hdr.revision, hdr.origin_device, raw)],
                        revocations: &[],
                        rekeys: &[],
                        push_head_always: true,
                    },
                )
                .await
                .unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }

        // Wait until querying each of srv_0, srv_1, srv_2 returns all 3 records from all 3 directions.
        let check0 =
            ZebraClient::new(&[cluster[0].endpoint.to_string()], Some(&ca_pem), true).unwrap();
        let check1 =
            ZebraClient::new(&[cluster[1].endpoint.to_string()], Some(&ca_pem), true).unwrap();
        let check2 =
            ZebraClient::new(&[cluster[2].endpoint.to_string()], Some(&ca_pem), true).unwrap();

        let mut converged = false;
        for _ in 0..50 {
            let empty = |()| PersonalStateInput {
                vault_bytes: &[],
                head_meta_plain: &[],
                generation: 0,
                head_epoch: 0,
                records: &[],
                revocations: &[],
                rekeys: &[],
                push_head_always: false,
            };
            let p0 = check0.reconcile_personal(&id0, empty(())).await.unwrap();
            let p1 = check1.reconcile_personal(&id1, empty(())).await.unwrap();
            let p2 = check2.reconcile_personal(&id2, empty(())).await.unwrap();
            if p0.frames.len() == 3 && p1.frames.len() == 3 && p2.frames.len() == 3 {
                converged = true;
                break;
            }
            sleep(Duration::from_millis(80)).await;
        }
        assert!(
            converged,
            "parallel bidirectional mesh did not converge all 3 records across all 3 servers"
        );

        for h in cluster {
            h.stop().await;
        }
    });

    let _ = std::fs::remove_dir_all(&dir);
}

struct SecretCopy<'a>(&'a secret::Secret<[u8; 32]>);

fn write_distinct_frame(
    sess: &mut session::Session,
    file: &mut VaultFile,
    target_id: u32,
    title: &str,
) -> Vec<u8> {
    write_record(sess, file, Some(target_id), &titled(title)).unwrap();
    session::latest_frame(sess, target_id).unwrap()
}

#[test]
fn zero_storage_live_p2p_relay() {
    let dir = temp_dir("relay-zero");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&dir);

    block_on(async {
        let srv = start_server(ZebraServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert_pem,
            key_pem,
            extra_ca_pem: Some(ca_pem.clone()),
            data_dir: dir.join("srv"),
            peers: Vec::new(),
            mesh_interval: Duration::from_secs(60),
            allow_loopback: true,
        })
        .await
        .unwrap();

        let phrase = SeedPhrase::generate_24().unwrap();
        let client_id = kdf::client_id(phrase.seed()).unwrap();
        let dev1 = [0xA1u8; 16];
        let dev2 = [0xA2u8; 16];
        let id1 =
            Arc::new(SyncIdentity::enroll(phrase.seed(), &client_id, dev1, u64::MAX).unwrap());
        let id2 =
            Arc::new(SyncIdentity::enroll(phrase.seed(), &client_id, dev2, u64::MAX).unwrap());

        let (_, mut sess1, mut file1, _) = create_vault(
            &dir.join("v1"),
            phrase.seed(),
            KdfProfile::Fast,
            BodyAlg::Frames,
        )
        .unwrap();
        sess1.set_origin_device(dev1).unwrap();
        let r1 = write_record(&mut sess1, &mut file1, None, &titled("Relay Secret A")).unwrap();
        let r2 = write_record(&mut sess1, &mut file1, None, &titled("Relay Secret B")).unwrap();

        let mut file2 = VaultFile::new(file1.as_bytes().to_vec());
        // Clone base file with zero records by creating fresh empty from same seed and zero records, or adopt snapshot:
        // Use a fresh empty vault with the same VK (unlock dev2 from initial pre-write snapshot? Easier: device 1 and 2 start at initial file):
        drop(file2);
        let (_, mut sess_init, mut file_init, _) = create_vault(
            &dir.join("v1b"),
            phrase.seed(),
            KdfProfile::Fast,
            BodyAlg::Frames,
        )
        .unwrap();
        sess_init.set_origin_device(dev1).unwrap();
        let _ = r1;
        let _ = r2;
        file2 = VaultFile::new(file_init.as_bytes().to_vec());
        let mut sess2 = unlock_with_key(&file2, &sess_init.reopen_key(), dev2).unwrap();
        let ra = write_record(
            &mut sess_init,
            &mut file_init,
            None,
            &titled("Relay Secret 1"),
        )
        .unwrap();
        let rb = write_record(
            &mut sess_init,
            &mut file_init,
            None,
            &titled("Relay Secret 2"),
        )
        .unwrap();

        let mine1 = Arc::new(session::frontier(&sess_init).unwrap());
        let frames1 = Arc::new(vec![
            (ra, session::latest_frame(&sess_init, ra).unwrap()),
            (rb, session::latest_frame(&sess_init, rb).unwrap()),
        ]);

        let client = ZebraClient::new(&[srv.endpoint.to_string()], Some(&ca_pem), true).unwrap();
        let ep = client.preferred_endpoint().unwrap().clone();
        let tls_cfg = Arc::clone(client.tls_config());
        let sid = personal_storage_id(&id1).unwrap();
        let slot = zsync_relay_slot(id1.account_gate().unwrap().expose(), &sid).unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);

        let holder_ep = ep.clone();
        let holder_tls = Arc::clone(&tls_cfg);
        let holder_id = Arc::clone(&id1);
        let holder_task = tokio::spawn(async move {
            hold_relay_slot(holder_ep, holder_tls, slot, stop_rx, move |stream| {
                let id_h = Arc::clone(&holder_id);
                let m = Arc::clone(&mine1);
                let fr = Arc::clone(&frames1);
                async move {
                    let _ = relay_sync_responder(stream, &id_h, &m, &fr).await;
                }
            })
            .await;
        });

        let mut spliced = None;
        for _ in 0..30 {
            if let Ok(Some(stream)) = connect_relay_slot(&ep, &tls_cfg, slot).await {
                spliced = Some(stream);
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        let stream = spliced.expect("failed to splice relay connection");
        let mine2 = session::frontier(&sess2).unwrap();
        let pulled = timeout(
            Duration::from_secs(10),
            relay_sync_initiator(stream, &id2, &mine2, &[]),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(pulled.len(), 2);
        for raw in &pulled {
            accept_peer_frame(&mut sess2, &mut file2, raw).unwrap();
        }
        assert_eq!(
            open_record(&sess2, ra).unwrap().text(TAG_TITLE).unwrap(),
            Some("Relay Secret 1")
        );
        assert_eq!(
            open_record(&sess2, rb).unwrap().text(TAG_TITLE).unwrap(),
            Some("Relay Secret 2")
        );

        let repos_dir = dir.join("srv").join("repos");
        let persisted_entries: Vec<_> = std::fs::read_dir(&repos_dir).unwrap().collect();
        assert!(
            persisted_entries.is_empty(),
            "live P2P relay must keep zero files in server repos/: {persisted_entries:?}"
        );

        let _ = stop_tx.send(true);
        holder_task.abort();
        srv.stop().await;
    });

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tamper_and_revocation_regressions() {
    let dir = temp_dir("tamper-rev");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&dir);

    block_on(async {
        let cluster = start_mesh_cluster(&dir, &ca_pem, &cert_pem, &key_pem).await;
        let phrase = SeedPhrase::generate_24().unwrap();
        let client_id = kdf::client_id(phrase.seed()).unwrap();
        let dev1 = [0x31u8; 16];
        let dev2 = [0x32u8; 16];
        let dev3 = [0x33u8; 16];

        let mut id1 = SyncIdentity::enroll(phrase.seed(), &client_id, dev1, u64::MAX).unwrap();
        let id2 = SyncIdentity::enroll(phrase.seed(), &client_id, dev2, u64::MAX).unwrap();
        let id3 = SyncIdentity::enroll(phrase.seed(), &client_id, dev3, u64::MAX).unwrap();

        let (_, mut sess1, mut file1, _) = create_vault(
            &dir.join("v"),
            phrase.seed(),
            KdfProfile::Fast,
            BodyAlg::Frames,
        )
        .unwrap();
        sess1.set_origin_device(dev1).unwrap();
        let r1 = write_record(&mut sess1, &mut file1, None, &titled("Before Revoke")).unwrap();

        // Check 1-byte tamper rejection on raw record frame.
        let mut tampered_frame = session::latest_frame(&sess1, r1).unwrap();
        let last_idx = tampered_frame.len() - 1;
        tampered_frame[last_idx] ^= 0x01;
        assert!(accept_peer_frame(&mut sess1, &mut file1, &tampered_frame).is_err());

        let c0 = ZebraClient::new(&[cluster[0].endpoint.to_string()], Some(&ca_pem), true).unwrap();
        let c1 = ZebraClient::new(&[cluster[1].endpoint.to_string()], Some(&ca_pem), true).unwrap();
        let c2 = ZebraClient::new(&[cluster[2].endpoint.to_string()], Some(&ca_pem), true).unwrap();

        let head1 = encode_personal_head(sess1.vault_id(), sess1.commit_tag(), sess1.generation());
        c0.reconcile_personal(
            &id1,
            PersonalStateInput {
                vault_bytes: file1.as_bytes(),
                head_meta_plain: &head1,
                generation: sess1.generation(),
                head_epoch: 1,
                records: &collect_records(&sess1),
                revocations: &[],
                rekeys: &[],
                push_head_always: false,
            },
        )
        .await
        .unwrap();

        // Register dev2 & dev3 certs on cluster first.
        let _ = c1
            .reconcile_personal(
                &id2,
                PersonalStateInput {
                    vault_bytes: &[],
                    head_meta_plain: &[],
                    generation: 0,
                    head_epoch: 0,
                    records: &[],
                    revocations: &[],
                    rekeys: &[],
                    push_head_always: false,
                },
            )
            .await
            .unwrap();
        let _ = c2
            .reconcile_personal(
                &id3,
                PersonalStateInput {
                    vault_bytes: &[],
                    head_meta_plain: &[],
                    generation: 0,
                    head_epoch: 0,
                    records: &[],
                    revocations: &[],
                    rekeys: &[],
                    push_head_always: false,
                },
            )
            .await
            .unwrap();

        // Device 1 revokes device 2, rotates VK, and seals SignedRekey ONLY for device 3.
        id1.revoke_device(&id2.devices()[0], 1_700_000_000_000)
            .unwrap();
        rotate_vault_key(
            &mut sess1,
            &mut file1,
            &RotateCreds {
                master: phrase.seed(),
                prfs: &[],
                human_password: None,
            },
        )
        .unwrap();
        write_record(&mut sess1, &mut file1, None, &titled("After Rotate")).unwrap();
        let new_vk = sess1.reopen_key();
        let new_gen = sess1.generation();
        let grant_3 = seal_personal_rekey(
            &id3.share_publics().unwrap(),
            &dev3,
            sess1.vault_id(),
            new_gen,
            &new_vk,
        )
        .unwrap();
        let head1_rot = encode_personal_head(sess1.vault_id(), sess1.commit_tag(), new_gen);
        c0.reconcile_personal(
            &id1,
            PersonalStateInput {
                vault_bytes: file1.as_bytes(),
                head_meta_plain: &head1_rot,
                generation: new_gen,
                head_epoch: 2,
                records: &collect_records(&sess1),
                revocations: id1.revocations().all(),
                rekeys: &[(new_gen, dev3, grant_3)],
                push_head_always: true,
            },
        )
        .await
        .unwrap();

        // Wait for mesh replication of revocation + rekey to srv_1 and srv_2.
        let mut dev2_blocked = false;
        let mut dev3_rekeyed = false;
        for _ in 0..45 {
            if !dev2_blocked {
                let res2 = c1
                    .reconcile_personal(
                        &id2,
                        PersonalStateInput {
                            vault_bytes: &[],
                            head_meta_plain: &[],
                            generation: 0,
                            head_epoch: 0,
                            records: &[],
                            revocations: &[],
                            rekeys: &[],
                            push_head_always: false,
                        },
                    )
                    .await;
                if res2.is_err() {
                    dev2_blocked = true;
                }
            }
            if !dev3_rekeyed
                && let Ok(res3) = c2
                    .reconcile_personal(
                        &id3,
                        PersonalStateInput {
                            vault_bytes: &[],
                            head_meta_plain: &[],
                            generation: 0,
                            head_epoch: 0,
                            records: &[],
                            revocations: &[],
                            rekeys: &[],
                            push_head_always: false,
                        },
                    )
                    .await
                && let Some((snap3, _, _)) = res3.snapshot
                && let Some((rgen, blob)) = res3.rekeys.first()
            {
                let opened_vk =
                    open_personal_rekey(id3.share_keys(), &dev3, sess1.vault_id(), *rgen, blob)
                        .unwrap();
                let vf = VaultFile::new(snap3.to_vec());
                let sess3 = unlock_with_key(&vf, &opened_vk, dev3).unwrap();
                assert!(sess3.generation() >= new_gen);
                dev3_rekeyed = true;
            }
            if dev2_blocked && dev3_rekeyed {
                break;
            }
            sleep(Duration::from_millis(80)).await;
        }
        assert!(dev2_blocked, "revoked device 2 was not rejected by srv_1");
        assert!(
            dev3_rekeyed,
            "non-revoked device 3 failed to adopt rotated VK from srv_2"
        );

        for h in cluster {
            h.stop().await;
        }
    });

    let _ = std::fs::remove_dir_all(&dir);
}

fn generate_self_signed(dir: &Path, name: &str, san: &str) -> (Vec<u8>, Vec<u8>) {
    let key = dir.join(format!("{name}.key"));
    let crt = dir.join(format!("{name}.crt"));
    let cnf = dir.join(format!("{name}.cnf"));
    std::fs::write(
        &cnf,
        format!(
            "[req]\ndistinguished_name = dn\nx509_extensions = v3_ext\nprompt = no\n\
             [dn]\nCN = ZebraPass SelfSigned\n\
             [v3_ext]\nbasicConstraints = critical, CA:TRUE\n\
             keyUsage = critical, digitalSignature, keyCertSign\n\
             subjectAltName = {san}\n"
        ),
    )
    .unwrap();
    run_openssl(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        key.to_str().unwrap(),
    ]);
    run_openssl(&[
        "req",
        "-x509",
        "-new",
        "-nodes",
        "-key",
        key.to_str().unwrap(),
        "-sha256",
        "-days",
        "7",
        "-config",
        cnf.to_str().unwrap(),
        "-out",
        crt.to_str().unwrap(),
    ]);
    (std::fs::read(&crt).unwrap(), std::fs::read(&key).unwrap())
}

#[test]
fn self_signed_x509_pin_accepts_matching_san_and_rejects_mismatch_or_unpinned() {
    let dir = temp_dir("self-signed-pin");
    let (ok_cert, ok_key) = generate_self_signed(&dir, "ok", "IP:127.0.0.1");
    let (bad_san_cert, bad_san_key) = generate_self_signed(&dir, "bad", "IP:192.0.2.1");

    block_on(async {
        let srv_ok = start_server(ZebraServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert_pem: ok_cert.clone(),
            key_pem: ok_key,
            extra_ca_pem: Some(ok_cert.clone()),
            data_dir: dir.join("srv-ok"),
            peers: Vec::new(),
            mesh_interval: Duration::from_secs(60),
            allow_loopback: true,
        })
        .await
        .unwrap();
        let srv_bad_san = start_server(ZebraServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert_pem: bad_san_cert.clone(),
            key_pem: bad_san_key,
            extra_ca_pem: Some(bad_san_cert.clone()),
            data_dir: dir.join("srv-bad"),
            peers: Vec::new(),
            mesh_interval: Duration::from_secs(60),
            allow_loopback: true,
        })
        .await
        .unwrap();

        let phrase = SeedPhrase::generate_24().unwrap();
        let client_id = kdf::client_id(phrase.seed()).unwrap();
        let identity = SyncIdentity::enroll(phrase.seed(), &client_id, [11; 16], u64::MAX).unwrap();
        let empty = || PersonalStateInput {
            vault_bytes: &[],
            head_meta_plain: &[],
            generation: 0,
            head_epoch: 0,
            records: &[],
            revocations: &[],
            rekeys: &[],
            push_head_always: false,
        };

        let ok_ep = srv_ok.endpoint.to_string();
        let pinned_ok =
            ZebraClient::new(std::slice::from_ref(&ok_ep), Some(&ok_cert), true).unwrap();
        pinned_ok
            .reconcile_personal(&identity, empty())
            .await
            .expect("pinned self-signed cert with matching SAN succeeds");

        let unpinned = ZebraClient::new(&[ok_ep], None, true).unwrap();
        assert!(
            unpinned
                .reconcile_personal(&identity, empty())
                .await
                .is_err(),
            "unpinned self-signed cert must fail closed"
        );

        let bad_ep = srv_bad_san.endpoint.to_string();
        let pinned_bad_san = ZebraClient::new(&[bad_ep], Some(&bad_san_cert), true).unwrap();
        assert!(
            pinned_bad_san
                .reconcile_personal(&identity, empty())
                .await
                .is_err(),
            "pinned self-signed cert with mismatched SAN must fail closed"
        );

        srv_ok.stop().await;
        srv_bad_san.stop().await;
    });

    let _ = std::fs::remove_dir_all(&dir);
}
