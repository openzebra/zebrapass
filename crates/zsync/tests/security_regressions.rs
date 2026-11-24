//! Adversarial security regression tests for `zsync`:
//! 1. Rogue server cloning (`StreamRole::PeerMesh`) is rejected both when mesh is
//!    disabled (`mesh: None`) and when mesh uses an unauthorized `ML-DSA-65` key.
//! 2. Cursor-paginated mesh sync converges `> MAX_MESH_PAGE` (`1,100+`) repositories.
//! 3. Post-revocation `SignedHead` & `RecordCommit` envelopes are opaque to a
//!    revoked device holding `account_gate` + `VK_old` (even if it steals the raw
//!    server repo file off disk), while authorized peers and BIP39 phrase restore
//!    recover cleanly.
//! 4. Shared-vault member removal over `zsync` cuts off the removed writer on
//!    `sid_0`, prevents decrypting `SignedRekey`, and transitions remaining
//!    members to `sid_1`.
//! 5. Multi-repo `WatchSub` (`[attacker_repo, victim_repo]`) bypass, unauthenticated
//!    relay slot hijack, reconnect slot-eviction race, `revision = u64::MAX`
//!    bricking, and private/loopback SSRF endpoint checks.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "adversarial security integration tests use concise setup and assertions"
)]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use kdf::zsync_vk_envelope_key;
use local::{
    PersonalDeviceEntry, Replace, SharedRepoProof, SyncIdentity, apply_rotation,
    create_shared_vault, create_vault, encode_personal_head, open_shared_rekey, plan_rotation,
    seal_master_grant, seal_personal_rekey, seal_shared_rekey, seed_matches_log,
};
use memberlog::{Action, MemberLog, Role};
use pq::{SYNC_VK_LEN, sync_verifying_key};
use record::{Document, TAG_TITLE};
use secret::Secret;
use seed::SeedPhrase;
use session::{
    BodyAlg, KdfProfile, RotateCreds, VaultFile, accept_peer_frame, accept_peer_frame_seen,
    open_record, rotate_vault_key, unlock_with_key, write_record,
};
use syncwire::encode_snapshot;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;
use zsync::limits::{MAX_MESH_PAGE, MAX_SAFE_REVISION};
use zsync::{
    MeshAuthConfig, MeshPeer, PersonalStateInput, RelayCredentials, RepoKind, RepoStore,
    SharedStateInput, StreamRole, WatchedRepo, WorkerEvent, WorkerMode, ZebraClient,
    ZebraServerConfig, ZebraWorker, connect_relay_slot, hold_relay_slot, personal_storage_id,
    relay_sync_initiator, relay_sync_responder, resolved_addr_allowed, start_server,
};

fn temp_dir(tag: &str) -> PathBuf {
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).unwrap();
    let hex = rnd.iter().fold(String::with_capacity(16), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    });
    let dir = std::env::temp_dir().join(format!("zp-sec-{tag}-{hex}"));
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
         [dn]\nCN = ZebraPass Sec Test CA\n\
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

fn mesh_vk(seed: &[u8; 32]) -> [u8; SYNC_VK_LEN] {
    sync_verifying_key(seed).unwrap().try_into().unwrap()
}

#[test]
fn attacker_rogue_server_cloning_is_rejected_in_every_mode() {
    let dir = temp_dir("rogue-clone");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&dir);

    block_on(async {
        let legit_seed = [0x41u8; 32];
        let legit_ally_seed = [0x42u8; 32];
        let rogue_seed = [0x99u8; 32];
        let legit_vk = mesh_vk(&legit_seed);
        let legit_ally_vk = mesh_vk(&legit_ally_seed);

        // 1. Standalone server (mesh: None) completely disables StreamRole::PeerMesh.
        let standalone = start_server(ZebraServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert_pem: cert_pem.clone(),
            key_pem: Secret::new(key_pem.clone()),
            extra_ca_pem: Some(ca_pem.clone()),
            data_dir: dir.join("standalone"),
            mesh: None,
            mesh_interval: Duration::from_millis(80),
            allow_private: true,
        })
        .await
        .unwrap();

        // 2. Mesh-enabled server trusting ONLY legit_ally_vk.
        let mesh_srv = start_server(ZebraServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert_pem: cert_pem.clone(),
            key_pem: Secret::new(key_pem.clone()),
            extra_ca_pem: Some(ca_pem.clone()),
            data_dir: dir.join("mesh-srv"),
            mesh: Some(MeshAuthConfig {
                seed: Secret::new(legit_seed),
                peers: Vec::new(),
                allowed_vks: vec![legit_ally_vk],
            }),
            mesh_interval: Duration::from_millis(80),
            allow_private: true,
        })
        .await
        .unwrap();

        // Victim uploads vault data to both servers.
        let phrase = SeedPhrase::generate_24().unwrap();
        let cid = kdf::client_id(phrase.seed()).unwrap();
        let dev = [0x01u8; 16];
        let id = SyncIdentity::enroll(phrase.seed(), &cid, dev, u64::MAX).unwrap();
        let (_, mut sess, mut file, _) = create_vault(
            &dir.join("victim"),
            phrase.seed(),
            KdfProfile::Fast,
            BodyAlg::Frames,
        )
        .unwrap();
        sess.set_origin_device(dev).unwrap();
        write_record(&mut sess, &mut file, None, &titled("Top Secret Vault")).unwrap();
        let vk = sess.reopen_key();
        let head = encode_personal_head(sess.vault_id(), sess.commit_tag(), sess.generation());
        let recs = collect_records(&sess);

        for ep in [&standalone.endpoint, &mesh_srv.endpoint] {
            let cli = ZebraClient::new(&[ep.to_string()], Some(&ca_pem), true).unwrap();
            cli.reconcile_personal(
                &id,
                PersonalStateInput {
                    vk: Some(&vk),
                    master_seed: None,
                    master_grant: None,
                    vault_bytes: file.as_bytes(),
                    head_meta_plain: &head,
                    generation: sess.generation(),
                    head_epoch: 1,
                    records: &recs,
                    revocations: &[],
                    rekeys: &[],
                    push_head_always: true,
                },
            )
            .await
            .unwrap();
        }

        // Attacker spins up a rogue ZebraServer pointing at BOTH victims!
        let rogue_dir = dir.join("rogue-data");
        let rogue = start_server(ZebraServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert_pem: cert_pem.clone(),
            key_pem: Secret::new(key_pem.clone()),
            extra_ca_pem: Some(ca_pem.clone()),
            data_dir: rogue_dir.clone(),
            mesh: Some(MeshAuthConfig {
                seed: Secret::new(rogue_seed),
                peers: vec![
                    MeshPeer {
                        endpoint: standalone.endpoint.clone(),
                        peer_vk: Box::new(legit_vk),
                    },
                    MeshPeer {
                        endpoint: mesh_srv.endpoint.clone(),
                        peer_vk: Box::new(legit_vk),
                    },
                ],
                allowed_vks: vec![legit_vk],
            }),
            mesh_interval: Duration::from_millis(60),
            allow_private: true,
        })
        .await
        .unwrap();

        sleep(Duration::from_millis(500)).await;
        rogue.stop().await;

        let stolen = RepoStore::open(&rogue_dir).unwrap();
        assert_eq!(
            stolen.repo_count(),
            0,
            "rogue server must obtain ZERO user repositories from standalone or mesh servers"
        );

        // Also probe raw StreamRole::PeerMesh byte directly over TLS: server must close immediately.
        let helper_cli =
            ZebraClient::new(&[standalone.endpoint.to_string()], Some(&ca_pem), true).unwrap();
        let tcp = TcpStream::connect(standalone.local_addr).await.unwrap();
        let sni = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        let mut tls = TlsConnector::from(Arc::clone(helper_cli.tls_config()))
            .connect(sni, tcp)
            .await
            .unwrap();
        tls.write_all(&[StreamRole::PeerMesh as u8]).await.unwrap();
        let mut buf = [0u8; 8];
        let n = timeout(Duration::from_secs(2), tls.read(&mut buf))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(
            n, 0,
            "unconfigured PeerMesh stream must close without leaking data"
        );

        standalone.stop().await;
        mesh_srv.stop().await;
    });

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn paginated_mesh_sync_replicates_over_1100_repositories() {
    let dir = temp_dir("mesh-page");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&dir);

    block_on(async {
        let total = MAX_MESH_PAGE + 96;
        let dir_a = dir.join("srv-a");
        let dir_b = dir.join("srv-b");

        let seed_a = [0x51u8; 32];
        let seed_b = [0x52u8; 32];
        let vk_a = mesh_vk(&seed_a);
        let vk_b = mesh_vk(&seed_b);

        let srv_a = start_server(ZebraServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert_pem: cert_pem.clone(),
            key_pem: Secret::new(key_pem.clone()),
            extra_ca_pem: Some(ca_pem.clone()),
            data_dir: dir_a.clone(),
            mesh: Some(MeshAuthConfig {
                seed: Secret::new(seed_a),
                peers: Vec::new(),
                allowed_vks: vec![vk_b],
            }),
            mesh_interval: Duration::from_millis(150),
            allow_private: true,
        })
        .await
        .unwrap();

        let cli_a = ZebraClient::new(&[srv_a.endpoint.to_string()], Some(&ca_pem), true).unwrap();
        for idx in 0..total {
            let mut mseed = [0u8; 64];
            mseed[..8].copy_from_slice(&(idx as u64 + 1).to_be_bytes());
            mseed[8] = 0xA5;
            let cid = kdf::client_id(&mseed).unwrap();
            let mut dev = [0u8; 16];
            dev[..8].copy_from_slice(&(idx as u64 + 1).to_be_bytes());
            let id = SyncIdentity::enroll(&mseed, &cid, dev, u64::MAX).unwrap();
            cli_a
                .reconcile_personal(
                    &id,
                    PersonalStateInput {
                        vk: None,
                        master_seed: None,
                        master_grant: None,
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
        }

        let srv_b = start_server(ZebraServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert_pem,
            key_pem: Secret::new(key_pem),
            extra_ca_pem: Some(ca_pem),
            data_dir: dir_b.clone(),
            mesh: Some(MeshAuthConfig {
                seed: Secret::new(seed_b),
                peers: vec![MeshPeer {
                    endpoint: srv_a.endpoint.clone(),
                    peer_vk: Box::new(vk_a),
                }],
                allowed_vks: vec![vk_a],
            }),
            mesh_interval: Duration::from_millis(120),
            allow_private: true,
        })
        .await
        .unwrap();

        let mut converged = false;
        for _ in 0..80 {
            if let Ok(store_b) = RepoStore::open(&dir_b)
                && store_b.repo_count() == total
            {
                converged = true;
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }

        srv_b.stop().await;
        srv_a.stop().await;
        assert!(
            converged,
            "paginated mesh sync must replicate all {total} repos (> MAX_MESH_PAGE)"
        );
    });

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn post_revocation_signed_head_and_frames_are_opaque_to_revoked_device() {
    let dir = temp_dir("post-revoke");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&dir);

    block_on(async {
        let srv_dir = dir.join("srv");
        let srv = start_server(ZebraServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert_pem,
            key_pem: Secret::new(key_pem),
            extra_ca_pem: Some(ca_pem.clone()),
            data_dir: srv_dir.clone(),
            mesh: None,
            mesh_interval: Duration::from_secs(60),
            allow_private: true,
        })
        .await
        .unwrap();

        let phrase = SeedPhrase::generate_24().unwrap();
        let cid = kdf::client_id(phrase.seed()).unwrap();
        let dev_owner = [0x10u8; 16];
        let dev_peer = [0x20u8; 16];
        let dev_revoked = [0x30u8; 16];

        let mut id_owner = SyncIdentity::enroll(phrase.seed(), &cid, dev_owner, u64::MAX).unwrap();
        let id_peer = SyncIdentity::enroll(phrase.seed(), &cid, dev_peer, u64::MAX).unwrap();
        let id_revoked = SyncIdentity::enroll(phrase.seed(), &cid, dev_revoked, u64::MAX).unwrap();
        let id_phrase = SyncIdentity::enroll(phrase.seed(), &cid, [0x40u8; 16], u64::MAX).unwrap();

        let (_, mut sess, mut file, _) = create_vault(
            &dir.join("v"),
            phrase.seed(),
            KdfProfile::Fast,
            BodyAlg::Frames,
        )
        .unwrap();
        sess.set_origin_device(dev_owner).unwrap();
        write_record(&mut sess, &mut file, None, &titled("Pre-Revoke")).unwrap();
        let old_vk = sess.reopen_key();
        let sid = personal_storage_id(&id_owner).unwrap();

        let cli = ZebraClient::new(&[srv.endpoint.to_string()], Some(&ca_pem), true).unwrap();
        let head1 = encode_personal_head(sess.vault_id(), sess.commit_tag(), sess.generation());
        cli.reconcile_personal(
            &id_owner,
            PersonalStateInput {
                vk: Some(&old_vk),
                master_seed: None,
                master_grant: None,
                vault_bytes: file.as_bytes(),
                head_meta_plain: &head1,
                generation: sess.generation(),
                head_epoch: 1,
                records: &collect_records(&sess),
                revocations: &[],
                rekeys: &[],
                push_head_always: true,
            },
        )
        .await
        .unwrap();

        // Owner revokes dev_revoked, rotates VK, writes a post-revocation secret,
        // and seals PersonalRekey ONLY to dev_peer + master_grant for phrase restore.
        let rev_cert = id_revoked.devices()[0].clone();
        let rev = id_owner
            .revoke_device(&rev_cert, 1_700_000_000_000)
            .unwrap();
        rotate_vault_key(
            &mut sess,
            &mut file,
            &RotateCreds {
                master: phrase.seed(),
                prfs: &[],
                human_password: Some(b"PostRevokePass!99"),
            },
        )
        .unwrap();
        let post_rec =
            write_record(&mut sess, &mut file, None, &titled("Post-Revoke Nuclear")).unwrap();
        let new_vk = sess.reopen_key();
        assert_ne!(old_vk.expose(), new_vk.expose());

        let peer_pubs = id_peer.share_publics().unwrap();
        let grant_peer = seal_personal_rekey(
            &peer_pubs,
            &dev_peer,
            sess.vault_id(),
            sess.generation(),
            &new_vk,
        )
        .unwrap();
        let mgrant = seal_master_grant(phrase.seed(), &sid, sess.vault_id(), &new_vk).unwrap();
        let head2 = encode_personal_head(sess.vault_id(), sess.commit_tag(), sess.generation());
        cli.reconcile_personal(
            &id_owner,
            PersonalStateInput {
                vk: Some(&new_vk),
                master_seed: None,
                master_grant: Some(&mgrant),
                vault_bytes: file.as_bytes(),
                head_meta_plain: &head2,
                generation: sess.generation(),
                head_epoch: 2,
                records: &collect_records(&sess),
                revocations: &[rev],
                rekeys: &[(sess.generation(), dev_peer, grant_peer)],
                push_head_always: true,
            },
        )
        .await
        .unwrap();

        // 1. Revoked device holding account_gate + old_vk tries to reconcile: MUST FAIL!
        let revoked_attempt = cli
            .reconcile_personal(
                &id_revoked,
                PersonalStateInput {
                    vk: Some(&old_vk),
                    master_seed: None,
                    master_grant: None,
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
        assert!(
            revoked_attempt.is_err(),
            "revoked device with old_vk must fail to open post-rotation SignedHead/frames"
        );

        // 2. Even if revoked device steals the raw repo file off disk, old_vk and
        //    account_gate cannot decrypt the stored SignedHead or frames, and raw
        //    vault.brby magic ("BRBY") is never in cleartext on disk.
        let mut raw_files = std::fs::read_dir(srv_dir.join("repos"))
            .unwrap()
            .map(|e| std::fs::read(e.unwrap().path()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(raw_files.len(), 1);
        let on_disk = raw_files.pop().unwrap();
        assert!(
            !on_disk.windows(4).any(|w| w == b"BRBY"),
            "vault.brby header must never appear in cleartext in server repo file"
        );
        let old_env_key = zsync_vk_envelope_key(old_vk.expose(), &sid).unwrap();
        let gate_env_key =
            kdf::personal_envelope_key(id_revoked.account_gate().unwrap().expose(), &sid).unwrap();
        assert!(frame::open(&old_env_key, &on_disk).is_err());
        assert!(frame::open(&gate_env_key, &on_disk).is_err());

        // 3. Authorized peer device adopts new_vk via hybrid PersonalRekey.
        let peer_pull = cli
            .reconcile_personal(
                &id_peer,
                PersonalStateInput {
                    vk: Some(&old_vk),
                    master_seed: None,
                    master_grant: None,
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
        let (peer_snap, _, _) = peer_pull.snapshot.unwrap();
        let (_, peer_vk) = peer_pull.adopted_vk.unwrap();
        let mut peer_file = VaultFile::new(peer_snap.to_vec());
        let mut peer_sess = unlock_with_key(&peer_file, &peer_vk, dev_peer).unwrap();
        for f in &peer_pull.frames {
            let _ = accept_peer_frame(&mut peer_sess, &mut peer_file, f);
        }
        assert_eq!(
            open_record(&peer_sess, post_rec)
                .unwrap()
                .text(TAG_TITLE)
                .unwrap(),
            Some("Post-Revoke Nuclear")
        );

        // 4. BIP39 phrase restore recovers without any online peer via master_grant.
        let phrase_pull = cli
            .reconcile_personal(
                &id_phrase,
                PersonalStateInput {
                    vk: None,
                    master_seed: Some(phrase.seed()),
                    master_grant: None,
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
        assert!(phrase_pull.snapshot.is_some());
        assert_eq!(phrase_pull.adopted_vk.unwrap().1.expose(), new_vk.expose());

        srv.stop().await;
    });

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn shared_vault_member_removal_over_zsync_cuts_off_removed_writer_and_transitions_remaining_member()
{
    let dir = temp_dir("shared-rm");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&dir);

    block_on(async {
        let srv = start_server(ZebraServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert_pem,
            key_pem: Secret::new(key_pem),
            extra_ca_pem: Some(ca_pem.clone()),
            data_dir: dir.join("srv"),
            mesh: None,
            mesh_interval: Duration::from_secs(60),
            allow_private: true,
        })
        .await
        .unwrap();
        let cli = ZebraClient::new(&[srv.endpoint.to_string()], Some(&ca_pem), true).unwrap();

        let p_alice = SeedPhrase::generate_24().unwrap();
        let p_bob = SeedPhrase::generate_24().unwrap();
        let p_malloy = SeedPhrase::generate_24().unwrap();
        let cid_alice = kdf::client_id(p_alice.seed()).unwrap();
        let cid_bob = kdf::client_id(p_bob.seed()).unwrap();
        let cid_malloy = kdf::client_id(p_malloy.seed()).unwrap();
        let id_alice =
            SyncIdentity::enroll(p_alice.seed(), &cid_alice, [0xA1; 16], u64::MAX).unwrap();
        let id_bob = SyncIdentity::enroll(p_bob.seed(), &cid_bob, [0xB1; 16], u64::MAX).unwrap();
        let id_malloy =
            SyncIdentity::enroll(p_malloy.seed(), &cid_malloy, [0xC1; 16], u64::MAX).unwrap();

        let (mut sv_alice, ref0) =
            create_shared_vault(&dir.join("alice"), &id_alice, "SecOps", KdfProfile::Fast).unwrap();
        let vault_id = ref0.vault_id;
        let anchor = ref0.anchor;

        // Owner Alice adds Bob and Malloy as Writers.
        let own_alice = id_alice.devices()[0].clone();
        for (cid, rvk) in [
            (cid_bob, *id_bob.root_vk()),
            (cid_malloy, *id_malloy.root_vk()),
        ] {
            let entry = sv_alice
                .log
                .propose(
                    &id_alice.sign_key(),
                    &own_alice,
                    Action::Add {
                        client_id: cid,
                        root_vk: Box::new(rvk),
                        role: Role::Writer,
                    },
                    1_700_000_000_000,
                )
                .unwrap();
            sv_alice.log.append(entry).unwrap();
        }
        sv_alice.save_log(&ref0.seed).unwrap();
        let r_init = sv_alice
            .edit(
                &ref0,
                &id_alice,
                local::Edit::Create(Box::new(titled("Before Removal"))),
            )
            .unwrap();
        let att_init = sv_alice.attestations(&ref0, &id_alice).unwrap();
        let snap0 = encode_snapshot(sv_alice.file.as_bytes(), &att_init).unwrap();
        let b_init = sv_alice.bundle(&ref0, &id_alice, r_init).unwrap().unwrap();
        let hdr_init =
            frame::parse(&session::latest_frame(&sv_alice.session, r_init).unwrap()).unwrap();
        let entries0: Vec<Vec<u8>> = sv_alice
            .log
            .entries()
            .iter()
            .map(|e| e.encode().unwrap())
            .collect();

        cli.reconcile_shared(
            &id_alice,
            SharedStateInput {
                shared_seed: ref0.seed.expose(),
                vault_id,
                anchor,
                member_entries: &entries0,
                snapshot_bytes: Some(&snap0),
                generation: sv_alice.session.generation(),
                head_epoch: 1,
                bundles: &[(r_init, hdr_init.revision, hdr_init.origin_device, b_init)],
                rekeys: &[],
                rotate_to: None,
            },
        )
        .await
        .unwrap();

        // Bob and Malloy both reconcile sid_0 (publishing their device SharePublics).
        for id in [&id_bob, &id_malloy] {
            let pulled = cli
                .reconcile_shared(
                    id,
                    SharedStateInput {
                        shared_seed: ref0.seed.expose(),
                        vault_id,
                        anchor,
                        member_entries: &[],
                        snapshot_bytes: None,
                        generation: 0,
                        head_epoch: 0,
                        bundles: &[],
                        rekeys: &[],
                        rotate_to: None,
                    },
                )
                .await
                .unwrap();
            assert!(pulled.snapshot.is_some());
        }

        // Alice pulls member_devices from sid_0, removes Malloy -> ref1 (seed_1),
        // seals SignedRekey ONLY to Bob, updates sid_0, and publishes rotated vault to sid_1.
        let alice_pull = cli
            .reconcile_shared(
                &id_alice,
                SharedStateInput {
                    shared_seed: ref0.seed.expose(),
                    vault_id,
                    anchor,
                    member_entries: &entries0,
                    snapshot_bytes: None,
                    generation: sv_alice.session.generation(),
                    head_epoch: 1,
                    bundles: &[],
                    rekeys: &[],
                    rotate_to: None,
                },
            )
            .await
            .unwrap();
        let bob_dev: &PersonalDeviceEntry = alice_pull
            .member_devices
            .iter()
            .find(|d| d.cert.client_id == cid_bob)
            .expect("Bob device key announced");

        let ref1 = plan_rotation(&ref0, sv_alice.log.epoch()).unwrap();
        apply_rotation(&mut sv_alice, &ref1, &id_alice, Replace::Remove(cid_malloy)).unwrap();
        let entries1: Vec<Vec<u8>> = sv_alice
            .log
            .entries()
            .iter()
            .map(|e| e.encode().unwrap())
            .collect();
        let grant_bob = seal_shared_rekey(
            &bob_dev.publics,
            &bob_dev.cert.device_id,
            &vault_id,
            &anchor,
            ref1.epoch,
            &ref1.seed,
        )
        .unwrap();

        // Push removal + Bob's hybrid grant to sid_0.
        cli.reconcile_shared(
            &id_alice,
            SharedStateInput {
                shared_seed: ref0.seed.expose(),
                vault_id,
                anchor,
                member_entries: &entries1,
                snapshot_bytes: None,
                generation: 0,
                head_epoch: 0,
                bundles: &[],
                rekeys: &[(
                    u64::from(ref1.epoch),
                    bob_dev.cert.device_id,
                    grant_bob.clone(),
                )],
                rotate_to: None,
            },
        )
        .await
        .unwrap();

        // Push rotated vault + post-removal secret to sid_1.
        let r_after = sv_alice
            .edit(
                &ref1,
                &id_alice,
                local::Edit::Create(Box::new(titled("After Malloy Removed"))),
            )
            .unwrap();
        let att1 = sv_alice.attestations(&ref1, &id_alice).unwrap();
        let snap1 = encode_snapshot(sv_alice.file.as_bytes(), &att1).unwrap();
        let b_after = sv_alice.bundle(&ref1, &id_alice, r_after).unwrap().unwrap();
        let hdr_after =
            frame::parse(&session::latest_frame(&sv_alice.session, r_after).unwrap()).unwrap();
        cli.reconcile_shared(
            &id_alice,
            SharedStateInput {
                shared_seed: ref1.seed.expose(),
                vault_id,
                anchor,
                member_entries: &entries1,
                snapshot_bytes: Some(&snap1),
                generation: sv_alice.session.generation(),
                head_epoch: 2,
                bundles: &[(
                    r_after,
                    hdr_after.revision,
                    hdr_after.origin_device,
                    b_after,
                )],
                rekeys: &[],
                rotate_to: None,
            },
        )
        .await
        .unwrap();

        // Malloy is immediately rejected on sid_0 AND cannot decrypt Bob's hybrid grant!
        let malloy_res = cli
            .reconcile_shared(
                &id_malloy,
                SharedStateInput {
                    shared_seed: ref0.seed.expose(),
                    vault_id,
                    anchor,
                    member_entries: &entries0,
                    snapshot_bytes: None,
                    generation: 1,
                    head_epoch: 1,
                    bundles: &[],
                    rekeys: &[],
                    rotate_to: None,
                },
            )
            .await;
        assert!(
            malloy_res.is_err(),
            "removed writer Malloy must be rejected by sid_0 immediately"
        );
        assert!(
            open_shared_rekey(
                id_malloy.share_keys(),
                &[0xC1; 16],
                &vault_id,
                &anchor,
                ref1.epoch,
                &grant_bob,
            )
            .is_err(),
            "Malloy must not be able to decapsulate Bob's hybrid rekey grant"
        );

        // Bob reconciles sid_0, receives his hybrid grant, verifies rotation_commit,
        // and transitions to sid_1 to read "After Malloy Removed"!
        let bob_sid0 = cli
            .reconcile_shared(
                &id_bob,
                SharedStateInput {
                    shared_seed: ref0.seed.expose(),
                    vault_id,
                    anchor,
                    member_entries: &[],
                    snapshot_bytes: None,
                    generation: 0,
                    head_epoch: 0,
                    bundles: &[],
                    rekeys: &[],
                    rotate_to: None,
                },
            )
            .await
            .unwrap();
        let merged_log =
            MemberLog::from_entries(vault_id, &bob_sid0.member_entries, &anchor).unwrap();
        assert_eq!(merged_log.epoch(), 1);
        let (_, target_dev, rk_blob) = &bob_sid0.rekeys[0];
        let bob_seed1 = open_shared_rekey(
            id_bob.share_keys(),
            target_dev,
            &vault_id,
            &anchor,
            1,
            rk_blob,
        )
        .unwrap();
        assert!(seed_matches_log(&merged_log, 1, &bob_seed1));

        let bob_sid1 = cli
            .reconcile_shared(
                &id_bob,
                SharedStateInput {
                    shared_seed: bob_seed1.expose(),
                    vault_id,
                    anchor,
                    member_entries: &[],
                    snapshot_bytes: None,
                    generation: 0,
                    head_epoch: 0,
                    bundles: &[],
                    rekeys: &[],
                    rotate_to: None,
                },
            )
            .await
            .unwrap();
        assert!(bob_sid1.snapshot.is_some());
        assert_eq!(bob_sid1.bundles.len(), 1);

        srv.stop().await;
    });

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn watch_acl_relay_reconnect_ssrf_and_revision_overflow_regressions() {
    let dir = temp_dir("watch-relay-ssrf");
    let (ca_pem, cert_pem, key_pem) = generate_test_pki(&dir);

    // 1. SSRF / private IP checks fail closed by default (`allow_private == false`).
    for forbidden in [
        "127.0.0.1:443",
        "localhost:443",
        "10.0.0.1:443",
        "172.16.5.4:443",
        "192.168.1.1:443",
        "100.64.0.1:443",
        "169.254.169.254:443",
        "[::1]:443",
        "[fd00::1]:443",
    ] {
        assert!(
            ZebraClient::new(&[forbidden.to_owned()], None, false).is_err(),
            "private/loopback endpoint {forbidden} must be rejected when allow_private=false"
        );
    }
    for bad_resolved in [
        "127.0.0.1:443",
        "10.1.2.3:443",
        "100.64.1.1:443",
        "169.254.169.254:443",
        "[fd12::1]:443",
        "0.0.0.0:443",
    ] {
        let sa: SocketAddr = bad_resolved.parse().unwrap();
        assert!(!resolved_addr_allowed(sa, false));
    }
    assert!(resolved_addr_allowed(
        "93.184.216.34:443".parse().unwrap(),
        false
    ));

    // 2. Client-side revision overflow / jump guard (`accept_peer_frame_seen`).
    {
        let p = SeedPhrase::generate_24().unwrap();
        let (_, mut sess, mut file, _) = create_vault(
            &dir.join("ovf"),
            p.seed(),
            KdfProfile::Fast,
            BodyAlg::Frames,
        )
        .unwrap();
        let fk = kdf::frame_key(sess.reopen_key().expose(), sess.vault_id(), 7).unwrap();
        let bad_frame = frame::seal(
            &fk,
            &frame::FrameMeta {
                kind: frame::KIND_REVISION,
                record_id: 7,
                revision: MAX_SAFE_REVISION + 1,
                origin_device: [0x22; 16],
                timestamp_ms: 1,
                alg: frame::ALG_CASCADE,
            },
            &titled("Overflow").encode().unwrap(),
        )
        .unwrap();
        assert!(
            accept_peer_frame_seen(&mut sess, &mut file, &bad_frame, |_| None).is_err(),
            "revision > MAX_SAFE_REVISION must be rejected so record cannot be bricked"
        );
    }

    block_on(async {
        let srv = start_server(ZebraServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert_pem,
            key_pem: Secret::new(key_pem),
            extra_ca_pem: Some(ca_pem.clone()),
            data_dir: dir.join("srv"),
            mesh: None,
            mesh_interval: Duration::from_secs(60),
            allow_private: true,
        })
        .await
        .unwrap();

        let cli =
            Arc::new(ZebraClient::new(&[srv.endpoint.to_string()], Some(&ca_pem), true).unwrap());

        // 3. Multi-repo WatchSub bypass (`[attacker_sid, victim_sid]`): must NOT enter LiveWatch!
        let p_att = SeedPhrase::generate_24().unwrap();
        let p_vic = SeedPhrase::generate_24().unwrap();
        let id_att = Arc::new(
            SyncIdentity::enroll(
                p_att.seed(),
                &kdf::client_id(p_att.seed()).unwrap(),
                [0x71; 16],
                u64::MAX,
            )
            .unwrap(),
        );
        let id_vic = SyncIdentity::enroll(
            p_vic.seed(),
            &kdf::client_id(p_vic.seed()).unwrap(),
            [0x72; 16],
            u64::MAX,
        )
        .unwrap();

        let empty = PersonalStateInput {
            vk: None,
            master_seed: None,
            master_grant: None,
            vault_bytes: &[],
            head_meta_plain: &[],
            generation: 0,
            head_epoch: 0,
            records: &[],
            revocations: &[],
            rekeys: &[],
            push_head_always: false,
        };
        cli.reconcile_personal(&id_att, empty).await.unwrap();
        cli.reconcile_personal(
            &id_vic,
            PersonalStateInput {
                vk: None,
                master_seed: None,
                master_grant: None,
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

        let att_sid = personal_storage_id(&id_att).unwrap();
        let vic_sid = personal_storage_id(&id_vic).unwrap();
        let (_, shared_unauth_sid) =
            SharedRepoProof::issue(&[0x55; 64], [0x66; 16], [0x77; 32]).unwrap();
        let (worker, mut wrx) = ZebraWorker::spawn(
            &tokio::runtime::Handle::current(),
            Arc::clone(&cli),
            Arc::clone(&id_att),
            vec![
                WatchedRepo {
                    kind: RepoKind::Personal,
                    storage_id: att_sid,
                    vault_id: [1; 16],
                    shared_proof: None,
                },
                WatchedRepo {
                    kind: RepoKind::Personal,
                    storage_id: vic_sid,
                    vault_id: [2; 16],
                    shared_proof: None,
                },
                WatchedRepo {
                    kind: RepoKind::Shared,
                    storage_id: shared_unauth_sid,
                    vault_id: [3; 16],
                    shared_proof: None,
                },
            ],
            Duration::from_secs(30),
        );
        sleep(Duration::from_millis(350)).await;
        while let Ok(ev) = wrx.try_recv() {
            assert_ne!(
                ev,
                WorkerEvent::ModeChanged(WorkerMode::LiveWatch),
                "multi-repo WatchSub with unauthorized victim repo must never enter LiveWatch"
            );
        }
        worker.stop();

        // 4. Token-guarded RelayHub reconnect race: holder_2 supersedes holder_1,
        //    and dropping holder_1 MUST NOT evict holder_2's active slot!
        let ep = cli.preferred_endpoint().unwrap().clone();
        let tls_cfg = Arc::clone(cli.tls_config());
        let creds = Arc::new(
            RelayCredentials::derive(id_att.account_gate().unwrap().expose(), &att_sid).unwrap(),
        );
        let slot = creds.slot();

        let (stop1_tx, stop1_rx) = watch::channel(false);
        let ep1 = ep.clone();
        let tls1 = Arc::clone(&tls_cfg);
        let c1 = Arc::clone(&creds);
        let id1 = Arc::clone(&id_att);
        let h1 = tokio::spawn(async move {
            hold_relay_slot(ep1, tls1, c1, stop1_rx, move |s| {
                let id_c = Arc::clone(&id1);
                async move {
                    let _ = relay_sync_responder(s, &id_c, &[], &[]).await;
                }
            })
            .await;
        });
        sleep(Duration::from_millis(180)).await;

        let (stop2_tx, stop2_rx) = watch::channel(false);
        let ep2 = ep.clone();
        let tls2 = Arc::clone(&tls_cfg);
        let c2 = Arc::clone(&creds);
        let id2 = Arc::clone(&id_att);
        let h2 = tokio::spawn(async move {
            hold_relay_slot(ep2, tls2, c2, stop2_rx, move |s| {
                let id_c = Arc::clone(&id2);
                async move {
                    let _ = relay_sync_responder(s, &id_c, &[], &[]).await;
                }
            })
            .await;
        });
        sleep(Duration::from_millis(180)).await;

        // Drop holder 1; wait for server cleanup of holder 1's stream.
        let _ = stop1_tx.send(true);
        h1.abort();
        sleep(Duration::from_millis(200)).await;

        // Holder 2 must STILL hold `slot`!
        let id_att_peer = SyncIdentity::enroll(
            p_att.seed(),
            &kdf::client_id(p_att.seed()).unwrap(),
            [0x73; 16],
            u64::MAX,
        )
        .unwrap();
        let spliced = connect_relay_slot(&ep, &tls_cfg, slot)
            .await
            .unwrap()
            .expect("closing superseded holder_1 must not evict active holder_2 slot");
        let pulled = relay_sync_initiator(spliced, &id_att_peer, &[], &[])
            .await
            .unwrap();
        assert_eq!(pulled.len(), 0);

        let _ = stop2_tx.send(true);
        h2.abort();
        srv.stop().await;
    });

    let _ = std::fs::remove_dir_all(&dir);
}
