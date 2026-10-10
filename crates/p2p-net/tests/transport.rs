#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::panic,
    reason = "tests may unwrap and index"
)]

use std::future::Future;
use std::sync::{Arc, Mutex};

use p2p_core::{Account, Channel, CookieSecret, Initiator, Load, Message, Reassembler};
use p2p_net::{
    authenticate, fetch, first_message, now_ms, serve_requests_with, Conn, Dialing, FetchError,
    Limits, Policy, Provider, Service, SnapshotSource, Tickets, VaultView,
};
use session::{issue_device_cert, sync_verifying_key, DeviceSignKey, Revocation};
use syncwire::limits::CHUNK_LEN;
use syncwire::{ChunkRequest, Direction, Header, MsgType, SnapHead};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const VAULT: [u8; 16] = [0x77; 16];
const MARKER: &[u8] = b"ZEBRA-PLAINTEXT-MARKER-0123456789";

fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

struct Dev {
    root: [u8; 32],
    id: u8,
    client: u8,
}

impl Dev {
    fn view(&self, trusted: &[(u8, [u8; 32])], gate: u8, revoked: Vec<Revocation>) -> VaultView {
        let sign = DeviceSignKey::from_seed(&[self.id; 32]);
        let cert = issue_device_cert(
            &self.root,
            &[self.client; 64],
            &[self.id; 16],
            &sign.verifying_key().unwrap(),
            u64::MAX,
            u64::from(self.id),
        )
        .unwrap();
        VaultView {
            vault_id: VAULT,
            cert,
            sign,
            accounts: trusted
                .iter()
                .map(|(client, root)| Account {
                    client_id: [*client; 64],
                    root_vk: Box::new(sync_verifying_key(root).unwrap().try_into().unwrap()),
                })
                .collect(),
            revoked,
            gate_keys: vec![kdf::p2p_gate_key(&[gate; 32], &VAULT).unwrap()],
            dialing: Dialing {
                policy: Policy { loopback: true },
                trusted: Vec::new(),
            },
        }
    }
}

struct Served {
    server: Dev,
    trusted: Vec<(u8, [u8; 32])>,
    gate: u8,
    revoked: Mutex<Vec<Revocation>>,
    log: Vec<u8>,
    snapshot: std::path::PathBuf,
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.snapshot);
    }
}

impl Provider for Served {
    fn views(&self) -> Vec<VaultView> {
        vec![self.server.view(
            &self.trusted,
            self.gate,
            self.revoked.lock().unwrap().clone(),
        )]
    }

    fn log(&self, vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        (vault_id == &VAULT).then(|| self.log.clone())
    }

    fn snapshot_source(&self, vault_id: &[u8; 16]) -> Option<SnapshotSource> {
        let file = std::fs::File::open(&self.snapshot).ok()?;
        let file_len = file.metadata().ok()?.len();
        (vault_id == &VAULT).then_some(SnapshotSource {
            prefix: Vec::new(),
            file,
            file_len,
        })
    }
}

fn served(snapshot: Vec<u8>) -> Arc<Served> {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let path = std::env::temp_dir().join(format!(
        "zebrapass-transport-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&path, snapshot).unwrap();
    Arc::new(Served {
        server: Dev {
            root: [1; 32],
            id: 0xA1,
            client: 1,
        },
        trusted: vec![(1, [1; 32])],
        gate: 5,
        revoked: Mutex::new(Vec::new()),
        log: vec![0x4C; 700],
        snapshot: path,
    })
}

const fn client_dev() -> Dev {
    Dev {
        root: [1; 32],
        id: 0xB2,
        client: 1,
    }
}

async fn run_server(listener: TcpListener, provider: Arc<Served>, load: Load, limits: Limits) {
    let tickets = Tickets::new(limits);
    let cookies = Arc::new(CookieSecret::generate().unwrap());
    loop {
        let Ok((mut tcp, _)) = listener.accept().await else {
            return;
        };
        let (provider, cookies, tickets) = (
            Arc::clone(&provider),
            Arc::clone(&cookies),
            Arc::clone(&tickets),
        );
        tokio::spawn(async move {
            let Ok(first) = first_message(&mut tcp).await else {
                return;
            };
            let views = provider.views();
            let Ok((index, peer, channel)) =
                authenticate(&mut tcp, &views, &cookies, load, first).await
            else {
                return;
            };
            let vault = views[index].vault_id;
            let _ =
                serve_requests_with(tcp, channel, provider, vault, peer.client_id, &tickets).await;
        });
    }
}

async fn start(provider: Arc<Served>, load: Load) -> String {
    start_limited(provider, load, Limits::default()).await
}

async fn start_limited(provider: Arc<Served>, load: Load, limits: Limits) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(run_server(listener, provider, load, limits));
    addr
}

struct Raw {
    tcp: TcpStream,
    channel: Channel,
    reassembler: Reassembler,
    next_id: u32,
}

async fn send_framed(tcp: &mut TcpStream, bytes: &[u8]) {
    tcp.write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    tcp.write_all(bytes).await.unwrap();
}

async fn read_framed(tcp: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    tcp.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; usize::try_from(u32::from_be_bytes(len)).ok()?];
    tcp.read_exact(&mut body).await.ok()?;
    Some(body)
}

/// A connection that has done the handshake and nothing else, so a test can
/// say exactly what goes over the channel.
async fn raw(view: &VaultView, addr: &str) -> Raw {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    let (initiator, hello) = Initiator::start(view.gate_keys.first().unwrap(), now_ms()).unwrap();
    send_framed(&mut tcp, &hello).await;
    let reply = read_framed(&mut tcp).await.unwrap();
    let (finish, established) = initiator.finish(&view.local(), &reply, now_ms()).unwrap();
    send_framed(&mut tcp, &finish).await;
    Raw {
        tcp,
        channel: established.channel,
        reassembler: Reassembler::new(Direction::Response),
        next_id: 1,
    }
}

impl Raw {
    async fn send_bytes(&mut self, plain: &[u8]) {
        let sealed = self.channel.seal(plain).unwrap();
        send_framed(&mut self.tcp, &sealed).await;
    }

    async fn request(&mut self, ty: MsgType, payload: &[u8]) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let header = Header::new(ty, id, payload.len(), Direction::Request).unwrap();
        self.send_bytes(&[&header.encode()[..], payload].concat())
            .await;
        id
    }

    /// The next reply, or `None` once the server has closed the connection.
    async fn reply(&mut self) -> Option<Message> {
        let mut out = Vec::new();
        while out.is_empty() {
            let sealed = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                read_framed(&mut self.tcp),
            )
            .await
            .ok()??;
            let plain = self.channel.open(&sealed).ok()?;
            self.reassembler.feed(plain.expose(), &mut out).ok()?;
        }
        Some(out.remove(0))
    }
}

fn big_snapshot() -> Vec<u8> {
    (0..3 * 1024 * 1024u32)
        .map(|n| u8::try_from(n.wrapping_mul(2_654_435_761) >> 24).unwrap())
        .collect()
}

#[test]
fn a_member_fetches_the_log_and_a_multi_megabyte_vault_file() {
    let snapshot = big_snapshot();
    let provider = served(snapshot.clone());
    block_on(async {
        let addr = start(Arc::clone(&provider), Load::default()).await;
        let view = client_dev().view(&[(1, [1; 32])], 5, Vec::new());
        let fetched = fetch(&view, &addr).await.unwrap();
        assert_eq!(fetched.peer.device_id, [0xA1; 16]);
        assert_eq!(fetched.log, provider.log);
        assert_eq!(fetched.snapshot, snapshot);
        assert!(fetched.rekey.is_none());
    });
}

#[test]
fn a_busy_server_makes_the_client_solve_a_puzzle_transparently() {
    let provider = served(vec![9; 1000]);
    block_on(async {
        let addr = start(provider, Load { difficulty: 10 }).await;
        let view = client_dev().view(&[(1, [1; 32])], 5, Vec::new());
        let fetched = fetch(&view, &addr).await.unwrap();
        assert_eq!(fetched.snapshot, vec![9; 1000]);
    });
}

#[test]
fn a_message_that_breaks_the_protocol_closes_the_connection() {
    let provider = served(vec![1; 50_000]);
    block_on(async {
        let addr = start(provider, Load::default()).await;
        let view = member_view();
        let header =
            |ty: u8, id: u32, len: u32| [&[ty][..], &id.to_be_bytes(), &len.to_be_bytes()].concat();
        let cases = [
            ("an unknown type", header(99, 1, 0)),
            ("type zero", header(0, 1, 0)),
            ("a reply type sent as a request", header(13, 1, 8)),
            ("a status type sent as a request", header(15, 1, 0)),
            ("a length over the limit of its type", header(12, 1, 9)),
            ("a huge length", header(6, 1, u32::MAX)),
            (
                "a payload on a type that carries none",
                [header(4, 1, 1), vec![0]].concat(),
            ),
        ];
        for (name, bytes) in cases {
            let mut raw = raw(&view, &addr).await;
            raw.send_bytes(&bytes).await;
            assert!(raw.reply().await.is_none(), "{name}");
        }
        let mut raw = raw(&view, &addr).await;
        raw.request(MsgType::Ping, &7u64.to_be_bytes()).await;
        let pong = raw.reply().await.unwrap();
        assert_eq!(pong.header.ty, MsgType::Pong);
        assert_eq!(pong.payload.expose(), &7u64.to_be_bytes());
        raw.request(MsgType::Ping, &8u64.to_be_bytes()).await;
        assert_eq!(raw.reply().await.unwrap().header.req_id, 2);
    });
}

#[test]
fn a_stranger_a_foreign_root_and_a_revoked_device_never_get_a_byte() {
    let provider = served(MARKER.repeat(100));
    block_on(async {
        let addr = start(Arc::clone(&provider), Load::default()).await;

        // Wrong gate key: dropped before any asymmetric work.
        let stranger = client_dev().view(&[(1, [1; 32])], 6, Vec::new());
        assert!(fetch(&stranger, &addr).await.is_err());

        // Right gate key but a certificate from another root.
        let intruder = Dev {
            root: [2; 32],
            id: 0xC3,
            client: 1,
        }
        .view(&[(1, [1; 32])], 5, Vec::new());
        assert!(fetch(&intruder, &addr).await.is_err());

        // Right root, but revoked by the server's list.
        let member = Dev {
            root: [1; 32],
            id: 0xD4,
            client: 1,
        };
        let honest = client_dev().view(&[(1, [1; 32])], 5, Vec::new());
        let revoked_view = member.view(&[(1, [1; 32])], 5, Vec::new());
        let revocation =
            session::issue_revocation(&honest.sign, &honest.cert, &revoked_view.cert, 1).unwrap();
        provider.revoked.lock().unwrap().push(revocation);
        assert!(fetch(&revoked_view, &addr).await.is_err());
        assert!(fetch(&honest, &addr).await.is_ok());
    });
}

#[test]
fn the_wire_carries_no_plaintext() {
    let provider = served(MARKER.repeat(2000));
    block_on(async {
        let target = start(provider, Load::default()).await;
        let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap().to_string();
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            let server = TcpStream::connect(target).await.unwrap();
            let (mut cr, mut cw) = client.into_split();
            let (mut sr, mut sw) = server.into_split();
            let up_log = Arc::clone(&log);
            let up = tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    let n = cr.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    up_log.lock().unwrap().extend_from_slice(&buf[..n]);
                    if sw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
            let mut buf = vec![0u8; 8192];
            loop {
                let n = sr.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                log.lock().unwrap().extend_from_slice(&buf[..n]);
                if cw.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = up.await;
        });
        let view = client_dev().view(&[(1, [1; 32])], 5, Vec::new());
        let fetched = fetch(&view, &proxy_addr).await.unwrap();
        assert_eq!(fetched.snapshot.len(), MARKER.len() * 2000);
        let wire = seen.lock().unwrap().clone();
        assert!(
            wire.len() > MARKER.len() * 2000,
            "the whole body crossed the wire"
        );
        assert!(!wire.windows(MARKER.len()).any(|window| window == MARKER));
        let log_run = vec![0x4C; 64];
        assert!(
            !wire.windows(log_run.len()).any(|window| window == log_run),
            "the member log does not cross in the clear"
        );
        assert!(
            !wire.windows(MARKER.len()).any(|window| window == MARKER),
            "no snapshot byte crosses in the clear"
        );
    });
}

#[test]
fn a_failed_fetch_says_why() {
    let provider = served(vec![1; 100]);
    block_on(async {
        let addr = start(provider, Load::default()).await;
        let honest = client_dev().view(&[(1, [1; 32])], 5, Vec::new());

        let closed = {
            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            probe.local_addr().unwrap().to_string()
        };
        assert_eq!(
            fetch(&honest, &closed).await.unwrap_err(),
            FetchError::Unreachable
        );

        let stranger = client_dev().view(&[(1, [1; 32])], 6, Vec::new());
        assert_eq!(
            fetch(&stranger, &addr).await.unwrap_err(),
            FetchError::Refused
        );

        let intruder = Dev {
            root: [2; 32],
            id: 0xC3,
            client: 1,
        }
        .view(&[(1, [1; 32])], 5, Vec::new());
        assert_eq!(
            fetch(&intruder, &addr).await.unwrap_err(),
            FetchError::Refused
        );

        let mut conn = Conn::connect(&honest, &addr).await.unwrap();
        assert_eq!(
            conn.announce().await.unwrap_err(),
            FetchError::Failed,
            "a peer that does not hold the vault file says no"
        );
    });
}

fn member_view() -> VaultView {
    client_dev().view(&[(1, [1; 32])], 5, Vec::new())
}

#[test]
fn an_address_the_policy_forbids_is_never_dialed() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let own = listener.local_addr().unwrap().to_string();
    let mut view = member_view();
    view.dialing = Dialing::default();
    block_on(async {
        for hint in [
            own.as_str(),
            "localhost:7447",
            "169.254.169.254:80",
            "10.0.0.8:80",
            "[::1]:7447",
            "[fd00::1]:7447",
            "192.168.1.9:0",
            "no-port",
        ] {
            assert_eq!(
                Conn::connect(&view, hint).await.err(),
                Some(FetchError::Unreachable),
                "{hint}"
            );
        }
    });
    assert!(listener.accept().is_err(), "nothing connected");
}

#[test]
fn a_connection_that_keeps_asking_for_what_it_may_not_have_is_closed() {
    let provider = served(vec![1; 100]);
    block_on(async {
        let limits = Limits {
            max_failed: 3,
            ..Limits::default()
        };
        let addr = start_limited(provider, Load::default(), limits).await;
        let mut conn = Conn::connect(&member_view(), &addr).await.unwrap();
        for _ in 0..3 {
            assert!(conn.announce().await.is_err());
        }
        assert!(
            conn.log().await.is_err(),
            "the connection is gone, not merely refused"
        );
        let mut again = Conn::connect(&member_view(), &addr).await.unwrap();
        assert!(again.log().await.is_ok());
    });
}

#[test]
fn a_connection_may_only_make_so_many_requests() {
    let provider = served(vec![1; 100]);
    block_on(async {
        let limits = Limits {
            max_requests: 3,
            ..Limits::default()
        };
        let addr = start_limited(provider, Load::default(), limits).await;
        let mut conn = Conn::connect(&member_view(), &addr).await.unwrap();
        for token in 0..3 {
            conn.ping(token).await.unwrap();
        }
        assert!(conn.ping(3).await.is_err());
    });
}

#[test]
fn an_idle_connection_is_closed_and_a_busy_one_is_not() {
    let provider = served(vec![1; 100]);
    block_on(async {
        let limits = Limits {
            idle: std::time::Duration::from_millis(300),
            ..Limits::default()
        };
        let addr = start_limited(provider, Load::default(), limits).await;
        let mut idle = Conn::connect(&member_view(), &addr).await.unwrap();
        let mut busy = Conn::connect(&member_view(), &addr).await.unwrap();
        for _ in 0..5 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            assert!(busy.ping(1).await.is_ok());
        }
        assert!(idle.ping(1).await.is_err());
    });
}

#[test]
fn one_address_cannot_hold_every_handshake_slot() {
    let provider = served(vec![1; 100]);
    let limits = Limits {
        per_address_handshakes: 2,
        ..Limits::default()
    };
    let node = Service::start_with(Some("127.0.0.1:0"), Arc::clone(&provider), limits).unwrap();
    let addr = node.local_addr().unwrap();
    block_on(async {
        let first = TcpStream::connect(addr).await.unwrap();
        let second = TcpStream::connect(addr).await.unwrap();
        let mut third = TcpStream::connect(addr).await.unwrap();
        let mut byte = [0u8; 1];
        let closed =
            tokio::time::timeout(std::time::Duration::from_secs(2), third.read(&mut byte)).await;
        assert!(
            matches!(closed, Ok(Ok(0) | Err(_))),
            "the third silent connection is dropped at once"
        );
        drop((first, second));
        // The two slots free up as soon as their sockets close.
        let view = member_view();
        let mut fetched = None;
        for _ in 0..50 {
            fetched = fetch(&view, &addr.to_string()).await.ok();
            if fetched.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(fetched.is_some());
    });
}

fn resident_kib(pid: u32) -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

/// The node of the memory measurement, run as a process of its own so that
/// its memory is not mixed with that of the clients. It is started by
/// `memory_of_the_serving_process` and does nothing when run by itself.
#[test]
#[ignore = "child of the memory measurement"]
fn memory_server_child() {
    use std::io::{BufRead, Write};
    if std::env::var("ZP_MEM_CHILD").is_err() {
        return;
    }
    let max_snapshots: usize = std::env::var("ZP_MEM_CAP")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(2);
    let provider = served(vec![7u8; file_mib() * 1024 * 1024]);
    block_on(async {
        let limits = Limits {
            per_address_peers: 64,
            per_address_handshakes: 64,
            max_snapshots,
            // Opening 32 connections takes a debug build minutes; they must
            // not be closed as idle before the measurement starts.
            idle: std::time::Duration::from_secs(3600),
            ..Limits::default()
        };
        let addr = start_limited(provider, Load::default(), limits).await;
        println!("ZP-ADDR {addr}");
        std::io::stdout().flush().unwrap();
        tokio::task::spawn_blocking(|| {
            let mut line = String::new();
            while std::io::stdin()
                .lock()
                .read_line(&mut line)
                .is_ok_and(|n| n > 0)
            {
                line.clear();
            }
        })
        .await
        .unwrap();
    });
}

/// Size of the vault file the measurement moves, in MiB (`ZP_MEM_FILE_MIB`,
/// default 2): a debug build seals 64 KiB chunks slowly enough that 32
/// concurrent copies of a larger file outlast the client's request timeout.
fn file_mib() -> usize {
    std::env::var("ZP_MEM_FILE_MIB")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(2)
}

struct ServerProcess {
    child: std::process::Child,
    addr: String,
}

impl ServerProcess {
    fn start(max_snapshots: usize) -> Self {
        use std::io::BufRead;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "memory_server_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ZP_MEM_CHILD", "1")
            .env("ZP_MEM_CAP", max_snapshots.to_string())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let addr = std::io::BufReader::new(out)
            .lines()
            .map_while(Result::ok)
            .find_map(|line| line.split_once("ZP-ADDR ").map(|(_, addr)| addr.to_owned()))
            .unwrap();
        Self { child, addr }
    }

    fn rss(&self) -> u64 {
        resident_kib(self.child.id())
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Resident memory of the server process while `work` runs: its peak over
/// what it held when `work` began.
async fn peak_over<F: std::future::Future>(server: &ServerProcess, work: F) -> (u64, F::Output) {
    let pid = server.child.id();
    let start = resident_kib(pid);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sampler = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut peak = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                peak = peak.max(resident_kib(pid));
            }
            peak.max(resident_kib(pid))
        })
    };
    let out = work.await;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    (sampler.join().unwrap().saturating_sub(start), out)
}

/// What the serving process alone costs: per idle connection, for one
/// transfer of the file, and for every held connection fetching at once under the cap on
/// concurrent snapshots (`ZP_MEM_CAP`, default 2). The node runs as a child
/// process and each phase gets a fresh one, because a process keeps memory it
/// has freed. Clients live in this process and are not counted.
/// `ZP_MEM_CAP=32 cargo test -p p2p-net --test transport -- --ignored --nocapture memory_of`.
#[test]
#[ignore = "measurement: run on request"]
fn memory_of_the_serving_process() {
    let held_count: u64 = std::env::var("ZP_MEM_HELD")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(12);
    let max_snapshots: usize = std::env::var("ZP_MEM_CAP")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(2);
    block_on(async {
        let open_many = |server: &ServerProcess| {
            let addr = server.addr.clone();
            async move {
                let mut held = Vec::new();
                for _ in 0..held_count {
                    let mut conn = Conn::connect(&member_view(), &addr).await.unwrap();
                    conn.log().await.unwrap();
                    held.push(conn);
                }
                held
            }
        };

        let (per_connection, one) = if std::env::var("ZP_MEM_ONLY_STORM").is_ok() {
            (0, 0)
        } else {
            let server = ServerProcess::start(max_snapshots);
            let mut warm = Conn::connect(&member_view(), &server.addr).await.unwrap();
            warm.log().await.unwrap();
            drop(warm);
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let base = server.rss();
            let (_, opened) = peak_over(&server, open_many(&server)).await;
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let per_connection = server.rss().saturating_sub(base) / held_count;
            drop(opened);
            drop(server);

            let server = ServerProcess::start(max_snapshots);
            let mut conn = Conn::connect(&member_view(), &server.addr).await.unwrap();
            conn.log().await.unwrap();
            let (one, snapshot) =
                peak_over(&server, async { conn.snapshot().await.unwrap() }).await;
            assert_eq!(snapshot.len(), file_mib() * 1024 * 1024);
            drop(conn);
            drop(server);

            (per_connection, one)
        };
        let server = ServerProcess::start(max_snapshots);
        let held = open_many(&server).await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let (storm, served_ok) = peak_over(&server, async {
            let downloads: Vec<_> = held
                .into_iter()
                .map(|mut conn| {
                    tokio::spawn(async move { conn.snapshot().await.map(|file| file.len()) })
                })
                .collect();
            let mut ok = 0;
            for download in downloads {
                match download.await.unwrap() {
                    Ok(_) => ok += 1,
                    Err(error) => eprintln!("a fetch failed: {error}"),
                }
            }
            ok
        })
        .await;
        println!(
            "server process (cap {max_snapshots}): {per_connection} KiB per idle connection; one {} MiB transfer +{one} KiB; {held_count} concurrent fetches +{storm} KiB, {served_ok} served at once",
            file_mib()
        );
    });
}

#[test]
fn a_busy_node_says_so_and_that_does_not_count_against_the_peer() {
    let provider = served(vec![1; 100]);
    block_on(async {
        let limits = Limits {
            max_snapshots: 0,
            max_failed: 2,
            ..Limits::default()
        };
        let addr = start_limited(provider, Load::default(), limits).await;
        let mut conn = Conn::connect(&member_view(), &addr).await.unwrap();
        for _ in 0..6 {
            assert_eq!(conn.snapshot().await.unwrap_err(), FetchError::Failed);
        }
        conn.ping(1).await.unwrap();
        let mut raw = raw(&member_view(), &addr).await;
        raw.request(MsgType::SnapReq, &[]).await;
        assert_eq!(raw.reply().await.unwrap().header.ty, MsgType::Busy);
    });
}

/// Begin a snapshot transfer on `raw` and return its head.
async fn begin(raw: &mut Raw) -> SnapHead {
    raw.request(MsgType::SnapReq, &[]).await;
    let reply = raw.reply().await.unwrap();
    assert_eq!(reply.header.ty, MsgType::SnapHead);
    SnapHead::try_from(&reply.payload.expose()[..]).unwrap()
}

#[test]
fn the_node_serves_only_so_many_snapshots_at_once_and_frees_the_place() {
    let provider = served(vec![5; 3 * CHUNK_LEN]);
    block_on(async {
        let limits = Limits {
            max_snapshots: 1,
            ..Limits::default()
        };
        let addr = start_limited(provider, Load::default(), limits).await;
        let mut holder = raw(&member_view(), &addr).await;
        begin(&mut holder).await;

        let mut other = Conn::connect(&member_view(), &addr).await.unwrap();
        assert!(other.snapshot().await.is_err(), "the only place is taken");

        drop(holder);
        let mut got = None;
        for _ in 0..50 {
            got = other.snapshot().await.ok();
            if got.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(got.unwrap(), vec![5; 3 * CHUNK_LEN]);
    });
}

#[test]
fn a_transfer_is_released_when_its_last_byte_has_gone_out() {
    let provider = served(vec![5; CHUNK_LEN + 10]);
    block_on(async {
        let limits = Limits {
            max_snapshots: 1,
            ..Limits::default()
        };
        let addr = start_limited(provider, Load::default(), limits).await;
        let mut one = Conn::connect(&member_view(), &addr).await.unwrap();
        let mut two = Conn::connect(&member_view(), &addr).await.unwrap();
        for _ in 0..3 {
            assert_eq!(one.snapshot().await.unwrap().len(), CHUNK_LEN + 10);
            assert_eq!(two.snapshot().await.unwrap().len(), CHUNK_LEN + 10);
        }
    });
}

#[test]
fn a_chunk_of_another_transfer_or_out_of_range_is_not_served() {
    let provider = served(vec![5; 2 * CHUNK_LEN]);
    block_on(async {
        let addr = start(provider, Load::default()).await;
        let mut raw = raw(&member_view(), &addr).await;
        let head = begin(&mut raw).await;
        assert_eq!(head.size, u64::try_from(2 * CHUNK_LEN).unwrap());
        assert_eq!((head.chunk_size as usize, head.chunk_count), (CHUNK_LEN, 2));
        let id = head.id;

        raw.request(
            MsgType::SnapReq,
            &ChunkRequest {
                id: [7; 32],
                offset: 0,
            }
            .encode(),
        )
        .await;
        assert_eq!(raw.reply().await.unwrap().header.ty, MsgType::Stale);

        raw.request(
            MsgType::SnapReq,
            &ChunkRequest {
                id,
                offset: u64::MAX,
            }
            .encode(),
        )
        .await;
        assert_eq!(raw.reply().await.unwrap().header.ty, MsgType::Refused);

        raw.request(MsgType::SnapReq, &ChunkRequest { id, offset: 5 }.encode())
            .await;
        assert_eq!(
            raw.reply().await.unwrap().header.ty,
            MsgType::Refused,
            "a chunk starts on a chunk boundary"
        );

        let at = u64::try_from(CHUNK_LEN).unwrap();
        raw.request(MsgType::SnapReq, &ChunkRequest { id, offset: at }.encode())
            .await;
        let second = raw.reply().await.unwrap();
        assert_eq!(second.header.ty, MsgType::SnapChunk);
        assert_eq!(second.header.len as usize, 32 + 8 + 8 + 4 + CHUNK_LEN);
    });
}

#[test]
fn chunk_requests_have_a_budget_of_their_own() {
    let provider = served(vec![1; 3 * CHUNK_LEN]);
    block_on(async {
        let limits = Limits {
            max_chunks: 2,
            ..Limits::default()
        };
        let addr = start_limited(provider, Load::default(), limits).await;
        let mut conn = Conn::connect(&member_view(), &addr).await.unwrap();
        assert!(conn.snapshot().await.is_err());
        let mut again = Conn::connect(&member_view(), &addr).await.unwrap();
        again.ping(1).await.unwrap();
        again.log().await.unwrap();
    });
}

#[test]
fn the_node_tells_a_peer_the_address_it_sees() {
    let provider = served(vec![1; 10]);
    block_on(async {
        let addr = start(provider, Load::default()).await;
        let mut conn = Conn::connect(&member_view(), &addr).await.unwrap();
        let seen = conn.whoami().await.unwrap();
        assert!(seen.ip().is_loopback());
        assert_ne!(seen.port(), 0);
    });
}

#[test]
fn a_pipeline_holds_at_most_four_requests() {
    let provider = served(vec![1; 10]);
    block_on(async {
        let addr = start(provider, Load::default()).await;
        let mut conn = Conn::connect(&member_view(), &addr).await.unwrap();
        let wanted: Vec<(u32, u64)> = (1..=5).map(|id| (id, 1)).collect();
        assert!(conn.revisions(&wanted).await.is_err());
        let found = conn.revisions(&wanted[..4]).await.unwrap();
        assert_eq!(found, vec![None; 4], "the provider holds no records");
        conn.ping(1).await.unwrap();
    });
}

#[test]
fn replies_arrive_in_request_order_whatever_order_they_finish_in() {
    let provider = served(vec![3; 5 * CHUNK_LEN + 17]);
    block_on(async {
        let addr = start(provider, Load::default()).await;
        let mut conn = Conn::connect(&member_view(), &addr).await.unwrap();
        assert_eq!(conn.snapshot().await.unwrap(), vec![3; 5 * CHUNK_LEN + 17]);
        assert_eq!(conn.log().await.unwrap(), vec![0x4C; 700]);
    });
}

#[test]
fn several_connections_can_each_fetch_a_snapshot_at_once_under_a_big_enough_cap() {
    const FETCHERS: usize = 4;
    let provider = served(vec![9; 4 * CHUNK_LEN]);
    block_on(async {
        let limits = Limits {
            max_snapshots: FETCHERS,
            ..Limits::default()
        };
        let addr = start_limited(provider, Load::default(), limits).await;
        let mut conns = Vec::new();
        for _ in 0..FETCHERS {
            conns.push(Conn::connect(&member_view(), &addr).await.unwrap());
        }
        let downloads: Vec<_> = conns
            .into_iter()
            .map(|mut conn| tokio::spawn(async move { conn.snapshot().await }))
            .collect();
        for download in downloads {
            assert_eq!(download.await.unwrap().unwrap(), vec![9; 4 * CHUNK_LEN]);
        }
    });
}
