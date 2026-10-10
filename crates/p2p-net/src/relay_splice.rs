//! Copying bytes between two joined members, within limits.
//!
//! Each direction has its own task and one fixed buffer, so memory per splice
//! is constant. A splice ends when either side closes, when it has carried
//! its bytes, run its time, or been silent too long.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

use crate::relay::State;

/// Bytes copied at once.
const CHUNK: usize = 16 * 1024;

/// What a splice has used.
struct Budget {
    carried: AtomicU64,
    limit: u64,
    ends: Instant,
    next_free: Mutex<Instant>,
    rate: u64,
}

impl Budget {
    /// Count `bytes`; `false` when the splice has had its share.
    fn take(&self, bytes: usize) -> bool {
        let carried = self
            .carried
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
        carried.saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX)) <= self.limit
            && Instant::now() < self.ends
    }

    /// How long to wait so that this splice stays under its rate.
    fn pace(&self, bytes: usize) -> Duration {
        let cost = Duration::from_micros(
            u64::try_from(bytes)
                .unwrap_or(u64::MAX)
                .saturating_mul(1_000_000)
                / self.rate.max(1),
        );
        let Ok(mut next) = self.next_free.lock() else {
            return Duration::ZERO;
        };
        let now = Instant::now();
        let start = (*next).max(now);
        *next = start + cost;
        start.duration_since(now)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ended {
    /// The sender closed.
    Closed,
    /// A limit or an error.
    Cut,
}

async fn pump(
    mut from: ReadHalf<TcpStream>,
    mut to: WriteHalf<TcpStream>,
    state: Arc<State>,
    budget: Arc<Budget>,
) -> Ended {
    let idle = state.limits.splice_idle;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let read = match timeout(idle, from.read(&mut buffer)).await {
            Ok(Ok(0)) => {
                let _ = to.shutdown().await;
                return Ended::Closed;
            }
            Ok(Ok(read)) => read,
            Ok(Err(_)) | Err(_) => return Ended::Cut,
        };
        let Some(chunk) = buffer.get(..read) else {
            return Ended::Cut;
        };
        if !budget.take(read) {
            return Ended::Cut;
        }
        if let Some(tap) = state.tap.as_ref() {
            if let Ok(mut seen) = tap.lock() {
                if seen.len() < (64 << 20) {
                    seen.extend_from_slice(chunk);
                }
            }
        }
        sleep(budget.pace(read).max(state.pace(read))).await;
        if timeout(idle, to.write_all(chunk))
            .await
            .map_or(true, |done| done.is_err())
        {
            return Ended::Cut;
        }
    }
}

/// Copy between `a` and `b` until the splice is over.
pub async fn splice(state: &Arc<State>, a: TcpStream, b: TcpStream) {
    let limits = state.limits;
    let budget = Arc::new(Budget {
        carried: AtomicU64::new(0),
        limit: limits.splice_bytes,
        ends: Instant::now() + limits.splice_time,
        next_free: Mutex::new(Instant::now()),
        rate: limits.splice_rate,
    });
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);
    let (done, mut results) = mpsc::channel::<Ended>(2);
    let run = |from, to| {
        let (state, budget, done) = (Arc::clone(state), Arc::clone(&budget), done.clone());
        tokio::spawn(async move {
            let ended = pump(from, to, state, budget).await;
            let _ = done.send(ended).await;
        })
    };
    let forward = run(a_read, b_write);
    let backward = run(b_read, a_write);
    drop(done);
    // A close lets the other direction finish what it carries; anything else
    // ends both.
    let _ = timeout(
        limits.splice_time.saturating_add(limits.splice_idle),
        async {
            if results.recv().await == Some(Ended::Closed) {
                results.recv().await;
            }
        },
    )
    .await;
    forward.abort();
    backward.abort();
}
