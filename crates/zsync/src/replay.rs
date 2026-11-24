//! Bounded anti-replay nonce filter and per-IP connection / relay rate guards.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::auth::now_unix_secs;
use crate::limits::{
    MAX_CONNECTS_PER_MIN, MAX_CONNS_PER_IP, MAX_RESERVES_PER_IP, REPLAY_CAPACITY,
    WATCH_MAX_SKEW_SECS,
};

#[derive(Debug, Default)]
struct ReplayInner {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<(u64, [u8; 32])>,
}

/// Bounded expiring anti-replay cache for signed `FrontierAuth`, `WatchSub`,
/// and `RelayMsg::Reserve` requests within the clock-skew window.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    inner: Mutex<ReplayInner>,
}

impl ReplayGuard {
    /// Return `true` and record `(domain, actor, timestamp_s, nonce)` if unseen;
    /// return `false` on replay or lock poison.
    pub fn check_and_insert(
        &self,
        domain: &[u8],
        actor: &[u8; 16],
        timestamp_s: u64,
        nonce: &[u8; 16],
    ) -> bool {
        let now_s = now_unix_secs();
        let ttl = WATCH_MAX_SKEW_SECS.saturating_mul(2).saturating_add(10);
        let key: [u8; 32] = Sha256::new()
            .chain_update(b"brby/v3/zsync-replay")
            .chain_update(domain)
            .chain_update(actor)
            .chain_update(timestamp_s.to_be_bytes())
            .chain_update(nonce)
            .finalize()
            .into();
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        while let Some(&(ts, old)) = guard.order.front() {
            if now_s.saturating_sub(ts) <= ttl {
                break;
            }
            guard.order.pop_front();
            guard.seen.remove(&old);
        }
        if guard.seen.contains(&key) {
            return false;
        }
        while guard.order.len() >= REPLAY_CAPACITY {
            if let Some((_, oldest)) = guard.order.pop_front() {
                guard.seen.remove(&oldest);
            } else {
                break;
            }
        }
        guard.seen.insert(key);
        guard.order.push_back((now_s, key));
        true
    }
}

#[derive(Debug, Default)]
struct IpBucket {
    conns: usize,
    reserves: usize,
    window_s: u64,
    connects_in_window: u32,
}

/// Per-IP connection, relay reservation, and relay connect rate limiter.
#[derive(Debug, Default)]
pub struct IpLimiter {
    buckets: Mutex<HashMap<IpAddr, IpBucket>>,
}

/// RAII guard decrementing active per-IP TCP connections on drop.
#[derive(Debug)]
pub struct IpConnGuard {
    limiter: Arc<IpLimiter>,
    ip: IpAddr,
}

impl Drop for IpConnGuard {
    fn drop(&mut self) {
        self.limiter.release_conn(self.ip);
    }
}

/// RAII guard decrementing active per-IP relay slot reservations on drop.
#[derive(Debug)]
pub struct IpReserveGuard {
    limiter: Arc<IpLimiter>,
    ip: IpAddr,
}

impl Drop for IpReserveGuard {
    fn drop(&mut self) {
        self.limiter.release_reserve(self.ip);
    }
}

impl IpLimiter {
    /// Admit a new TCP connection from `ip` if below [`MAX_CONNS_PER_IP`].
    pub fn try_acquire_conn(self: &Arc<Self>, ip: IpAddr) -> Option<IpConnGuard> {
        let ip = ip.to_canonical();
        let mut guard = self.buckets.lock().ok()?;
        let entry = guard.entry(ip).or_default();
        if entry.conns >= MAX_CONNS_PER_IP {
            return None;
        }
        entry.conns = entry.conns.saturating_add(1);
        drop(guard);
        Some(IpConnGuard {
            limiter: Arc::clone(self),
            ip,
        })
    }

    /// Admit a new relay reservation from `ip` if below [`MAX_RESERVES_PER_IP`].
    pub fn try_acquire_reserve(self: &Arc<Self>, ip: IpAddr) -> Option<IpReserveGuard> {
        let ip = ip.to_canonical();
        let mut guard = self.buckets.lock().ok()?;
        let entry = guard.entry(ip).or_default();
        if entry.reserves >= MAX_RESERVES_PER_IP {
            return None;
        }
        entry.reserves = entry.reserves.saturating_add(1);
        drop(guard);
        Some(IpReserveGuard {
            limiter: Arc::clone(self),
            ip,
        })
    }

    /// Check and increment the per-minute relay `Connect` rate for `ip`.
    pub fn allow_relay_connect(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        let now_min = now_unix_secs() / 60;
        let Ok(mut guard) = self.buckets.lock() else {
            return false;
        };
        let entry = guard.entry(ip).or_default();
        if entry.window_s != now_min {
            entry.window_s = now_min;
            entry.connects_in_window = 0;
        }
        if entry.connects_in_window >= MAX_CONNECTS_PER_MIN {
            return false;
        }
        entry.connects_in_window = entry.connects_in_window.saturating_add(1);
        true
    }

    fn release_conn(&self, ip: IpAddr) {
        if let Ok(mut guard) = self.buckets.lock()
            && let Some(entry) = guard.get_mut(&ip)
        {
            entry.conns = entry.conns.saturating_sub(1);
            if entry.conns == 0 && entry.reserves == 0 {
                guard.remove(&ip);
            }
        }
    }

    fn release_reserve(&self, ip: IpAddr) {
        if let Ok(mut guard) = self.buckets.lock()
            && let Some(entry) = guard.get_mut(&ip)
        {
            entry.reserves = entry.reserves.saturating_sub(1);
            if entry.conns == 0 && entry.reserves == 0 {
                guard.remove(&ip);
            }
        }
    }
}
