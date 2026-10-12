//! The encrypted, ordered channel that carries sync traffic after the
//! handshake.
//!
//! Each message is one cascade frame (AEGIS-256 inside Kuznyechik-CTR with
//! HMAC) under a per-direction key. The frame header is authenticated data
//! and carries the sender, the direction and a counter, so a replayed,
//! reordered, reflected or re-addressed message fails to open.

use anyhow::{anyhow, Result};
use frame::{
    open, parse, seal, FrameMeta, ALG_CASCADE, CASCADE_OVERHEAD, HEADER_LEN, KIND_REVISION, TAG_LEN,
};
use secret::Secret;

/// Largest plaintext of one message; larger payloads are chunked.
pub const MAX_PLAINTEXT: usize = 64 * 1024;

/// Wire overhead of one message.
pub const OVERHEAD: usize = HEADER_LEN + CASCADE_OVERHEAD + TAG_LEN;

/// Messages one key may protect before the channel must be replaced.
pub const MAX_MESSAGES: u64 = 1 << 32;

const STREAM_I2R: u32 = 1;
const STREAM_R2I: u32 = 2;

fn channel_error() -> anyhow::Error {
    anyhow!("channel error")
}

/// The two per-direction traffic keys of one handshake.
pub struct TrafficKeys {
    pub i2r: Secret<[u8; 32]>,
    pub r2i: Secret<[u8; 32]>,
}

/// Which side of the handshake this device was.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Initiator,
    Responder,
}

/// The sending half of a channel.
#[derive(Debug)]
pub struct SendHalf {
    key: Secret<[u8; 32]>,
    counter: u64,
    stream: u32,
    local_id: [u8; 16],
}

/// The receiving half of a channel.
#[derive(Debug)]
pub struct RecvHalf {
    key: Secret<[u8; 32]>,
    counter: u64,
    stream: u32,
    peer_id: [u8; 16],
}

impl SendHalf {
    /// Encrypt one message.
    ///
    /// # Errors
    ///
    /// `channel error` for an oversized plaintext or an exhausted key;
    /// entropy failure.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT || self.counter >= MAX_MESSAGES {
            return Err(channel_error());
        }
        let meta = FrameMeta {
            kind: KIND_REVISION,
            record_id: self.stream,
            revision: self.counter,
            origin_device: self.local_id,
            timestamp_ms: 0,
            alg: ALG_CASCADE,
        };
        let wire = seal(&self.key, &meta, plaintext)?;
        self.counter += 1;
        Ok(wire)
    }
}

impl RecvHalf {
    /// Decrypt the next message from the peer.
    ///
    /// # Errors
    ///
    /// `channel error` for any message that is not exactly the next one from
    /// the peer on this stream, or that does not authenticate. The counter
    /// advances only on success.
    pub fn open(&mut self, wire: &[u8]) -> Result<Secret<Vec<u8>>> {
        if wire.len() > MAX_PLAINTEXT + OVERHEAD || self.counter >= MAX_MESSAGES {
            return Err(channel_error());
        }
        let header = parse(wire).map_err(|_| channel_error())?;
        if header.alg != ALG_CASCADE
            || header.kind != KIND_REVISION
            || header.record_id != self.stream
            || header.revision != self.counter
            || header.origin_device != self.peer_id
        {
            return Err(channel_error());
        }
        let plaintext = open(&self.key, wire).map_err(|_| channel_error())?;
        self.counter += 1;
        Ok(plaintext)
    }
}

/// One end of an established channel. A message that fails to open means
/// the connection is compromised or corrupt: drop it.
#[derive(Debug)]
pub struct Channel {
    send: SendHalf,
    recv: RecvHalf,
}

impl Channel {
    #[must_use]
    pub fn new(side: Side, keys: TrafficKeys, local_id: [u8; 16], peer_id: [u8; 16]) -> Self {
        let TrafficKeys { i2r, r2i } = keys;
        let (send_key, recv_key, send_stream, recv_stream) = match side {
            Side::Initiator => (i2r, r2i, STREAM_I2R, STREAM_R2I),
            Side::Responder => (r2i, i2r, STREAM_R2I, STREAM_I2R),
        };
        Self {
            send: SendHalf {
                key: send_key,
                counter: 0,
                stream: send_stream,
                local_id,
            },
            recv: RecvHalf {
                key: recv_key,
                counter: 0,
                stream: recv_stream,
                peer_id,
            },
        }
    }

    /// The authenticated peer.
    #[must_use]
    pub const fn peer_id(&self) -> &[u8; 16] {
        &self.recv.peer_id
    }

    /// Encrypt one message.
    ///
    /// # Errors
    ///
    /// As [`SendHalf::seal`].
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.send.seal(plaintext)
    }

    /// Decrypt the next message from the peer.
    ///
    /// # Errors
    ///
    /// As [`RecvHalf::open`].
    pub fn open(&mut self, wire: &[u8]) -> Result<Secret<Vec<u8>>> {
        self.recv.open(wire)
    }

    /// Split into independent halves, so two tasks can send and receive at
    /// once.
    #[must_use]
    pub fn into_halves(self) -> (SendHalf, RecvHalf) {
        (self.send, self.recv)
    }
}
