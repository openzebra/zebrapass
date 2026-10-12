//! The request/reply flow inside a channel, with no I/O: reassembling
//! messages from channel plaintext, correlating replies on the dialing side,
//! and bounding what the answering side accepts. A returned error means the
//! peer broke the protocol and the connection must be closed.

use anyhow::{anyhow, Result};
use secret::Secret;
use syncwire::limits::PIPELINE_DEPTH;
use syncwire::{Direction, Header, MsgType};

fn broken() -> anyhow::Error {
    anyhow!("connection error")
}

/// One complete message.
#[derive(Debug)]
pub struct Message {
    /// The decoded header.
    pub header: Header,
    /// The payload, whose length the header bounded before it was read.
    pub payload: Secret<Vec<u8>>,
}

/// Turns the plaintext of channel messages, which may split or join
/// protocol messages anywhere, back into messages.
#[derive(Debug)]
pub struct Reassembler {
    head: [u8; syncwire::limits::MUX_HEADER_LEN],
    body: Vec<u8>,
    pending: Option<Header>,
    head_len: usize,
    incoming: Direction,
}

impl Reassembler {
    /// A reader of messages that travel in `incoming` direction.
    #[must_use]
    pub const fn new(incoming: Direction) -> Self {
        Self {
            head: [0; syncwire::limits::MUX_HEADER_LEN],
            body: Vec::new(),
            pending: None,
            head_len: 0,
            incoming,
        }
    }

    /// Whether a message is half-read.
    #[must_use]
    pub const fn is_mid_message(&self) -> bool {
        self.pending.is_some() || self.head_len > 0
    }

    /// Feed channel plaintext; finished messages are pushed to `out`.
    ///
    /// # Errors
    ///
    /// `connection error` for an unknown type, a type not allowed in this
    /// direction, or a length over the limit of its type.
    pub fn feed(&mut self, mut bytes: &[u8], out: &mut Vec<Message>) -> Result<()> {
        while !bytes.is_empty() {
            bytes = match self.pending {
                Some(header) => self.fill_body(header, bytes, out)?,
                None => self.fill_head(bytes, out)?,
            };
        }
        Ok(())
    }

    fn fill_head<'a>(&mut self, bytes: &'a [u8], out: &mut Vec<Message>) -> Result<&'a [u8]> {
        let want = self.head.len() - self.head_len;
        let (take, rest) = bytes.split_at(want.min(bytes.len()));
        self.head
            .get_mut(self.head_len..self.head_len + take.len())
            .ok_or_else(broken)?
            .copy_from_slice(take);
        self.head_len += take.len();
        if self.head_len == self.head.len() {
            self.head_len = 0;
            let header = Header::decode(&self.head, self.incoming).map_err(|_| broken())?;
            self.begin(header, out);
        }
        Ok(rest)
    }

    fn begin(&mut self, header: Header, out: &mut Vec<Message>) {
        if header.len == 0 {
            out.push(Message {
                header,
                payload: Secret::new(Vec::new()),
            });
        } else {
            self.pending = Some(header);
        }
    }

    fn fill_body<'a>(
        &mut self,
        header: Header,
        bytes: &'a [u8],
        out: &mut Vec<Message>,
    ) -> Result<&'a [u8]> {
        let len = usize::try_from(header.len).map_err(|_| broken())?;
        let want = len.checked_sub(self.body.len()).ok_or_else(broken)?;
        let (take, rest) = bytes.split_at(want.min(bytes.len()));
        self.body.extend_from_slice(take);
        if self.body.len() == len {
            self.pending = None;
            out.push(Message {
                header,
                payload: Secret::new(std::mem::take(&mut self.body)),
            });
        }
        Ok(rest)
    }
}

/// What a reply was.
#[derive(Debug)]
pub enum Reply {
    /// The answer to the request.
    Payload(Secret<Vec<u8>>),
    /// The node is serving as much as it will; try later.
    Busy,
    /// Turned away.
    Refused,
    /// What the request named has moved on.
    Stale,
}

/// A request and its reply.
#[derive(Debug)]
pub struct Done {
    /// The reply.
    pub reply: Reply,
    /// The request it answers.
    pub request: MsgType,
    /// Its request number.
    pub req_id: u32,
}

#[derive(Debug)]
struct Pending {
    deadline_ms: u64,
    req_id: u32,
    ty: MsgType,
}

/// The dialing side: numbers requests, keeps at most [`PIPELINE_DEPTH`] of
/// them open, and matches each reply to the request it answers.
#[derive(Debug)]
pub struct Dispatcher {
    pending: Vec<Pending>,
    timeout_ms: u64,
    next_id: u32,
}

const fn answers(request: MsgType, reply: MsgType) -> bool {
    match request {
        MsgType::Announce => matches!(reply, MsgType::Announce),
        MsgType::LogHead => matches!(reply, MsgType::LogHead),
        MsgType::LogChunk => matches!(reply, MsgType::LogChunk),
        MsgType::Frontier => matches!(reply, MsgType::Frontier),
        MsgType::Want | MsgType::Bundle => matches!(reply, MsgType::Bundle),
        MsgType::SnapReq => matches!(reply, MsgType::SnapHead | MsgType::SnapChunk),
        MsgType::Rekey => matches!(reply, MsgType::Rekey),
        MsgType::Peers => matches!(reply, MsgType::Peers),
        MsgType::WhoAmI => matches!(reply, MsgType::WhoAmI),
        MsgType::Ping => matches!(reply, MsgType::Pong),
        MsgType::SnapChunk
        | MsgType::SnapHead
        | MsgType::Pong
        | MsgType::Busy
        | MsgType::Refused
        | MsgType::Stale => false,
    }
}

impl Dispatcher {
    /// A dispatcher that gives each request `timeout_ms` to be answered.
    #[must_use]
    pub const fn new(timeout_ms: u64) -> Self {
        Self {
            pending: Vec::new(),
            timeout_ms,
            next_id: 1,
        }
    }

    /// Requests still waiting for an answer.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }

    /// Number a request of `ty` with a payload of `len` bytes. `None` means
    /// the pipeline is full: wait for an answer first.
    ///
    /// # Errors
    ///
    /// The type may not be sent as a request, or `len` is over its limit.
    pub fn request(&mut self, ty: MsgType, len: usize, now_ms: u64) -> Result<Option<Header>> {
        if self.pending.len() >= PIPELINE_DEPTH {
            return Ok(None);
        }
        let header = Header::new(ty, self.next_id, len, Direction::Request)?;
        self.next_id = self.next_id.wrapping_add(1);
        self.pending.push(Pending {
            deadline_ms: now_ms.saturating_add(self.timeout_ms),
            req_id: header.req_id,
            ty,
        });
        Ok(Some(header))
    }

    /// Match a reply to its request.
    ///
    /// # Errors
    ///
    /// `connection error` for a reply to nothing that is open, or of a type
    /// that cannot answer the request.
    pub fn on_message(&mut self, message: Message) -> Result<Done> {
        let Message { header, payload } = message;
        let at = self
            .pending
            .iter()
            .position(|pending| pending.req_id == header.req_id)
            .ok_or_else(broken)?;
        let reply = match header.ty {
            MsgType::Busy => Reply::Busy,
            MsgType::Refused => Reply::Refused,
            MsgType::Stale => Reply::Stale,
            MsgType::Announce
            | MsgType::LogHead
            | MsgType::LogChunk
            | MsgType::Frontier
            | MsgType::Want
            | MsgType::Bundle
            | MsgType::SnapReq
            | MsgType::SnapChunk
            | MsgType::SnapHead
            | MsgType::Rekey
            | MsgType::Peers
            | MsgType::WhoAmI
            | MsgType::Ping
            | MsgType::Pong => {
                let request = self.pending.get(at).ok_or_else(broken)?.ty;
                if !answers(request, header.ty) {
                    return Err(broken());
                }
                Reply::Payload(payload)
            }
        };
        let done = self.pending.swap_remove(at);
        Ok(Done {
            reply,
            request: done.ty,
            req_id: done.req_id,
        })
    }

    /// The request number of one that has waited too long, if any. The
    /// caller closes the connection.
    #[must_use]
    pub fn expired(&self, now_ms: u64) -> Option<u32> {
        self.pending
            .iter()
            .find(|pending| now_ms >= pending.deadline_ms)
            .map(|pending| pending.req_id)
    }
}

/// How a request ended, for the answering side's budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Answered.
    Served,
    /// Turned away; counts against the peer.
    Refused,
    /// Moved on; does not count against the peer.
    Stale,
    /// The node was at its limit; does not count against the peer.
    Busy,
}

/// The answering side: which requests are open, and how many the peer may
/// still make or get wrong.
#[derive(Debug)]
pub struct Inbound {
    open: Vec<u32>,
    max_requests: u32,
    max_chunks: u32,
    max_failed: u32,
    requests: u32,
    chunks: u32,
    failed: u32,
}

impl Inbound {
    /// Budgets for one connection: requests of any kind, chunk requests
    /// (which a large transfer makes many of), and refused requests.
    #[must_use]
    pub const fn new(max_requests: u32, max_chunks: u32, max_failed: u32) -> Self {
        Self {
            open: Vec::new(),
            max_requests,
            max_chunks,
            max_failed,
            requests: 0,
            chunks: 0,
            failed: 0,
        }
    }

    /// Requests being served.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.open.len()
    }

    /// Accept a request header, or say the connection must close.
    ///
    /// # Errors
    ///
    /// `connection error` for a request number already open, more than
    /// [`PIPELINE_DEPTH`] open requests, or an exhausted budget.
    pub fn admit(&mut self, header: &Header) -> Result<()> {
        if self.open.len() >= PIPELINE_DEPTH || self.open.contains(&header.req_id) {
            return Err(broken());
        }
        let (counter, max) = match header.ty {
            MsgType::LogChunk | MsgType::SnapReq => (&mut self.chunks, self.max_chunks),
            MsgType::Announce
            | MsgType::LogHead
            | MsgType::Frontier
            | MsgType::Want
            | MsgType::Bundle
            | MsgType::SnapChunk
            | MsgType::SnapHead
            | MsgType::Rekey
            | MsgType::Peers
            | MsgType::WhoAmI
            | MsgType::Ping
            | MsgType::Pong
            | MsgType::Busy
            | MsgType::Refused
            | MsgType::Stale => (&mut self.requests, self.max_requests),
        };
        if *counter >= max {
            return Err(broken());
        }
        *counter += 1;
        self.open.push(header.req_id);
        Ok(())
    }

    /// Record how a request ended.
    ///
    /// # Errors
    ///
    /// `connection error` when the peer has been refused too often, or the
    /// request was not open.
    pub fn finish(&mut self, req_id: u32, outcome: Outcome) -> Result<()> {
        let at = self
            .open
            .iter()
            .position(|open| *open == req_id)
            .ok_or_else(broken)?;
        self.open.swap_remove(at);
        match outcome {
            Outcome::Served | Outcome::Stale | Outcome::Busy => Ok(()),
            Outcome::Refused => {
                self.failed += 1;
                if self.failed >= self.max_failed {
                    Err(broken())
                } else {
                    Ok(())
                }
            }
        }
    }

    /// A request that took too long counts against the peer too.
    ///
    /// # Errors
    ///
    /// As [`Inbound::finish`].
    pub fn timed_out(&mut self, req_id: u32) -> Result<()> {
        self.finish(req_id, Outcome::Refused)
    }
}
