//! End-to-end PQ peer-to-peer sync over a spliced TLS relay stream.
//!
//! Runs `p2p_core`'s full `ML-KEM-768 + P-256` handshake and `Cascade`
//! encrypted [`Channel`] inside the spliced stream, trading personal-vault
//! frontiers and raw record frames directly without the relay seeing or storing
//! any vault bytes.

use anyhow::anyhow;
use local::SyncIdentity;
use p2p_core::suite::{KIND_CHALLENGE, MAX_HANDSHAKE_MSG};
use p2p_core::{
    Accept, Account, CookieSecret, Initiator, KIND_OFFSET, Load, Local, MAX_PLAINTEXT, OVERHEAD,
    Reassembler, RecvHalf, Responder, SendHalf,
};
use session::{FrontierEntry, reconcile};
use syncwire::{
    Direction, Header, MsgType, decode_frontier, decode_personal_frame, encode_frontier,
    encode_personal_frame,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::auth::now_ms;
use crate::limits::{IO_TIMEOUT, MAX_RECORDS_PER_MSG};

async fn write_hs<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) -> anyhow::Result<()> {
    let len = u32::try_from(msg.len())?;
    timeout(IO_TIMEOUT, async {
        w.write_all(&len.to_be_bytes()).await?;
        w.write_all(msg).await?;
        w.flush().await
    })
    .await??;
    Ok(())
}

async fn read_hs<R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<Vec<u8>> {
    timeout(IO_TIMEOUT, async {
        let mut hdr = [0u8; 4];
        r.read_exact(&mut hdr).await?;
        let len = usize::try_from(u32::from_be_bytes(hdr))?;
        if len > MAX_HANDSHAKE_MSG {
            anyhow::bail!("handshake message too large");
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf).await?;
        Ok(buf)
    })
    .await?
}

async fn write_chan<W: AsyncWrite + Unpin>(
    w: &mut W,
    send: &mut SendHalf,
    ty: MsgType,
    req_id: u32,
    dir: Direction,
    payload: &[u8],
) -> anyhow::Result<()> {
    let header = Header::new(ty, req_id, payload.len(), dir)?;
    let head = header.encode();
    let lead_len = payload.len().min(MAX_PLAINTEXT - head.len());
    let (lead, rest) = payload
        .split_at_checked(lead_len)
        .ok_or_else(|| anyhow!("split failed"))?;
    let mut first = Vec::with_capacity(head.len() + lead.len());
    first.extend_from_slice(&head);
    first.extend_from_slice(lead);
    send_piece(w, send, &first).await?;
    for piece in rest.chunks(MAX_PLAINTEXT) {
        send_piece(w, send, piece).await?;
    }
    w.flush().await?;
    Ok(())
}

async fn send_piece<W: AsyncWrite + Unpin>(
    w: &mut W,
    send: &mut SendHalf,
    plain: &[u8],
) -> anyhow::Result<()> {
    let wire = send.seal(plain)?;
    let len = u32::try_from(wire.len())?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&wire).await?;
    Ok(())
}

async fn read_chan<R: AsyncRead + Unpin>(
    r: &mut R,
    recv: &mut RecvHalf,
    reasm: &mut Reassembler,
) -> anyhow::Result<p2p_core::Message> {
    let mut out = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        timeout(IO_TIMEOUT, r.read_exact(&mut hdr)).await??;
        let len = usize::try_from(u32::from_be_bytes(hdr))?;
        if len > MAX_PLAINTEXT + OVERHEAD {
            anyhow::bail!("channel piece too large");
        }
        let mut wire = vec![0u8; len];
        timeout(IO_TIMEOUT, r.read_exact(&mut wire)).await??;
        let plain = recv.open(&wire)?;
        reasm.feed(plain.expose(), &mut out)?;
        if let Some(msg) = out.into_iter().next() {
            return Ok(msg);
        }
        out = Vec::new();
    }
}

struct PersonalGate {
    route: [u8; 16],
    cert: session::DeviceCert,
    sign: session::DeviceSignKey,
    accounts: [Account; 1],
    revoked: Vec<session::Revocation>,
    gate_keys: [secret::Secret<[u8; 32]>; 1],
}

impl PersonalGate {
    fn from_identity(identity: &SyncIdentity) -> anyhow::Result<Self> {
        let gate = identity
            .account_gate()
            .ok_or_else(|| anyhow!("missing account gate"))?;
        let route = kdf::account_route_id(gate)?;
        let cert = identity
            .devices()
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("missing device cert"))?;
        let gk = kdf::p2p_gate_key(gate.expose(), &route)?;
        Ok(Self {
            route,
            accounts: [Account {
                client_id: cert.client_id,
                root_vk: Box::new(*identity.root_vk()),
            }],
            cert,
            sign: identity.sign_key(),
            revoked: identity.revocations().all().to_vec(),
            gate_keys: [gk],
        })
    }

    fn as_local(&self) -> Local<'_> {
        Local {
            vault_id: self.route,
            cert: &self.cert,
            sign: &self.sign,
            accounts: &self.accounts,
            revoked: &self.revoked,
            gate_keys: &self.gate_keys,
        }
    }
}

/// Run the initiator side of an end-to-end PQ personal sync over a spliced
/// TLS relay stream: fetches frames `mine` lacks and pushes frames the peer lacks.
///
/// # Errors
///
/// Handshake, authentication, or stream failure.
pub async fn relay_sync_initiator<S>(
    mut stream: S,
    identity: &SyncIdentity,
    mine: &[FrontierEntry],
    local_frames: &[(u32, Vec<u8>)],
) -> anyhow::Result<Vec<Vec<u8>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let gate = PersonalGate::from_identity(identity)?;
    let local = gate.as_local();
    let gate_key = local
        .gate_keys
        .first()
        .ok_or_else(|| anyhow!("missing gate key"))?;
    let (initiator, hello) = Initiator::start(gate_key, now_ms())?;
    write_hs(&mut stream, &hello).await?;
    let mut reply = read_hs(&mut stream).await?;
    if reply.get(KIND_OFFSET) == Some(&KIND_CHALLENGE) {
        let solved = initiator.solve(&reply)?;
        write_hs(&mut stream, &solved).await?;
        reply = read_hs(&mut stream).await?;
    }
    let (finish, established) = initiator.finish(&local, &reply, now_ms())?;
    write_hs(&mut stream, &finish).await?;

    let (mut send, mut recv) = established.channel.into_halves();
    let mut reasm = Reassembler::new(Direction::Response);

    write_chan(
        &mut stream,
        &mut send,
        MsgType::Frontier,
        1,
        Direction::Request,
        &[],
    )
    .await?;
    let resp = read_chan(&mut stream, &mut recv, &mut reasm).await?;
    let theirs = decode_frontier(resp.payload.expose())?;
    let plan = reconcile(mine, &theirs);

    let mut pulled = Vec::new();
    let mut req_id = 2u32;
    for id in plan.pull.into_iter().take(MAX_RECORDS_PER_MSG) {
        let want_rev = theirs
            .iter()
            .find(|e| e.record_id == id)
            .map_or(0, |e| e.revision);
        let payload = syncwire::Want {
            record_id: id,
            revision: want_rev,
        }
        .encode();
        write_chan(
            &mut stream,
            &mut send,
            MsgType::Want,
            req_id,
            Direction::Request,
            &payload,
        )
        .await?;
        let msg = read_chan(&mut stream, &mut recv, &mut reasm).await?;
        if msg.header.ty == MsgType::Bundle
            && let Ok(frame) = decode_personal_frame(msg.payload.expose())
        {
            pulled.push(frame);
        }
        req_id = req_id.saturating_add(1);
    }

    for id in plan.push.into_iter().take(MAX_RECORDS_PER_MSG) {
        if let Some((_, raw)) = local_frames.iter().find(|(rid, _)| *rid == id)
            && let Ok(bundle) = encode_personal_frame(raw)
        {
            write_chan(
                &mut stream,
                &mut send,
                MsgType::Bundle,
                req_id,
                Direction::Request,
                &bundle,
            )
            .await?;
            let _ = read_chan(&mut stream, &mut recv, &mut reasm).await?;
            req_id = req_id.saturating_add(1);
        }
    }

    Ok(pulled)
}

/// Run the responder side of an end-to-end PQ personal sync over a spliced TLS
/// relay stream, returning any raw record frames pushed by the initiator.
///
/// # Errors
///
/// Handshake, authentication, or stream failure.
pub async fn relay_sync_responder<S>(
    mut stream: S,
    identity: &SyncIdentity,
    mine: &[FrontierEntry],
    local_frames: &[(u32, Vec<u8>)],
) -> anyhow::Result<Vec<Vec<u8>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let gate = PersonalGate::from_identity(identity)?;
    let local = gate.as_local();
    let cookies = CookieSecret::generate()?;
    let mut msg = read_hs(&mut stream).await?;
    let channel = {
        let mut established = None;
        for _ in 0..2 {
            match Responder::accept(&local, &cookies, Load { difficulty: 0 }, &msg, now_ms())? {
                Accept::Challenge(chal) => {
                    write_hs(&mut stream, &chal).await?;
                    msg = read_hs(&mut stream).await?;
                }
                Accept::Reply(resp, reply) => {
                    write_hs(&mut stream, &reply).await?;
                    let finish = read_hs(&mut stream).await?;
                    established = Some(resp.finish(&local, &finish, now_ms())?.channel);
                    break;
                }
            }
        }
        established.ok_or_else(|| anyhow!("handshake incomplete"))?
    };

    let (mut send, mut recv) = channel.into_halves();
    let mut reasm = Reassembler::new(Direction::Request);
    let mut pushed = Vec::new();
    while let Ok(req) = read_chan(&mut stream, &mut recv, &mut reasm).await {
        match req.header.ty {
            MsgType::Frontier => {
                let wire = encode_frontier(mine)?;
                write_chan(
                    &mut stream,
                    &mut send,
                    MsgType::Frontier,
                    req.header.req_id,
                    Direction::Response,
                    &wire,
                )
                .await?;
            }
            MsgType::Want => {
                let want = syncwire::Want::try_from(req.payload.expose().as_slice())?;
                if let Some((_, raw)) = local_frames.iter().find(|(id, _)| *id == want.record_id)
                    && let Ok(bundle) = encode_personal_frame(raw)
                {
                    write_chan(
                        &mut stream,
                        &mut send,
                        MsgType::Bundle,
                        req.header.req_id,
                        Direction::Response,
                        &bundle,
                    )
                    .await?;
                } else {
                    write_chan(
                        &mut stream,
                        &mut send,
                        MsgType::Refused,
                        req.header.req_id,
                        Direction::Response,
                        &[],
                    )
                    .await?;
                }
            }
            MsgType::Bundle => {
                if let Ok(frame) = decode_personal_frame(req.payload.expose()) {
                    pushed.push(frame);
                }
                write_chan(
                    &mut stream,
                    &mut send,
                    MsgType::Bundle,
                    req.header.req_id,
                    Direction::Response,
                    &[],
                )
                .await?;
            }
            _ => {
                write_chan(
                    &mut stream,
                    &mut send,
                    MsgType::Refused,
                    req.header.req_id,
                    Direction::Response,
                    &[],
                )
                .await?;
            }
        }
    }
    Ok(pushed)
}
