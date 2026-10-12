//! Serving one incoming connection: handshake, then mux requests.
//!
//! Only authenticated devices of an account the vault trusts ever reach the
//! request stage. Requests are answered concurrently, at most
//! [`PIPELINE_DEPTH`] at a time; a peer that breaks the protocol, asks too
//! much, or is refused too often is disconnected.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use p2p_core::suite::MAX_HANDSHAKE_MSG;
use p2p_core::{Accept, CookieSecret, Inbound, Load, Message, Outcome, Responder};
use session::DeviceCert;
use syncwire::limits::PIPELINE_DEPTH;
use syncwire::{Direction, Header};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::io::{mux, now_ms, read_msg, write_msg};
use crate::limits::{Limits, Tickets};
use crate::serve::{Answer, Serve};
use crate::view::Provider;

fn refused() -> anyhow::Error {
    anyhow!("connection refused")
}

/// The first message of a connection, read before anything else is done.
///
/// # Errors
///
/// `connection error` for a bad read.
pub async fn first_message(tcp: &mut TcpStream) -> Result<Vec<u8>> {
    read_msg(tcp, MAX_HANDSHAKE_MSG).await
}

/// Run the responder side of the handshake on `first`, sending replies and
/// reading the rest from `tcp`. Returns the vault the peer asked for, by
/// index into `views`, and the authenticated peer.
///
/// # Errors
///
/// `handshake failed` or `connection error` for every failure.
pub async fn authenticate(
    tcp: &mut TcpStream,
    views: &[crate::view::VaultView],
    cookies: &CookieSecret,
    load: Load,
    first: Vec<u8>,
) -> Result<(usize, DeviceCert, p2p_core::Channel)> {
    let locals: Vec<_> = views.iter().map(crate::view::VaultView::local).collect();
    let index = Responder::route(&locals, &first, now_ms())?;
    let local = locals.get(index).ok_or_else(refused)?;
    let mut message = first;
    for _ in 0..2 {
        match Responder::accept(local, cookies, load, &message, now_ms())? {
            Accept::Challenge(challenge) => {
                write_msg(tcp, &challenge).await?;
                message = read_msg(tcp, MAX_HANDSHAKE_MSG).await?;
            }
            Accept::Reply(responder, reply) => {
                write_msg(tcp, &reply).await?;
                let finish = read_msg(tcp, MAX_HANDSHAKE_MSG).await?;
                let established = responder.finish(local, &finish, now_ms())?;
                return Ok((index, established.peer, established.channel));
            }
        }
    }
    Err(refused())
}

/// Serve requests for `vault_id` over an established channel until the peer
/// closes it, with the default [`Limits`]. `account` is the peer's
/// authenticated account.
///
/// # Errors
///
/// The connection could not be set up.
pub async fn serve_requests<P: Provider>(
    tcp: TcpStream,
    channel: p2p_core::Channel,
    provider: Arc<P>,
    vault_id: [u8; 16],
    account: [u8; 64],
) -> Result<()> {
    let tickets = Tickets::new(Limits::default());
    serve_requests_with(tcp, channel, provider, vault_id, account, &tickets).await
}

enum Event {
    Request(Message),
    Done(u32, Outcome),
    Closed,
}

struct Reply {
    body: Zeroizing<Vec<u8>>,
    header: Header,
}

async fn deliver<P: Provider>(
    serve: &Serve<P>,
    message: Message,
    out: &mpsc::Sender<Reply>,
) -> Outcome {
    let Message { header, payload } = message;
    let mut answer = serve.answer(header.ty, payload.expose()).await;
    let header = Header::new(
        answer.ty,
        header.req_id,
        answer.body.len(),
        Direction::Response,
    )
    .or_else(|_| {
        answer = Answer::refused();
        Header::new(answer.ty, header.req_id, 0, Direction::Response)
    });
    let Ok(header) = header else {
        return Outcome::Refused;
    };
    let outcome = answer.outcome;
    let reply = Reply {
        body: answer.body,
        header,
    };
    if out.send(reply).await.is_err() {
        return Outcome::Refused;
    }
    outcome
}

/// [`serve_requests`] under the limits of `tickets`: the connection is closed
/// when it sits idle, when too many of its requests fail, or when it makes
/// too many.
///
/// # Errors
///
/// The connection could not be set up.
pub async fn serve_requests_with<P: Provider>(
    tcp: TcpStream,
    channel: p2p_core::Channel,
    provider: Arc<P>,
    vault_id: [u8; 16],
    account: [u8; 64],
    tickets: &Arc<Tickets>,
) -> Result<()> {
    let limits = *tickets.limits();
    let peer = tcp.peer_addr()?;
    let (mut reader, mut writer) = mux(tcp, channel, Direction::Request)?;
    let (events, mut inbox) = mpsc::channel::<Event>(PIPELINE_DEPTH * 2);
    let (out, mut outbox) = mpsc::channel::<Reply>(PIPELINE_DEPTH);
    let read_task = tokio::spawn({
        let events = events.clone();
        async move {
            while let Ok(message) = reader.next().await {
                if events.send(Event::Request(message)).await.is_err() {
                    return;
                }
            }
            let _ = events.send(Event::Closed).await;
        }
    });
    let write_task = tokio::spawn({
        let events = events.clone();
        async move {
            while let Some(reply) = outbox.recv().await {
                let sent = timeout(limits.request, writer.send(&reply.header, &reply.body)).await;
                if !matches!(sent, Ok(Ok(()))) {
                    break;
                }
            }
            let _ = events.send(Event::Closed).await;
        }
    });
    let serve = Arc::new(Serve::new(
        provider,
        Arc::clone(tickets),
        peer,
        account,
        vault_id,
    ));
    let mut inbound = Inbound::new(limits.max_requests, limits.max_chunks, limits.max_failed);
    loop {
        let event = match timeout(limits.idle, inbox.recv()).await {
            Ok(Some(event)) => event,
            Err(_) if inbound.in_flight() > 0 => continue,
            Ok(None) | Err(_) => break,
        };
        let proceed = match event {
            Event::Closed => false,
            Event::Done(req_id, outcome) => inbound.finish(req_id, outcome).is_ok(),
            Event::Request(message) => {
                inbound.admit(&message.header).is_ok() && {
                    let (serve, out, events) = (Arc::clone(&serve), out.clone(), events.clone());
                    let req_id = message.header.req_id;
                    tokio::spawn(async move {
                        let outcome = timeout(limits.request, deliver(&serve, message, &out))
                            .await
                            .unwrap_or(Outcome::Refused);
                        let _ = events.send(Event::Done(req_id, outcome)).await;
                    });
                    true
                }
            }
        };
        if !proceed {
            break;
        }
    }
    read_task.abort();
    write_task.abort();
    Ok(())
}
