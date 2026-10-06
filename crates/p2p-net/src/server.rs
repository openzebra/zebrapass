//! Serving one incoming connection: handshake, then HTTP/2 requests.
//!
//! Only authenticated devices of an account the vault trusts ever reach the
//! request stage, so a request needs no further check here. A request is
//! `GET /v1/log` (the member log) or `GET /v1/snapshot` (the vault file);
//! anything else is refused.

use std::future::poll_fn;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use h2::server::SendResponse;
use http::{Method, Response, StatusCode};
use p2p_core::suite::MAX_HANDSHAKE_MSG;
use p2p_core::{Accept, CookieSecret, Load, Responder};
use session::DeviceCert;
use tokio::net::TcpStream;

use crate::io::{bridge, now_ms, read_msg, write_msg};
use crate::view::Provider;
use local::Verdict;

/// Concurrent requests one peer may have open.
const MAX_STREAMS: u32 = 8;

/// Flow-control windows: large enough that a vault file does not crawl.
const STREAM_WINDOW: u32 = 1 << 20;
const CONNECTION_WINDOW: u32 = 4 << 20;

/// Largest piece sent at once.
const SEND_CHUNK: usize = 64 * 1024;

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

async fn send_body(respond: &mut SendResponse<Bytes>, body: Vec<u8>) -> Result<()> {
    let response = Response::builder().status(StatusCode::OK).body(())?;
    let mut data = Bytes::from(body);
    if data.is_empty() {
        let mut stream = respond.send_response(response, false)?;
        stream.send_data(Bytes::new(), true)?;
        return Ok(());
    }
    let mut stream = respond.send_response(response, false)?;
    while !data.is_empty() {
        stream.reserve_capacity(data.len().min(SEND_CHUNK));
        let granted = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(refused)??;
        let take = granted.min(data.len());
        let piece = data.split_to(take);
        stream.send_data(piece, data.is_empty())?;
    }
    Ok(())
}

fn status_only(respond: &mut SendResponse<Bytes>, status: StatusCode) -> Result<()> {
    let response = Response::builder().status(status).body(())?;
    respond.send_response(response, true)?;
    Ok(())
}

/// Largest revision a peer may push: an attestation and a sealed frame.
pub const MAX_BUNDLE: usize = syncwire::ATTESTATION_WIRE_LEN + syncwire::limits::MAX_FRAME;

async fn read_body(mut stream: h2::RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk?;
        stream.flow_control().release_capacity(chunk.len())?;
        if body.len().saturating_add(chunk.len()) > max {
            return Err(refused());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

const fn verdict_status(verdict: Verdict) -> StatusCode {
    match verdict {
        Verdict::Applied => StatusCode::OK,
        Verdict::Stale => StatusCode::CONFLICT,
        Verdict::Refused => StatusCode::FORBIDDEN,
        Verdict::Invalid => StatusCode::BAD_REQUEST,
    }
}

async fn answer<P: Provider>(
    provider: Arc<P>,
    vault_id: [u8; 16],
    account: [u8; 64],
    request: http::Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
) -> Result<()> {
    let (parts, incoming) = request.into_parts();
    let path = parts.uri.path().to_owned();
    if parts.method == Method::POST && path == "/v1/revision" {
        let Ok(bundle) = read_body(incoming, MAX_BUNDLE).await else {
            return status_only(&mut respond, StatusCode::PAYLOAD_TOO_LARGE);
        };
        let verdict = tokio::task::spawn_blocking(move || {
            provider.accept_revision(&vault_id, &account, &bundle)
        })
        .await?;
        return status_only(&mut respond, verdict_status(verdict));
    }
    if parts.method != Method::GET {
        return status_only(&mut respond, StatusCode::METHOD_NOT_ALLOWED);
    }
    let body = tokio::task::spawn_blocking(move || match path.as_str() {
        "/v1/log" => Some(provider.log(&vault_id)),
        "/v1/snapshot" => Some(provider.snapshot(&vault_id)),
        "/v1/frontier" => Some(provider.frontier(&vault_id)),
        "/v1/rekey" => Some(
            provider
                .rekey(&vault_id, &account)
                .map(|seed| seed.to_vec()),
        ),
        other => other
            .strip_prefix("/v1/revision/")
            .and_then(|id| id.parse::<u32>().ok())
            .map(|id| provider.revision(&vault_id, id)),
    })
    .await?;
    match body {
        Some(Some(bytes)) => send_body(&mut respond, bytes).await,
        Some(None) | None => status_only(&mut respond, StatusCode::NOT_FOUND),
    }
}

/// Serve HTTP/2 requests for `vault_id` over an established channel until the
/// peer closes it. `account` is the peer's authenticated account.
///
/// # Errors
///
/// An HTTP/2 error on the connection.
pub async fn serve_requests<P: Provider>(
    tcp: TcpStream,
    channel: p2p_core::Channel,
    provider: Arc<P>,
    vault_id: [u8; 16],
    account: [u8; 64],
) -> Result<()> {
    let io = bridge(tcp, channel);
    let mut connection = h2::server::Builder::new()
        .max_concurrent_streams(MAX_STREAMS)
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .handshake::<_, Bytes>(io)
        .await?;
    while let Some(accepted) = connection.accept().await {
        let (request, respond) = accepted?;
        let provider = Arc::clone(&provider);
        tokio::spawn(async move {
            let _ = answer(provider, vault_id, account, request, respond).await;
        });
    }
    Ok(())
}
