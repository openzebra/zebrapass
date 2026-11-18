//! WebTunnel-style HTTP camouflage and active-probe resistance.
//!
//! Unauthenticated probes (`GET /`, `/favicon.ico`, wrong secret path slugs, or
//! malformed API routes) receive ordinary static web server responses with zero
//! `ZebraPass` headers or protocol identifiers. Secret slug validation compares
//! `SHA-256` digests in constant time via `secret::ct_eq_32`.

use secret::ct_eq_32;
use sha2::{Digest, Sha256};

use crate::http_wire::write_http_response;

/// Classified route for an inbound HTTP request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// `GET` or `HEAD /` -> benign decoy site HTML.
    DecoyHome { head_only: bool },
    /// `GET` or `HEAD /favicon.ico` -> `204 No Content`.
    DecoyFavicon,
    /// Matched secret slug: `POST /<slug>/v1/op`.
    ApiOp,
    /// Matched secret slug: `POST /<slug>/v1/state`.
    ApiState,
    /// Matched secret slug: `POST /<slug>/v1/chunk`.
    ApiChunk,
    /// Matched secret slug: `GET /<slug>/v1/ws`.
    ApiWs,
    /// Any unknown route or wrong secret slug -> benign `404 Not Found`.
    NotFound,
}

const HOME_HTML: &[u8] = b"<!doctype html>\n\
<html lang=\"en\">\n\
<head><meta charset=\"utf-8\"><title>Static Documentation Mirror</title></head>\n\
<body>\n\
<h1>Static Mirror</h1>\n\
<p>Reference assets and public release checksums are archived here.</p>\n\
</body>\n\
</html>\n";

const NOT_FOUND_HTML: &[u8] = b"<!doctype html>\n\
<html lang=\"en\">\n\
<head><meta charset=\"utf-8\"><title>404 Not Found</title></head>\n\
<body><h1>404 Not Found</h1><p>The requested resource was not found.</p></body>\n\
</html>\n";

const FORBIDDEN_HTML: &[u8] = b"<!doctype html>\n\
<html lang=\"en\">\n\
<head><meta charset=\"utf-8\"><title>403 Forbidden</title></head>\n\
<body><h1>403 Forbidden</h1></body>\n\
</html>\n";

/// Constant-time check comparing `candidate` against `secret_slug`.
///
/// Hashing both strings before [`ct_eq_32`] ensures different lengths do not
/// leak prefix or length information via timing.
#[must_use]
pub fn slug_matches(candidate: &str, secret_slug: &str) -> bool {
    let cand_hash: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
    let expected_hash: [u8; 32] = Sha256::digest(secret_slug.as_bytes()).into();
    ct_eq_32(&cand_hash, &expected_hash)
}

/// Classify HTTP `(method, path)` against `secret_slug`.
#[must_use]
pub fn classify_request(method: &str, raw_path: &str, secret_slug: &str) -> Route {
    let path = raw_path.split_once('?').map_or(raw_path, |(p, _)| p);
    match (method, path) {
        ("GET", "/") => return Route::DecoyHome { head_only: false },
        ("HEAD", "/") => return Route::DecoyHome { head_only: true },
        ("GET" | "HEAD", "/favicon.ico") => return Route::DecoyFavicon,
        _ => {}
    }
    let Some(trimmed) = path.strip_prefix('/') else {
        return Route::NotFound;
    };
    let Some((candidate_slug, endpoint)) = trimmed.split_once("/v1/") else {
        return Route::NotFound;
    };
    if !slug_matches(candidate_slug, secret_slug) {
        return Route::NotFound;
    }
    match (method, endpoint) {
        ("POST", "op") => Route::ApiOp,
        ("POST", "state") => Route::ApiState,
        ("POST", "chunk") => Route::ApiChunk,
        ("GET", "ws") => Route::ApiWs,
        _ => Route::NotFound,
    }
}

/// Write the benign HTTP response for decoy/404/403 routes.
///
/// # Errors
///
/// Socket write failure or timeout.
pub async fn write_decoy_response<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    route: Route,
) -> anyhow::Result<()> {
    match route {
        Route::DecoyHome { head_only } => {
            let body = if head_only { &[][..] } else { HOME_HTML };
            let len_str = HOME_HTML.len().to_string();
            write_http_response(
                writer,
                200,
                "OK",
                &[
                    ("Server", "nginx"),
                    ("Content-Type", "text/html; charset=utf-8"),
                    ("Content-Length", &len_str),
                    ("Connection", "close"),
                ],
                body,
            )
            .await
        }
        Route::DecoyFavicon => {
            write_http_response(
                writer,
                204,
                "No Content",
                &[("Server", "nginx"), ("Connection", "close")],
                &[],
            )
            .await
        }
        _ => {
            write_http_response(
                writer,
                404,
                "Not Found",
                &[
                    ("Server", "nginx"),
                    ("Content-Type", "text/html; charset=utf-8"),
                    ("Connection", "close"),
                ],
                NOT_FOUND_HTML,
            )
            .await
        }
    }
}

/// Write a plain `403 Forbidden` decoy response (e.g., when a browser sends an
/// `Origin` header to the WebSocket endpoint).
///
/// # Errors
///
/// Socket write failure or timeout.
pub async fn write_forbidden_response<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
) -> anyhow::Result<()> {
    write_http_response(
        writer,
        403,
        "Forbidden",
        &[
            ("Server", "nginx"),
            ("Content-Type", "text/html; charset=utf-8"),
            ("Connection", "close"),
        ],
        FORBIDDEN_HTML,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{Route, classify_request, slug_matches};

    #[test]
    fn classifies_decoys_and_constant_time_slug_routes() {
        let slug = "secret-tunnel-path-99aabb";
        assert_eq!(
            classify_request("GET", "/", slug),
            Route::DecoyHome { head_only: false }
        );
        assert_eq!(
            classify_request("HEAD", "/favicon.ico", slug),
            Route::DecoyFavicon
        );
        assert_eq!(
            classify_request("POST", "/secret-tunnel-path-99aabb/v1/op", slug),
            Route::ApiOp
        );
        assert_eq!(
            classify_request("POST", "/secret-tunnel-path-99aabb/v1/state", slug),
            Route::ApiState
        );
        assert_eq!(
            classify_request("GET", "/secret-tunnel-path-99aabb/v1/ws", slug),
            Route::ApiWs
        );
        assert_eq!(
            classify_request("POST", "/wrong-slug/v1/op", slug),
            Route::NotFound
        );
        assert!(!slug_matches("secret-tunnel", slug));
        assert!(slug_matches(slug, slug));
    }
}
