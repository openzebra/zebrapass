//! Validation for user-configured HTTPS/WSS sync server URLs, proxies, and
//! automatic local backup directory preferences.

use std::net::IpAddr;

use crate::address::never_dialable;
use crate::limits::{
    BACKUP_DIR_MAX_LEN, SYNC_PROXY_MAX_LEN, SYNC_SERVER_MAX_LEN, SYNC_SERVERS_MAX,
};

const SERVER_SHAPE: &str = "Use https://host[:port]/secret-path (or loopback http:// for tests).";
const PROXY_SHAPE: &str = "Use socks5h://host:port or http://host:port.";
const SLUG_SHAPE: &str = "Include a secret path, for example https://host/my-secret.";

fn valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host == "localhost" {
        return true;
    }
    let mut has_alpha = false;
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
        if label.bytes().any(|b| b.is_ascii_alphabetic()) {
            has_alpha = true;
        }
    }
    has_alpha
}

fn is_loopback_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return true;
    }
    let bare = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<IpAddr>()
        .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

fn split_host_port(authority: &str, default_port: Option<u16>) -> Option<(&str, u16)> {
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        let ip: IpAddr = addr.parse().ok()?;
        let _ = ip;
        let port = if tail.is_empty() {
            default_port?
        } else {
            let port_str = tail.strip_prefix(':')?;
            let p: u16 = port_str.parse().ok()?;
            if p == 0 || port_str != p.to_string() {
                return None;
            }
            p
        };
        return Some((authority.get(..addr.len() + 2)?, port));
    }
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let p: u16 = port_str.parse().ok()?;
        if p == 0 || port_str != p.to_string() {
            return None;
        }
        Some((host, p))
    } else {
        Some((authority, default_port?))
    }
}

fn validate_host(host: &str, allow_loopback: bool) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        let ip = ip.to_canonical();
        if ip.is_loopback() {
            return allow_loopback;
        }
        return !never_dialable(ip);
    }
    if is_loopback_host(host) && !allow_loopback {
        return false;
    }
    valid_hostname(host)
}

fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 128
        && !slug.contains("..")
        && !slug.starts_with('/')
        && !slug.ends_with('/')
        && !slug.contains("//")
        && slug
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/'))
}

/// Validate and normalize one HTTPS/WSS sync server URL (`https://host[:port]/slug`,
/// `wss://host[:port]/slug`, or loopback `http://` / `ws://` for local servers and
/// reverse-proxy tests).
///
/// # Errors
///
/// Human-readable validation message.
pub fn parse_sync_server_url(input: &str, allow_loopback: bool) -> Result<Box<str>, &'static str> {
    let raw = input.trim();
    if raw.is_empty()
        || raw.len() > SYNC_SERVER_MAX_LEN
        || raw.bytes().any(|b| b.is_ascii_control() || b == b' ')
        || raw.contains('?')
        || raw.contains('#')
    {
        return Err(SERVER_SHAPE);
    }
    let (raw_scheme, rest) = raw.split_once("://").ok_or(SERVER_SHAPE)?;
    let (scheme, default_port, tls) = match raw_scheme.to_ascii_lowercase().as_str() {
        "https" => ("https", 443, true),
        "wss" => ("wss", 443, true),
        "http" => ("http", 80, false),
        "ws" => ("ws", 80, false),
        _ => return Err(SERVER_SHAPE),
    };
    let Some((authority, raw_slug)) = rest.split_once('/') else {
        return Err(SLUG_SHAPE);
    };
    let Some((host, port)) = split_host_port(authority, Some(default_port)) else {
        return Err(SERVER_SHAPE);
    };
    if !tls && (!allow_loopback || !is_loopback_host(host)) {
        return Err("Remote sync servers must use https:// or wss://.");
    }
    if !validate_host(host, allow_loopback) {
        return Err("Other devices cannot reach that server address.");
    }
    let slug = raw_slug.trim_end_matches('/');
    if !valid_slug(slug) {
        return Err(SLUG_SHAPE);
    }
    let lower_host = host.to_ascii_lowercase();
    let canonical = if port == default_port {
        format!("{scheme}://{lower_host}/{slug}")
    } else {
        format!("{scheme}://{lower_host}:{port}/{slug}")
    };
    if canonical.len() > SYNC_SERVER_MAX_LEN {
        return Err(SERVER_SHAPE);
    }
    Ok(canonical.into_boxed_str())
}

/// Validate a newline-separated list of sync server URLs.
///
/// # Errors
///
/// When there are more than [`SYNC_SERVERS_MAX`] entries or any URL is invalid.
pub fn parse_sync_server_list(
    lines: &str,
    allow_loopback: bool,
) -> Result<Vec<Box<str>>, &'static str> {
    let mut out = Vec::new();
    for line in lines.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = parse_sync_server_url(trimmed, allow_loopback)?;
        if out.len() >= SYNC_SERVERS_MAX {
            return Err("At most 8 sync servers are allowed.");
        }
        if !out.contains(&normalized) {
            out.push(normalized);
        }
    }
    Ok(out)
}

/// Validate a `socks5h://[user:pass@]host:port`, `socks5://...`, or
/// `http://[user:pass@]host:port` proxy URL.
///
/// # Errors
///
/// Human-readable validation message.
pub fn parse_sync_proxy_url(input: &str) -> Result<Box<str>, &'static str> {
    let raw = input.trim();
    if raw.is_empty()
        || raw.len() > SYNC_PROXY_MAX_LEN
        || raw.bytes().any(|b| b.is_ascii_control() || b == b' ')
        || raw.contains('?')
        || raw.contains('#')
    {
        return Err(PROXY_SHAPE);
    }
    let (raw_scheme, rest) = raw.split_once("://").ok_or(PROXY_SHAPE)?;
    let scheme = match raw_scheme.to_ascii_lowercase().as_str() {
        "socks5h" | "socks5" => "socks5h",
        "http" => "http",
        _ => return Err(PROXY_SHAPE),
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.contains('/') {
        return Err(PROXY_SHAPE);
    }
    let (auth_part, host_port) = match rest.rsplit_once('@') {
        Some((creds, hp)) => {
            if creds.is_empty() || !creds.contains(':') {
                return Err(PROXY_SHAPE);
            }
            (Some(creds), hp)
        }
        None => (None, rest),
    };
    let Some((host, port)) = split_host_port(host_port, None) else {
        return Err(PROXY_SHAPE);
    };
    if !validate_host(host, true) {
        return Err(PROXY_SHAPE);
    }
    let canonical = auth_part.map_or_else(
        || format!("{scheme}://{}:{port}", host.to_ascii_lowercase()),
        |creds| format!("{scheme}://{creds}@{}:{port}", host.to_ascii_lowercase()),
    );
    if canonical.len() > SYNC_PROXY_MAX_LEN {
        return Err(PROXY_SHAPE);
    }
    Ok(canonical.into_boxed_str())
}

/// Validate an automatic local backup directory string preference.
///
/// # Errors
///
/// When empty, over [`BACKUP_DIR_MAX_LEN`], or containing control characters.
pub fn parse_backup_dir(input: &str) -> Result<Box<str>, &'static str> {
    let trimmed = input.trim();
    if trimmed.is_empty()
        || trimmed.len() > BACKUP_DIR_MAX_LEN
        || trimmed.bytes().any(|b| b.is_ascii_control())
    {
        return Err("Enter a valid local directory path.");
    }
    Ok(trimmed.into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use super::{parse_backup_dir, parse_sync_proxy_url, parse_sync_server_url};

    #[test]
    fn sync_server_url_validation_accepts_https_wss_and_loopback_only_http() {
        assert_eq!(
            &*parse_sync_server_url("HTTPS://Sync.Example.com/my-slug/", false).unwrap(),
            "https://sync.example.com/my-slug"
        );
        assert_eq!(
            &*parse_sync_server_url("wss://relay.example.org:8443/v/zp", false).unwrap(),
            "wss://relay.example.org:8443/v/zp"
        );
        assert_eq!(
            &*parse_sync_server_url("http://127.0.0.1:9000/zp-test", true).unwrap(),
            "http://127.0.0.1:9000/zp-test"
        );
        assert!(parse_sync_server_url("http://127.0.0.1:9000/zp-test", false).is_err());
        assert!(parse_sync_server_url("http://sync.example.com/zp", true).is_err());
        assert!(parse_sync_server_url("https://sync.example.com/", false).is_err());
        assert!(parse_sync_server_url("https://sync.example.com/../etc", false).is_err());
        assert!(parse_sync_server_url("https://169.254.169.254/zp", true).is_err());
    }

    #[test]
    fn proxy_url_validation_normalizes_socks5_and_checks_ports() {
        assert_eq!(
            &*parse_sync_proxy_url("socks5://127.0.0.1:1080").unwrap(),
            "socks5h://127.0.0.1:1080"
        );
        assert_eq!(
            &*parse_sync_proxy_url("socks5h://user:pass@127.0.0.1:9050").unwrap(),
            "socks5h://user:pass@127.0.0.1:9050"
        );
        assert_eq!(
            &*parse_sync_proxy_url("http://127.0.0.1:8080/").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert!(parse_sync_proxy_url("socks5h://127.0.0.1").is_err());
        assert!(parse_sync_proxy_url("https://127.0.0.1:8080").is_err());
    }

    #[test]
    fn backup_dir_rejects_empty_or_control_bytes() {
        assert!(parse_backup_dir("").is_err());
        assert!(parse_backup_dir("/tmp/a\nb").is_err());
        assert_eq!(
            &*parse_backup_dir(" /tmp/backups ").unwrap(),
            "/tmp/backups"
        );
    }
}
