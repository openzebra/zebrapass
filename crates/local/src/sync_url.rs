//! Hardcoded `ZebraPass` sync servers, validation for user-configured
//! self-hosted sync server endpoints (`host[:port]`), and automatic local
//! backup directory preferences.

use std::net::IpAddr;

use crate::address::{is_private_or_local_ip, never_dialable};
use crate::limits::{BACKUP_DIR_MAX_LEN, SYNC_SERVER_MAX_LEN, SYNC_SERVERS_MAX};

/// Default port for PQ TLS 1.3 `ZebraPass` sync & relay endpoints.
pub const DEFAULT_SYNC_PORT: u16 = 443;

/// Hardcoded official `ZebraPass` sync & relay cluster endpoints.
pub const DEFAULT_SYNC_SERVERS: [&str; 3] =
    ["ru.zebra.sh:443", "eu.zebra.sh:443", "zh.zebra.sh:443"];

const SERVER_SHAPE: &str =
    "Use host or host:port (for example eu.zebra.sh or sync.example.com:8443).";

/// Owned default server list (`ru.zebra.sh:443`, `eu.zebra.sh:443`, `zh.zebra.sh:443`).
#[must_use]
pub fn default_sync_servers() -> Vec<Box<str>> {
    DEFAULT_SYNC_SERVERS.iter().map(|s| (*s).into()).collect()
}

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

fn split_host_port(authority: &str, default_port: u16) -> Option<(&str, u16)> {
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        let _ip: IpAddr = addr.parse().ok()?;
        let port = if tail.is_empty() {
            default_port
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
        Some((authority, default_port))
    }
}

fn validate_host(host: &str, allow_private: bool) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        let ip = ip.to_canonical();
        if never_dialable(ip) {
            return false;
        }
        if is_private_or_local_ip(ip) {
            return allow_private;
        }
        return true;
    }
    if is_loopback_host(host) && !allow_private {
        return false;
    }
    valid_hostname(host)
}

/// Validate and normalize one PQ TLS 1.3 sync server endpoint (`host[:port]`,
/// optionally prefixed with `https://` or `tls://`).
///
/// # Errors
///
/// Human-readable validation message when malformed, unroutable, or carrying a
/// path/query/userinfo.
pub fn parse_sync_server_url(input: &str, allow_loopback: bool) -> Result<Box<str>, &'static str> {
    let raw = input.trim();
    if raw.is_empty()
        || raw.len() > SYNC_SERVER_MAX_LEN
        || raw.bytes().any(|b| b.is_ascii_control() || b == b' ')
        || raw.contains('?')
        || raw.contains('#')
        || raw.contains('@')
    {
        return Err(SERVER_SHAPE);
    }
    let stripped = if let Some((scheme, rest)) = raw.split_once("://") {
        if !matches!(scheme.to_ascii_lowercase().as_str(), "https" | "tls") {
            return Err(SERVER_SHAPE);
        }
        rest
    } else {
        raw
    };
    let authority = stripped.strip_suffix('/').unwrap_or(stripped);
    if authority.contains('/') {
        return Err(SERVER_SHAPE);
    }
    let Some((host, port)) = split_host_port(authority, DEFAULT_SYNC_PORT) else {
        return Err(SERVER_SHAPE);
    };
    if !validate_host(host, allow_loopback) {
        return Err("Other devices cannot reach that server address.");
    }
    let canonical = format!("{}:{port}", host.to_ascii_lowercase());
    if canonical.len() > SYNC_SERVER_MAX_LEN {
        return Err(SERVER_SHAPE);
    }
    Ok(canonical.into_boxed_str())
}

/// Validate a newline- or comma-separated list of sync server endpoints.
///
/// # Errors
///
/// When there are more than [`SYNC_SERVERS_MAX`] entries or any endpoint is
/// invalid.
pub fn parse_sync_server_list(
    lines: &str,
    allow_loopback: bool,
) -> Result<Vec<Box<str>>, &'static str> {
    let mut out = Vec::new();
    for item in lines.split(['\n', ',']) {
        let trimmed = item.trim();
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

    use super::{
        DEFAULT_SYNC_SERVERS, default_sync_servers, parse_backup_dir, parse_sync_server_list,
        parse_sync_server_url,
    };

    #[test]
    fn default_servers_validate_cleanly() {
        let defaults = default_sync_servers();
        assert_eq!(defaults.len(), 3);
        for (raw, norm) in DEFAULT_SYNC_SERVERS.iter().zip(defaults.iter()) {
            assert_eq!(parse_sync_server_url(raw, false).unwrap().as_ref(), &**norm);
        }
    }

    #[test]
    fn sync_server_validation_normalizes_host_port_and_rejects_paths_and_http() {
        assert_eq!(
            &*parse_sync_server_url("EU.Zebra.SH", false).unwrap(),
            "eu.zebra.sh:443"
        );
        assert_eq!(
            &*parse_sync_server_url("https://Sync.Example.com:8443/", false).unwrap(),
            "sync.example.com:8443"
        );
        assert_eq!(
            &*parse_sync_server_url("tls://[2606:2800:220:1::1]:8443", false).unwrap(),
            "[2606:2800:220:1::1]:8443"
        );
        assert_eq!(
            &*parse_sync_server_url("127.0.0.1:9000", true).unwrap(),
            "127.0.0.1:9000"
        );
        assert!(parse_sync_server_url("127.0.0.1:9000", false).is_err());
        assert!(parse_sync_server_url("http://sync.example.com", true).is_err());
        assert!(parse_sync_server_url("https://sync.example.com/slug", false).is_err());
        assert!(parse_sync_server_url("169.254.169.254:443", true).is_err());
    }

    #[test]
    fn sync_server_list_splits_commas_and_newlines_and_dedups() {
        let parsed =
            parse_sync_server_list("ru.zebra.sh, eu.zebra.sh:443\nRU.Zebra.SH:443", false).unwrap();
        assert_eq!(
            parsed.iter().map(AsRef::as_ref).collect::<Vec<_>>(),
            vec!["ru.zebra.sh:443", "eu.zebra.sh:443"]
        );
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
