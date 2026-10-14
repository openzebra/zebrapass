//! Embedded geographic relay directory and deterministic relay slot derivation.
//!
//! Embeds `nostr_relays.toml` directly into the binary via `include_str!` and
//! selects the closest relays using the Haversine great-circle distance, or a
//! deterministic fallback when no coordinates are available. Also derives
//! deterministic 16-byte relay slots from a shared or personal secret so peers
//! can rendezvous on a relay without out-of-band slot exchange.

use std::net::SocketAddr;
use std::sync::OnceLock;

use syncwire::RelayHint;

/// Raw TOML relay catalog compiled into the binary.
pub const EMBEDDED_RELAYS_TOML: &str = include_str!("nostr_relays.toml");

/// Earth mean radius in kilometers for Haversine great-circle calculation.
const EARTH_RADIUS_KM: f64 = 6371.0;

/// Maximum number of relay entries parsed from the embedded TOML catalog.
const MAX_EMBEDDED_RELAYS: usize = 512;

/// One entry from the embedded relay directory.
#[derive(Clone, Debug, PartialEq)]
pub struct RelayEntry {
    /// Relay URL as listed in `nostr_relays.toml`.
    pub url: Box<str>,
    /// Latitude in decimal degrees.
    pub lat: f64,
    /// Longitude in decimal degrees.
    pub lon: f64,
}

static PARSED_RELAYS: OnceLock<Box<[RelayEntry]>> = OnceLock::new();

/// All relay entries parsed from the embedded `nostr_relays.toml` catalog.
#[must_use]
pub fn embedded_relays() -> &'static [RelayEntry] {
    PARSED_RELAYS.get_or_init(|| parse_relays_toml(EMBEDDED_RELAYS_TOML).into_boxed_slice())
}

/// Parse a `[[relays]]` TOML catalog into [`RelayEntry`] records, bounded by
/// [`MAX_EMBEDDED_RELAYS`].
#[must_use]
pub fn parse_relays_toml(toml_text: &str) -> Vec<RelayEntry> {
    let mut entries = Vec::with_capacity(384);
    let mut current_url: Option<Box<str>> = None;
    let mut current_lat: Option<f64> = None;
    let mut current_lon: Option<f64> = None;

    let flush = |entries: &mut Vec<RelayEntry>,
                 url: &mut Option<Box<str>>,
                 lat: &mut Option<f64>,
                 lon: &mut Option<f64>| {
        if entries.len() < MAX_EMBEDDED_RELAYS {
            if let (Some(u), Some(la), Some(lo)) = (url.take(), lat.take(), lon.take()) {
                if !u.is_empty() && la.is_finite() && lo.is_finite() {
                    entries.push(RelayEntry {
                        url: u,
                        lat: la,
                        lon: lo,
                    });
                }
            }
        }
        *url = None;
        *lat = None;
        *lon = None;
    };

    for raw_line in toml_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[relays]]" {
            flush(
                &mut entries,
                &mut current_url,
                &mut current_lat,
                &mut current_lon,
            );
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "url" => {
                if let Some(unquoted) = value.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                    current_url = Some(unquoted.trim().into());
                }
            }
            "lat" => {
                current_lat = value.parse::<f64>().ok();
            }
            "lon" => {
                current_lon = value.parse::<f64>().ok();
            }
            _ => {}
        }
    }
    flush(
        &mut entries,
        &mut current_url,
        &mut current_lat,
        &mut current_lon,
    );
    entries
}

/// Great-circle distance in kilometers between two `(lat, lon)` coordinates in
/// decimal degrees.
#[must_use]
#[allow(
    clippy::suboptimal_flops,
    reason = "Haversine formula is clearer in standard form"
)]
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let r_lat1 = lat1.to_radians();
    let r_lat2 = lat2.to_radians();
    let sin_dlat = (d_lat * 0.5).sin();
    let sin_dlon = (d_lon * 0.5).sin();
    let a = (sin_dlat * sin_dlat) + (r_lat1.cos() * r_lat2.cos() * sin_dlon * sin_dlon);
    let clamped = a.clamp(0.0, 1.0);
    2.0 * EARTH_RADIUS_KM * clamped.sqrt().asin()
}

/// Select the `count` closest relays to `(lat, lon)` sorted by ascending
/// Haversine distance.
#[must_use]
pub fn closest_relays(lat: f64, lon: f64, count: usize) -> Vec<&'static RelayEntry> {
    let all = embedded_relays();
    let mut ranked: Vec<(f64, &'static RelayEntry)> = all
        .iter()
        .map(|entry| (haversine_km(lat, lon, entry.lat, entry.lon), entry))
        .collect();
    ranked.sort_by(|(d1, a), (d2, b)| {
        d1.partial_cmp(d2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.url.cmp(&b.url))
    });
    ranked
        .into_iter()
        .take(count)
        .map(|(_, entry)| entry)
        .collect()
}

/// Select up to `count` geographically distributed default relays when no
/// coordinates are given.
#[must_use]
pub fn default_relays(count: usize) -> Vec<&'static RelayEntry> {
    let all = embedded_relays();
    if all.is_empty() || count == 0 {
        return Vec::new();
    }
    let step = (all.len() / count.max(1)).max(1);
    all.iter().step_by(step).take(count).collect()
}

/// Derive a deterministic [`RelayHint`] on `relay` from a 32-byte key or gate
/// secret and a 16-byte vault/route identifier.
#[must_use]
pub fn deterministic_relay_hint(
    secret: &[u8],
    context_id: &[u8; 16],
    relay: SocketAddr,
) -> Option<RelayHint> {
    let slot = kdf::p2p_relay_slot(secret, context_id, &relay.to_string()).ok()?;
    Some(RelayHint { relay, slot })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::float_cmp,
    reason = "tests may unwrap and index"
)]
mod tests {
    use super::*;

    #[test]
    fn embedded_relays_load_and_haversine_ranks_closest_first() {
        let all = embedded_relays();
        assert_eq!(all.len(), 379);
        assert_eq!(&*all[0].url, "relay.gulugulu.moe:443");

        // Tokyo coordinates: closest relays should be in Japan / East Asia.
        let near_tokyo = closest_relays(35.6762, 139.6503, 5);
        assert_eq!(near_tokyo.len(), 5);
        let d0 = haversine_km(35.6762, 139.6503, near_tokyo[0].lat, near_tokyo[0].lon);
        let d4 = haversine_km(35.6762, 139.6503, near_tokyo[4].lat, near_tokyo[4].lon);
        assert!(d0 <= d4);
        assert!(d0 < 100.0, "expected a relay near Tokyo, got {d0} km");

        let defaults = default_relays(4);
        assert_eq!(defaults.len(), 4);
    }

    #[test]
    fn deterministic_relay_hint_is_stable_for_both_peers() {
        let relay: SocketAddr = "93.184.216.34:7447".parse().unwrap();
        let a = deterministic_relay_hint(&[0x11; 32], &[0x22; 16], relay).unwrap();
        let b = deterministic_relay_hint(&[0x11; 32], &[0x22; 16], relay).unwrap();
        let c = deterministic_relay_hint(&[0x11; 32], &[0x33; 16], relay).unwrap();
        assert_eq!(a, b);
        assert_ne!(a.slot, c.slot);
    }
}
