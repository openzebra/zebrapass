//! `YubiKey` PRF check: probe tokens, enroll a `hmac-secret` credential, evaluate PRF.
//!
//! End-to-end sanity check for [`platform::PrfBackend`] on real hardware.
//! Run with a `YubiKey` plugged in:
//!
//! ```text
//! cargo run -p platform --example yubikey_check
//! cargo run -p platform --example yubikey_check -- --pin 123456
//! ```
//!
//! Steps: list FIDO HID tokens, `makeCredential` with the `prf` extension
//! (touch), then evaluate the PRF twice on one salt — the outputs must be
//! equal — and once on another salt — the output must differ. Each PRF call
//! needs a touch.
//!
//! Exit codes: 0 all checks passed, 1 no token, 2 token refused (declined
//! touch, bad PIN, missing extension), 3 PRF outputs inconsistent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result
)]

use platform::{CtapPrf, PrfBackend};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        },
    )
}

/// Human names for CTAP2 status codes, canonical CTAP2.1 numbering
/// (`CTAP2_ERR_*` from the FIDO client-to-authenticator spec).
const fn ctap_name(status: u8) -> &'static str {
    match status {
        0x01 => "invalid command",
        0x02 | 0x11 => "invalid cbor",
        0x03 => "invalid cbor type",
        0x04 => "invalid length",
        0x05 => "invalid sequence",
        0x06 => "timeout",
        0x0A => "channel busy",
        0x0B => "lock required",
        0x0C => "invalid channel",
        0x10 => "cbor unexpected type",
        0x12 => "missing parameter",
        0x13 => "limit exceeded",
        0x16 => "credential excluded",
        0x19 => "processing",
        0x1A => "invalid credential",
        0x1B => "user action pending",
        0x1C => "operation pending",
        0x1E => "unsupported algorithm",
        0x1F => "operation denied",
        0x23 => "unsupported option",
        0x26 => "no credentials",
        0x27 => "user action timeout (touch declined or timed out)",
        0x28 => "not allowed",
        0x29 => "pin invalid (wrong PIN)",
        0x2A => "pin blocked",
        0x2B => "pin auth invalid",
        0x2C => "pin auth limit reached",
        0x2D => "no pin set on token",
        0x2E => "pin not set",
        0x31 => "pin policy violation (often: default PIN 123456 must be changed)",
        0x32 => "pin token deprecated",
        0x34 => "uv invalid",
        0x35 => "uv blocked",
        0x36 => "user presence required",
        _ => "unknown status",
    }
}

/// Extra context for a failed backend call: decodes `ctap-fido2` CTAP
/// statuses into advice (PIN hint) or a human name.
fn ctap_hint(err: &anyhow::Error) -> String {
    let Some(ctap_fido2::error::Error::Ctap(status)) = err.downcast_ref::<ctap_fido2::error::Error>()
    else {
        return String::new();
    };
    match status.as_byte() {
        0x29 => " — wrong PIN. Careful: every attempt burns one retry (~8 total, \
            then the token locks). If you do not remember the PIN, reset FIDO: \
            `brew install ykman && ykman fido reset` (wipes FIDO secrets on the token)"
            .to_owned(),
        0x2A => " — PIN blocked after too many wrong attempts; reset required: \
            `ykman fido reset`"
            .to_owned(),
        0x2B | 0x2C => " — token rejected the PIN protocol handshake. Unplug and \
            replug the key, then retry; if it persists, this token's firmware \
            does not accept the ctap-fido2 PIN protocol (v1)"
            .to_owned(),
        0x2D | 0x2E => " — no FIDO PIN configured; set one first: \
            `ykman fido access change-pin`"
            .to_owned(),
        0x31 => " — the PIN is still the factory default 123456 and the token \
            demands a change: run `ykman fido access change-pin`"
            .to_owned(),
        0x27 => " — touch declined or timed out".to_owned(),
        code => format!(" ({})", ctap_name(code)),
    }
}

fn fail(code: i32, message: &str) -> ! {
    eprintln!("FAIL: {message}");
    std::process::exit(code);
}

fn main() {
    println!("== YubiKey PRF check ==");
    let args: Vec<String> = std::env::args().collect();
    let pin = match args.len() {
        3 if args[1] == "--pin" => Some(args[2].as_str()),
        _ => None,
    };

    // 0. Diagnose tokens first: PRF support, PIN state, retries left.
    let reports = CtapPrf::diagnostics();
    if reports.is_empty() {
        fail(1, "no FIDO HID token found");
    }
    let mut dev = String::new();
    let mut prf_ok = false;
    let mut pin_set = false;
    let mut retries: Option<u8> = None;
    for report in reports {
        match report {
            Ok(info) => {
                println!(
                    "token {}: prf={} pin_set={}{}",
                    info.path,
                    info.prf,
                    info.pin_set,
                    info.pin_retries
                        .map(|count| format!(" retries_left={count}"))
                        .unwrap_or_default()
                );
                if !prf_ok && info.prf {
                    prf_ok = true;
                    dev.clone_from(&info.path);
                    pin_set = info.pin_set;
                    retries = info.pin_retries;
                }
            }
            Err(err) => println!("token probe failed: {err}"),
        }
    }
    if !prf_ok {
        fail(2, "no token advertises the prf (hmac-secret) extension");
    }
    if !pin_set {
        fail(
            2,
            "token has no FIDO PIN; set one first: brew install ykman && ykman fido access change-pin",
        );
    }
    if pin.is_none() {
        let left = retries
            .map(|count| format!(" (retries left: {count})"))
            .unwrap_or_default();
        fail(2, &format!("token requires PIN, rerun with --pin{left}"));
    }
    if let Some(count) = retries {
        println!("pin retries left: {count}");
    }
    let prf = CtapPrf::new();

    // 1. Enroll a non-discoverable `prf` credential. Touch required.
    let (cred_id, id) = match prf.enroll("zebrapass.local", b"zp-check", &dev, pin) {
        Ok(result) => result,
        Err(err) => fail(2, &format!("enroll: {err}{}", ctap_hint(&err))),
    };
    println!("enroll: cred_id {} bytes, grant id {}", cred_id.len(), hex(&id));

    // 2. Same salt twice: the token's HMAC must be deterministic. Touch each.
    let salt_a = [0x5Au8; 32];
    let first = prf.prf_with(&cred_id, &salt_a, &dev, pin);
    let first = match first {
        Ok(out) => out,
        Err(err) => fail(2, &format!("prf (first): {err}")),
    };
    let second = prf.prf_with(&cred_id, &salt_a, &dev, pin);
    let second = match second {
        Ok(out) => out,
        Err(err) => fail(2, &format!("prf (second): {err}")),
    };
    let stable = first == second;
    println!("prf stable across runs: {stable}");

    // 3. Another salt: the output must differ.
    let salt_b = [0x5Bu8; 32];
    let other = prf.prf_with(&cred_id, &salt_b, &dev, pin);
    let other = match other {
        Ok(out) => out,
        Err(err) => fail(2, &format!("prf (other salt): {err}")),
    };
    let distinct = other != first;
    println!("prf differs on other salt: {distinct}");

    if stable && distinct {
        println!("OK: YubiKey PRF contract verified");
    } else {
        fail(3, "PRF outputs inconsistent");
    }
}
