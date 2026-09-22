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

/// Human names for the CTAP status codes a PRF run can realistically hit.
const fn ctap_name(status: u8) -> &'static str {
    match status {
        0x01 => "invalid command",
        0x02 => "invalid parameter",
        0x03 => "invalid length",
        0x05 => "timeout",
        0x11 => "invalid cbor",
        0x14 => "unsupported extension",
        0x15 => "credential excluded",
        0x17 => "invalid credential",
        0x1B => "unsupported algorithm",
        0x1C => "operation denied",
        0x20 => "unsupported option",
        0x23 => "no credentials",
        0x25 => "pin invalid",
        0x26 => "pin blocked",
        0x27 => "pin auth invalid",
        0x29 => "pin not set",
        0x2A => "pin required",
        0x2B => "pin policy violation",
        0x2F => "user action timeout (touch declined or timed out)",
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
        0x2A | 0x2B => " — token requires PIN, rerun with --pin".to_owned(),
        0x2F => " — touch declined or timed out".to_owned(),
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

    let devices = ctap_fido2::device::list_devices()
        .map_err(|err| format!("hid enumeration failed: {err}"));
    let devices = match devices {
        Ok(devices) => devices,
        Err(message) => fail(2, &message),
    };
    if devices.is_empty() {
        fail(1, "no FIDO HID token found");
    }
    for device in &devices {
        println!("token: {}", device.path);
    }
    let dev = devices[0].path.clone();
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
