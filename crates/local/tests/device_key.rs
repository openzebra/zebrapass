#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap, index, and panic"
)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use kdf::KdfProfile;
use local::{open_device_key, seal_device_key, DeviceKey, DEVICE_KEY_FILE_LEN};

const VAULT: [u8; 16] = [7; 16];
const PIN: &[u8] = b"271828";
const AUTH: &str = "device key authentication failed";

fn temp_file(tag: &str) -> PathBuf {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).unwrap();
    let mut name = format!("zp-devkey-{tag}-");
    for byte in suffix {
        write!(name, "{byte:02x}").unwrap();
    }
    let dir = std::env::temp_dir().join(name);
    fs::create_dir_all(&dir).unwrap();
    dir.join("device.key")
}

fn sealed(tag: &str) -> (PathBuf, DeviceKey) {
    let path = temp_file(tag);
    let key = DeviceKey::generate().unwrap();
    seal_device_key(&path, &VAULT, &key, PIN, KdfProfile::Fast).unwrap();
    (path, key)
}

fn open_err(path: &Path, vault: &[u8; 16], pin: &[u8]) -> String {
    open_device_key(path, vault, pin).unwrap_err().to_string()
}

#[test]
fn round_trip_keeps_the_same_publics_and_ecdh() {
    let (path, key) = sealed("roundtrip");
    assert_eq!(fs::read(&path).unwrap().len(), DEVICE_KEY_FILE_LEN);
    let opened = open_device_key(&path, &VAULT, PIN).unwrap();
    assert_eq!(opened.id(), key.id());
    assert_eq!(opened.publics().unwrap(), key.publics().unwrap());
    let peer = key.publics().unwrap().chip_pub;
    assert_eq!(
        opened.ecdh(&peer).unwrap().expose(),
        key.ecdh(&peer).unwrap().expose()
    );
    assert_eq!(format!("{opened:?}"), "DeviceKey([REDACTED])");
}

#[test]
fn wrong_pin_other_vault_and_every_tampered_region_fail_the_same_way() {
    let (path, _) = sealed("tamper");
    assert_eq!(open_err(&path, &VAULT, b"314159"), AUTH);
    assert_eq!(open_err(&path, &[8; 16], PIN), AUTH);
    let original = fs::read(&path).unwrap();
    // magic, version, profile, salt, frame header, frame body, last tag byte.
    for offset in [0, 5, 6, 20, 40, 150, DEVICE_KEY_FILE_LEN - 1] {
        let mut bytes = original.clone();
        bytes[offset] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        assert_eq!(open_err(&path, &VAULT, PIN), AUTH, "offset {offset}");
    }
    fs::write(&path, &original[..DEVICE_KEY_FILE_LEN - 1]).unwrap();
    assert_eq!(open_err(&path, &VAULT, PIN), AUTH);
    let mut longer = original;
    longer.push(0);
    fs::write(&path, &longer).unwrap();
    assert_eq!(open_err(&path, &VAULT, PIN), AUTH);
}

#[test]
fn unknown_profile_byte_is_rejected_before_the_kdf() {
    let (path, _) = sealed("profile");
    let mut bytes = fs::read(&path).unwrap();
    // Profile byte 0xFF would name no preset; rejection must be immediate.
    bytes[6] = 0xFF;
    fs::write(&path, &bytes).unwrap();
    let started = std::time::Instant::now();
    assert_eq!(open_err(&path, &VAULT, PIN), AUTH);
    assert!(started.elapsed() < std::time::Duration::from_millis(50));
}

#[test]
fn pin_length_is_bounded_and_missing_file_is_distinct() {
    let path = temp_file("pinlen");
    let key = DeviceKey::generate().unwrap();
    let err = seal_device_key(&path, &VAULT, &key, b"12345", KdfProfile::Fast).unwrap_err();
    assert_eq!(err.to_string(), "device PIN length");
    assert!(!path.exists());
    let long = [b'x'; 129];
    assert_eq!(open_err(&path, &VAULT, &long), "device PIN length");
    assert_eq!(open_err(&path, &VAULT, PIN), "device key unreadable");
}
