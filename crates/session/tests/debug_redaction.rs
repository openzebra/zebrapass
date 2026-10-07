#![allow(clippy::unwrap_used, reason = "tests may unwrap")]

use session::DeviceSignKey;

#[test]
fn a_device_signing_key_never_prints_its_seed() {
    let key = DeviceSignKey::from_seed(&[0x5A; 32]);
    for text in [format!("{key:?}"), format!("{key:#?}")] {
        assert!(!text.contains("90, 90"), "{text}");
        assert!(!text.contains("5a5a"), "{text}");
        assert!(text.contains("DeviceSignKey"));
    }
}
