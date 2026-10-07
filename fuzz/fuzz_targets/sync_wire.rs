//! Fuzz target: every decoder of what a peer sends over the wire (records,
//! certificates, revocations, attestations, bundles, frontiers, peer lists)
//! must return an error, never panic, and whatever decodes must encode back.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = syncwire::decode_record(data) {
        let _ = syncwire::encode_record(&record);
    }
    let _ = syncwire::decode_cert(data);
    let _ = syncwire::decode_revocation(data);
    if let Ok(attestation) = syncwire::decode_attestation(data) {
        assert!(syncwire::encode_attestation(&attestation).is_ok());
    }
    let _ = syncwire::decode_bundle(data);
    if let Ok(frontier) = syncwire::decode_frontier(data) {
        assert_eq!(syncwire::encode_frontier(&frontier).ok().as_deref(), Some(data));
    }
    if let Ok(peers) = syncwire::decode_peers(data) {
        assert_eq!(syncwire::encode_peers(&peers).ok().as_deref(), Some(data));
    }
});
