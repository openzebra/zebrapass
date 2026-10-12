//! Fuzz target: every decoder of what a peer sends over the wire (records,
//! certificates, revocations, attestations, bundles, frontiers, peer lists, snapshots,
//! personal-vault announcements and frames)
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
    let _ = syncwire::decode_snapshot(data.to_vec());
    if let Ok(announce) = syncwire::decode_announce(data) {
        assert_eq!(syncwire::encode_announce(&announce), data);
    }
    if let Ok(frame) = syncwire::decode_personal_frame(data) {
        assert_eq!(syncwire::encode_personal_frame(&frame).ok().as_deref(), Some(data));
    }
    if let Ok(peers) = syncwire::decode_peers(data) {
        assert_eq!(syncwire::encode_peers(&peers).ok().as_deref(), Some(data));
    }
    if let Ok(beacon) = syncwire::decode_beacon(data) {
        assert_eq!(syncwire::encode_beacon(&beacon).ok().as_deref(), Some(data));
    }
    if let Some(bytes) = data.first_chunk::<{ syncwire::limits::RELAY_HEADER_LEN }>() {
        for side in [syncwire::RelaySide::Client, syncwire::RelaySide::Relay] {
            if let Ok(header) = syncwire::RelayHeader::decode(bytes, side) {
                assert_eq!(header.encode(), *bytes);
            }
        }
    }
    if let Some(bytes) = data.first_chunk::<{ syncwire::limits::RELAY_OPEN_LEN }>() {
        if syncwire::decode_open(bytes).is_ok() {
            assert_eq!(syncwire::encode_open(), *bytes);
        }
    }
    if let Ok(claim) = syncwire::Claim::try_from(data) {
        assert_eq!(claim.encode(), data);
    }
    if let Ok(challenge) = syncwire::Challenge::try_from(data) {
        assert_eq!(challenge.encode(), data);
    }
    if let Ok(granted) = syncwire::Reserved::try_from(data) {
        assert_eq!(granted.encode(), data);
    }
    if let Ok(conn_id) = syncwire::decode_incoming(data) {
        assert_eq!(syncwire::encode_incoming(&conn_id), data);
    }
    if let Some(hint) = std::str::from_utf8(data)
        .ok()
        .and_then(|text| text.parse::<syncwire::RelayHint>().ok())
    {
        assert_eq!(hint.to_string().parse::<syncwire::RelayHint>().ok(), Some(hint));
    }
});
