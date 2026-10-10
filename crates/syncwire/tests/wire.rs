#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index"
)]

use session::{
    issue_device_cert, sign_record, DeviceSignKey, SyncRecord, MSG_VERSION, SYNC_SIG_LEN,
};
use sha2::{Digest, Sha256};
use syncwire::limits::MAX_FRAME;
use syncwire::{decode_cert, decode_record, encode_cert, encode_record};

fn signed_record() -> (SyncRecord, [u8; session::SYNC_VK_LEN]) {
    let device = DeviceSignKey::from_seed(&[7u8; 32]);
    let frame = vec![9u8; 200];
    let base = SyncRecord {
        client_id: [5u8; 64],
        prev_hash: [6u8; 32],
        content_hash: Sha256::digest(&frame).into(),
        vault_id: [1u8; 16],
        device_id: [2u8; 16],
        record_id: 3,
        revision: 11,
        msg_version: MSG_VERSION,
        key_generation: 4,
        server_origin: Box::from(&b"https://sync.example"[..]),
        frame,
        signature: Vec::new(),
    };
    let signature = sign_record(&device, &base).unwrap();
    (
        SyncRecord { signature, ..base },
        device.verifying_key().unwrap(),
    )
}

#[test]
fn record_roundtrips_and_still_verifies() {
    let (record, vk) = signed_record();
    let bytes = encode_record(&record).unwrap();
    let decoded = decode_record(&bytes).unwrap();
    assert_eq!(decoded, record);
    decoded.verify(&vk, &[1u8; 16]).unwrap();
}

#[test]
fn record_golden_layout() {
    let record = SyncRecord {
        client_id: [1u8; 64],
        prev_hash: [2u8; 32],
        content_hash: [3u8; 32],
        vault_id: [4u8; 16],
        device_id: [5u8; 16],
        record_id: 0x0102_0304,
        revision: 0x0A0B_0C0D_0E0F_1011,
        msg_version: 2,
        key_generation: 7,
        server_origin: Box::from(&b"o"[..]),
        frame: vec![0xEE; 3],
        signature: vec![0xAA; SYNC_SIG_LEN],
    };
    let bytes = encode_record(&record).unwrap();
    assert_eq!(&bytes[..6], b"ZPSR\x00\x01");
    let fixed = 6 + 64 + 32 + 32 + 16 + 16;
    assert_eq!(&bytes[fixed..fixed + 4], &[1, 2, 3, 4]);
    assert_eq!(
        &bytes[fixed + 4..fixed + 12],
        &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11]
    );
    assert_eq!(&bytes[fixed + 12..fixed + 14], &[0, 2]);
    assert_eq!(&bytes[fixed + 14..fixed + 18], &[0, 0, 0, 7]);
    assert_eq!(&bytes[fixed + 18..fixed + 21], &[0, 1, b'o']);
    assert_eq!(
        &bytes[fixed + 21..fixed + 28],
        &[0, 0, 0, 3, 0xEE, 0xEE, 0xEE]
    );
    assert_eq!(bytes.len(), fixed + 28 + SYNC_SIG_LEN);
}

#[test]
fn every_truncation_is_rejected() {
    let (record, _) = signed_record();
    let bytes = encode_record(&record).unwrap();
    for len in 0..bytes.len() {
        assert!(decode_record(&bytes[..len]).is_err(), "prefix {len}");
    }
}

#[test]
fn trailing_bytes_magic_and_version_are_rejected() {
    let (record, _) = signed_record();
    let bytes = encode_record(&record).unwrap();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_record(&trailing).is_err());
    let mut magic = bytes.clone();
    magic[0] ^= 1;
    assert!(decode_record(&magic).is_err());
    let mut version = bytes;
    version[5] = 2;
    assert!(decode_record(&version).is_err());
}

#[test]
fn oversized_declared_lengths_fail_before_allocation() {
    let (record, _) = signed_record();
    let bytes = encode_record(&record).unwrap();
    let frame_len_at = 6 + 64 + 32 + 32 + 16 + 16 + 4 + 8 + 2 + 4 + 2 + record.server_origin.len();
    let mut huge = bytes.clone();
    huge[frame_len_at..frame_len_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(decode_record(&huge).is_err());
    let mut just_over = bytes.clone();
    let over = u32::try_from(MAX_FRAME + 1).unwrap();
    just_over[frame_len_at..frame_len_at + 4].copy_from_slice(&over.to_be_bytes());
    assert!(decode_record(&just_over).is_err());
    let origin_len_at = frame_len_at - 2 - record.server_origin.len();
    let mut origin = bytes;
    origin[origin_len_at..origin_len_at + 2].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(decode_record(&origin).is_err());
}

#[test]
fn encoder_refuses_oversized_or_unsigned_records() {
    let (record, _) = signed_record();
    let big = SyncRecord {
        frame: vec![0; MAX_FRAME + 1],
        ..record.clone()
    };
    assert!(encode_record(&big).is_err());
    let unsigned = SyncRecord {
        signature: Vec::new(),
        ..record
    };
    assert!(encode_record(&unsigned).is_err());
}

#[test]
fn flipped_wire_byte_never_yields_a_verifying_record() {
    let (record, vk) = signed_record();
    let bytes = encode_record(&record).unwrap();
    let step = bytes.len() / 97 + 1;
    for at in (0..bytes.len()).step_by(step) {
        let mut tampered = bytes.clone();
        tampered[at] ^= 0x01;
        if let Ok(decoded) = decode_record(&tampered) {
            assert!(decoded.verify(&vk, &[1u8; 16]).is_err(), "byte {at}");
        }
    }
}

#[test]
fn cert_roundtrips_and_still_verifies() {
    let root = DeviceSignKey::from_seed(&[7u8; 32]);
    let device = DeviceSignKey::from_seed(&[8u8; 32]);
    let cert = issue_device_cert(
        root.seed(),
        &[3u8; 64],
        &[6u8; 16],
        &device.verifying_key().unwrap(),
        1_000,
        9,
    )
    .unwrap();
    let bytes = encode_cert(&cert).unwrap();
    assert_eq!(&bytes[..6], b"ZPDC\x00\x02");
    assert_eq!(&bytes[6 + 64..6 + 64 + 16], &[6u8; 16]);
    assert_eq!(bytes.len(), syncwire::CERT_WIRE_LEN);
    let mut old_version = bytes.clone();
    old_version[5] = 1;
    assert!(decode_cert(&old_version).is_err());
    let decoded = decode_cert(&bytes).unwrap();
    assert_eq!(decoded, cert);
    decoded.verify(&root.verifying_key().unwrap(), 999).unwrap();
    for len in (0..bytes.len()).step_by(97) {
        assert!(decode_cert(&bytes[..len]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_cert(&trailing).is_err());
}

#[test]
fn revocation_round_trips_and_is_strict() {
    let root = DeviceSignKey::from_seed(&[7u8; 32]);
    let signer_key = DeviceSignKey::from_seed(&[8u8; 32]);
    let target_key = DeviceSignKey::from_seed(&[9u8; 32]);
    let cert = |key: &DeviceSignKey, id: u8| {
        issue_device_cert(
            root.seed(),
            &[3u8; 64],
            &[id; 16],
            &key.verifying_key().unwrap(),
            u64::MAX,
            u64::from(id),
        )
        .unwrap()
    };
    let (signer, target) = (cert(&signer_key, 8), cert(&target_key, 9));
    let revocation = session::issue_revocation(&signer_key, &signer, &target, 1_000).unwrap();
    let bytes = syncwire::encode_revocation(&revocation).unwrap();
    assert_eq!(bytes.len(), syncwire::REVOCATION_WIRE_LEN);
    assert_eq!(&bytes[..6], b"ZPRV\x00\x01");
    let decoded = syncwire::decode_revocation(&bytes).unwrap();
    assert_eq!(decoded, revocation);
    decoded
        .verify(&root.verifying_key().unwrap(), 1_000)
        .unwrap();
    for len in (0..bytes.len()).step_by(211) {
        assert!(syncwire::decode_revocation(&bytes[..len]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(syncwire::decode_revocation(&trailing).is_err());
    let mut flipped = bytes;
    flipped[80] ^= 1;
    if let Ok(parsed) = syncwire::decode_revocation(&flipped) {
        assert!(parsed
            .verify(&root.verifying_key().unwrap(), 1_000)
            .is_err());
    }
}

fn sample_attestation() -> session::Attestation {
    let root = DeviceSignKey::from_seed(&[7u8; 32]);
    let device = DeviceSignKey::from_seed(&[8u8; 32]);
    let signer = issue_device_cert(
        root.seed(),
        &[3u8; 64],
        &[6u8; 16],
        &device.verifying_key().unwrap(),
        u64::MAX,
        4,
    )
    .unwrap();
    session::Attestation {
        vault_id: [1; 16],
        record_id: 9,
        revision: 4,
        origin_device: [6; 16],
        plain_digest: [5; 32],
        signer,
        signature: vec![0xAB; SYNC_SIG_LEN],
    }
}

#[test]
fn an_attestation_and_a_bundle_round_trip_and_are_strict() {
    let attestation = sample_attestation();
    let bytes = syncwire::encode_attestation(&attestation).unwrap();
    assert_eq!(bytes.len(), syncwire::ATTESTATION_WIRE_LEN);
    assert_eq!(&bytes[..6], b"ZPRA\x00\x01");
    assert_eq!(syncwire::decode_attestation(&bytes).unwrap(), attestation);
    for len in (0..bytes.len()).step_by(499) {
        assert!(syncwire::decode_attestation(&bytes[..len]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(syncwire::decode_attestation(&trailing).is_err());
    let mut other_magic = bytes;
    other_magic[0] ^= 1;
    assert!(syncwire::decode_attestation(&other_magic).is_err());

    let frame = vec![0x5A; 300];
    let bundle = syncwire::encode_bundle(&attestation, &frame).unwrap();
    let (back, rest) = syncwire::decode_bundle(&bundle).unwrap();
    assert_eq!(back, attestation);
    assert_eq!(rest, frame.as_slice());
    assert!(syncwire::decode_bundle(&bundle[..syncwire::ATTESTATION_WIRE_LEN - 1]).is_err());
    assert!(syncwire::encode_bundle(&attestation, &vec![0; MAX_FRAME + 1]).is_err());
    let mut oversized = syncwire::encode_attestation(&attestation).unwrap();
    oversized.extend(std::iter::repeat_n(0, MAX_FRAME + 1));
    assert!(syncwire::decode_bundle(&oversized).is_err());
}

#[test]
fn a_frontier_round_trips_and_refuses_disorder_and_oversize() {
    let entry = |id: u32| session::FrontierEntry {
        record_id: id,
        revision: u64::from(id) + 1,
        origin_device: [u8::try_from(id).unwrap(); 16],
    };
    let entries: Vec<_> = [1u32, 4, 9].into_iter().map(entry).collect();
    let bytes = syncwire::encode_frontier(&entries).unwrap();
    assert_eq!(bytes.len(), 4 + 3 * 28);
    assert_eq!(syncwire::decode_frontier(&bytes).unwrap(), entries);
    assert!(
        syncwire::decode_frontier(&syncwire::encode_frontier(&[]).unwrap())
            .unwrap()
            .is_empty()
    );

    assert!(syncwire::encode_frontier(&[entry(4), entry(1)]).is_err());
    assert!(syncwire::encode_frontier(&[entry(4), entry(4)]).is_err());
    let mut swapped = bytes.clone();
    swapped[4..8].copy_from_slice(&9u32.to_be_bytes());
    assert!(
        syncwire::decode_frontier(&swapped).is_err(),
        "ids must increase"
    );
    assert!(syncwire::decode_frontier(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(syncwire::decode_frontier(&trailing).is_err());

    // A count that claims far more than the bytes hold is refused before any
    // allocation.
    let mut liar = vec![0u8; 8];
    liar[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(syncwire::decode_frontier(&liar).is_err());
    let mut over = Vec::new();
    over.extend_from_slice(
        &u32::try_from(syncwire::MAX_FRONTIER + 1)
            .unwrap()
            .to_be_bytes(),
    );
    assert!(syncwire::decode_frontier(&over).is_err());
}

mod peers {
    use session::{issue_device_cert, DeviceSignKey, PeerRecord};
    use syncwire::{decode_peers, encode_peers, MAX_PEERS};

    fn record(n: u8) -> PeerRecord {
        let key = DeviceSignKey::from_seed(&[n; 32]);
        let cert = issue_device_cert(
            &[n ^ 1; 32],
            &[n; 64],
            &[n; 16],
            &key.verifying_key().unwrap(),
            u64::MAX,
            1,
        )
        .unwrap();
        PeerRecord::sign(
            &key,
            &cert,
            [4; 16],
            vec!["10.0.0.1:7447".to_owned(), "[::1]:7447".to_owned()],
            1_700_000_000_000,
        )
        .unwrap()
    }

    #[test]
    fn a_list_roundtrips() {
        let list = vec![record(1), record(2)];
        let bytes = encode_peers(&list).unwrap();
        assert_eq!(&bytes[..4], b"ZPRP");
        assert_eq!(decode_peers(&bytes).unwrap(), list);
        assert!(decode_peers(&encode_peers(&[]).unwrap())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn golden_layout_of_version_two() {
        let one = record(1);
        let bytes = encode_peers(std::slice::from_ref(&one)).unwrap();
        assert_eq!(
            &bytes[..6],
            b"ZPRP\x00\x02",
            "the record format is version 2"
        );
        assert_eq!(bytes[6], 1, "one record");
        assert_eq!(&bytes[7..23], &[4; 16], "vault id");
        assert_eq!(
            &bytes[23..31],
            &1_700_000_000_000u64.to_be_bytes(),
            "issued"
        );
        assert_eq!(bytes[31], 2, "two hints");
        assert_eq!(bytes[32], 13, "first hint length");
        assert_eq!(&bytes[33..46], b"10.0.0.1:7447");
        assert_eq!(bytes[46], 10, "second hint length");
        assert_eq!(&bytes[47..57], b"[::1]:7447");
        let after = 57 + syncwire::CERT_WIRE_LEN + session::SYNC_SIG_LEN;
        assert_eq!(bytes.len(), after, "certificate and signature close it");
    }

    #[test]
    fn a_hint_may_be_a_relay_address_and_a_slot_up_to_the_limit() {
        use session::MAX_HINT_LEN;
        assert_eq!(MAX_HINT_LEN, 96);
        let relayed = format!("[2001:4860:4860::8888]:7447/{}", "ab".repeat(16));
        assert!(relayed.len() <= MAX_HINT_LEN);
        let key = DeviceSignKey::from_seed(&[1; 32]);
        let cert = issue_device_cert(
            &[0; 32],
            &[1; 64],
            &[1; 16],
            &key.verifying_key().unwrap(),
            u64::MAX,
            1,
        )
        .unwrap();
        let sign = |hint: String| PeerRecord::sign(&key, &cert, [4; 16], vec![hint], 1);
        let list = vec![
            sign(relayed).unwrap(),
            sign("x".repeat(MAX_HINT_LEN)).unwrap(),
        ];
        assert_eq!(decode_peers(&encode_peers(&list).unwrap()).unwrap(), list);
        assert!(sign("x".repeat(MAX_HINT_LEN + 1)).is_err());
    }

    #[test]
    fn version_one_is_not_read_and_a_hint_over_the_limit_is_refused() {
        let mut bytes = encode_peers(&[record(1)]).unwrap();
        bytes[5] = 1;
        assert!(decode_peers(&bytes).is_err(), "no parser for version one");
        let mut bytes = encode_peers(&[record(1)]).unwrap();
        bytes[32] = 97;
        assert!(decode_peers(&bytes).is_err());
        bytes[32] = 0;
        assert!(decode_peers(&bytes).is_err());
    }

    #[test]
    fn every_truncation_and_trailing_byte_is_refused() {
        let bytes = encode_peers(&[record(1)]).unwrap();
        for cut in 0..bytes.len() {
            assert!(decode_peers(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        let mut longer = bytes;
        longer.push(0);
        assert!(decode_peers(&longer).is_err());
    }

    #[test]
    fn a_hostile_count_is_refused_before_anything_is_read() {
        let mut bytes = encode_peers(&[]).unwrap();
        *bytes.last_mut().unwrap() = u8::try_from(MAX_PEERS + 1).unwrap();
        assert!(decode_peers(&bytes).is_err());
        let many = vec![record(1); MAX_PEERS + 1];
        assert!(encode_peers(&many).is_err());
    }
}

mod canonical {
    use session::{issue_device_cert, DeviceSignKey, FrontierEntry, PeerRecord};
    use syncwire::{decode_frontier, decode_peers, encode_frontier, encode_peers};

    /// Whatever a mutated list still decodes to must encode back to exactly
    /// the same bytes, so two encodings never mean the same thing.
    #[test]
    fn a_list_that_decodes_encodes_back_identically() {
        let key = DeviceSignKey::from_seed(&[3; 32]);
        let cert = issue_device_cert(
            &[4; 32],
            &[3; 64],
            &[3; 16],
            &key.verifying_key().unwrap(),
            u64::MAX,
            1,
        )
        .unwrap();
        let peers = encode_peers(&[PeerRecord::sign(
            &key,
            &cert,
            [1; 16],
            vec!["10.0.0.1:7447".to_owned()],
            1_700_000_000_000,
        )
        .unwrap()])
        .unwrap();
        let frontier = encode_frontier(&[
            FrontierEntry {
                record_id: 1,
                revision: 2,
                origin_device: [3; 16],
            },
            FrontierEntry {
                record_id: 9,
                revision: 4,
                origin_device: [5; 16],
            },
        ])
        .unwrap();
        for index in 0..peers.len().max(frontier.len()) {
            for bit in 0..8 {
                if let Some(mut bytes) = Some(peers.clone()).filter(|b| index < b.len()) {
                    bytes[index] ^= 1 << bit;
                    if let Ok(list) = decode_peers(&bytes) {
                        assert_eq!(encode_peers(&list).unwrap(), bytes);
                    }
                }
                if let Some(mut bytes) = Some(frontier.clone()).filter(|b| index < b.len()) {
                    bytes[index] ^= 1 << bit;
                    if let Ok(list) = decode_frontier(&bytes) {
                        assert_eq!(encode_frontier(&list).unwrap(), bytes);
                    }
                }
            }
        }
    }
}

#[test]
fn a_snapshot_round_trips_and_is_strict() {
    let attestations = vec![sample_attestation(), {
        let mut second = sample_attestation();
        second.record_id += 1;
        second
    }];
    let file = vec![0xAB; 1000];
    let bytes = syncwire::encode_snapshot(&file, &attestations).unwrap();
    let (back, held) = syncwire::decode_snapshot(bytes.clone()).unwrap();
    assert_eq!(back, file);
    assert_eq!(held, attestations);

    let (empty_file, none) =
        syncwire::decode_snapshot(syncwire::encode_snapshot(&file, &[]).unwrap()).unwrap();
    assert_eq!(empty_file, file);
    assert!(none.is_empty());

    for len in 0..8 + 2 * syncwire::ATTESTATION_WIRE_LEN {
        assert!(syncwire::decode_snapshot(bytes[..len].to_vec()).is_err());
    }
    let mut magic = bytes.clone();
    magic[0] ^= 1;
    assert!(syncwire::decode_snapshot(magic).is_err());
    let mut version = bytes.clone();
    version[5] ^= 1;
    assert!(syncwire::decode_snapshot(version).is_err());
    let mut count = bytes;
    count[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(syncwire::decode_snapshot(count).is_err());
}

fn sealed_frame() -> Vec<u8> {
    let meta = frame::FrameMeta {
        kind: frame::KIND_REVISION,
        record_id: 3,
        revision: 2,
        origin_device: [4; 16],
        timestamp_ms: 5,
        alg: frame::ALG_CASCADE,
    };
    frame::seal(&secret::Secret::new([8u8; 32]), &meta, b"plain").unwrap()
}

#[test]
fn an_announcement_round_trips_and_is_strict() {
    let announce = syncwire::Announce {
        vault_id: [1; 16],
        generation: 9,
        commit_tag: [2; 32],
    };
    let bytes = syncwire::encode_announce(&announce);
    assert_eq!(bytes.len(), syncwire::ANNOUNCE_WIRE_LEN);
    assert_eq!(syncwire::decode_announce(&bytes).unwrap(), announce);
    for len in 0..bytes.len() {
        assert!(syncwire::decode_announce(&bytes[..len]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(syncwire::decode_announce(&trailing).is_err());
    let mut magic = bytes.clone();
    magic[0] ^= 1;
    assert!(syncwire::decode_announce(&magic).is_err());
    let mut version = bytes;
    version[5] ^= 1;
    assert!(syncwire::decode_announce(&version).is_err());
}

#[test]
fn a_personal_frame_round_trips_and_is_strict() {
    let frame = sealed_frame();
    let bytes = syncwire::encode_personal_frame(&frame).unwrap();
    assert_eq!(syncwire::decode_personal_frame(&bytes).unwrap(), frame);
    for len in 0..bytes.len() {
        assert!(syncwire::decode_personal_frame(&bytes[..len]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(syncwire::decode_personal_frame(&trailing).is_err());
    let mut magic = bytes.clone();
    magic[1] ^= 1;
    assert!(syncwire::decode_personal_frame(&magic).is_err());
    let mut version = bytes.clone();
    version[5] ^= 1;
    assert!(syncwire::decode_personal_frame(&version).is_err());
    let mut liar = bytes;
    liar[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(syncwire::decode_personal_frame(&liar).is_err());
    let mut over = Vec::new();
    over.extend_from_slice(&syncwire::PERSONAL_FRAME_MAGIC);
    over.extend_from_slice(&syncwire::PERSONAL_FRAME_WIRE_VERSION.to_be_bytes());
    over.extend_from_slice(&u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes());
    over.resize(over.len() + MAX_FRAME + 1, 0);
    assert!(syncwire::decode_personal_frame(&over).is_err());
    assert!(syncwire::encode_personal_frame(&[0u8; 8]).is_err());
}

mod beacon {
    use syncwire::{decode_beacon, encode_beacon, Beacon, BEACON_WIRE_MAX, MAX_BEACON_VAULTS};

    fn sample() -> Beacon {
        Beacon {
            vaults: vec![[0xA1; 16], [0xB2; 16]],
            port: 0x1D17,
        }
    }

    #[test]
    fn golden_layout() {
        let bytes = encode_beacon(&sample()).unwrap();
        assert_eq!(&bytes[..6], b"ZPBC\x00\x01");
        assert_eq!(&bytes[6..8], &[0x1D, 0x17], "port, big-endian");
        assert_eq!(bytes[8], 2, "vault count");
        assert_eq!(&bytes[9..25], &[0xA1; 16]);
        assert_eq!(&bytes[25..41], &[0xB2; 16]);
        assert_eq!(bytes.len(), 41);
        assert_eq!(decode_beacon(&bytes).unwrap(), sample());
        let most = Beacon {
            vaults: vec![[1; 16]; MAX_BEACON_VAULTS],
            port: 1,
        };
        assert_eq!(encode_beacon(&most).unwrap().len(), BEACON_WIRE_MAX);
    }

    #[test]
    fn strict_decode() {
        let bytes = encode_beacon(&sample()).unwrap();
        for len in 0..bytes.len() {
            assert!(decode_beacon(&bytes[..len]).is_err(), "cut at {len}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_beacon(&trailing).is_err());
        let mut bad = bytes.clone();
        bad[0] ^= 1;
        assert!(decode_beacon(&bad).is_err(), "magic");
        let mut bad = bytes.clone();
        bad[5] = 2;
        assert!(decode_beacon(&bad).is_err(), "version");
        let mut bad = bytes.clone();
        bad[6..8].copy_from_slice(&[0, 0]);
        assert!(decode_beacon(&bad).is_err(), "no port");
        let mut bad = bytes.clone();
        bad[8] = 0;
        assert!(decode_beacon(&bad).is_err(), "no vaults");
        let mut bad = bytes;
        bad[8] = 255;
        assert!(decode_beacon(&bad).is_err(), "a count over the bound");
        assert!(encode_beacon(&Beacon {
            vaults: vec![],
            port: 1
        })
        .is_err());
        assert!(encode_beacon(&Beacon {
            vaults: vec![[0; 16]],
            port: 0
        })
        .is_err());
        assert!(encode_beacon(&Beacon {
            vaults: vec![[0; 16]; MAX_BEACON_VAULTS + 1],
            port: 1
        })
        .is_err());
    }
}
