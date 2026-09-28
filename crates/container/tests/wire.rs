#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests may unwrap and index"
)]

use container::{
    assemble, encode_chip_entry, encode_human_password_entry, encode_password_entry,
    encode_prf_entry, encode_wrap_dir, HumanKdf, StaticHeader, VaultFile, WrapDir, WrapEntry,
    BODY_AEGIS256, BODY_KUZ_CTR_HMAC, BODY_KUZ_MGM, COMMIT_LEN, DOMAIN_BODY, DOMAIN_WRAP_CHIP,
    DOMAIN_WRAP_PASSWORD, HEADER_LEN, KDF_ARGON2ID, KDF_M_KIB_MAX, KDF_M_KIB_MIN, KDF_P_MAX,
    KDF_P_MIN, KDF_T_MAX, KDF_T_MIN, KIND_CHIP, KIND_PASSWORD, KIND_PRF, MAGIC,
    PASSWORD_PAYLOAD_LEN, PASSWORD_RECORD_LEN, VERSION, WRAP_AEGIS256,
};
use pq::{KEM_CT_LEN, PQ_PK_LEN};

const fn header_with(body_alg: u16, m_kib: u32, t: u32, p: u32) -> StaticHeader {
    StaticHeader {
        kdf_alg: KDF_ARGON2ID,
        kdf_m_kib: m_kib,
        kdf_t: t,
        kdf_p: p,
        kdf_salt: [0xA5; 32],
        vault_id: [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ],
        body_alg,
        wrap_alg: WRAP_AEGIS256,
    }
}

const fn sample_header(body_alg: u16) -> StaticHeader {
    header_with(body_alg, KDF_M_KIB_MIN, KDF_T_MIN, KDF_P_MIN)
}

fn password_record() -> [u8; PASSWORD_RECORD_LEN] {
    encode_password_entry([9; 8], [1; 32], [2; 32], [3; 32])
}

/// A well-formed record of the retired X25519 device kind `0x0002`: id,
/// KEM id, two X25519 keys, ML-KEM ciphertext, nonce, ct, tag.
fn retired_device_record() -> Vec<u8> {
    let payload_len = 16 + 2 + 32 + 32 + KEM_CT_LEN + 32 + 32 + 32;
    let mut raw = Vec::with_capacity(6 + payload_len);
    raw.extend_from_slice(&0x0002u16.to_le_bytes());
    raw.extend_from_slice(&u32::try_from(payload_len).unwrap().to_le_bytes());
    raw.extend_from_slice(&[0x11; 16]);
    raw.extend_from_slice(&0xC002u16.to_le_bytes());
    raw.resize(6 + payload_len, 0x5A);
    raw
}

fn chip_record(id_byte: u8, ct_byte: u8) -> Vec<u8> {
    chip_record_with_kem(id_byte, ct_byte, 0x5A)
}

fn chip_record_with_kem(id_byte: u8, ct_byte: u8, kem_byte: u8) -> Vec<u8> {
    encode_chip_entry(
        [id_byte; 16],
        [0x41; 65],
        [0x43; 65],
        [0x42; PQ_PK_LEN],
        &[kem_byte; KEM_CT_LEN],
        [1; 32],
        [ct_byte; 32],
        [3; 32],
    )
    .unwrap()
}

fn file_from(header: &StaticHeader, entries: &[&[u8]], body: &[u8], generation: u64) -> VaultFile {
    let dir = encode_wrap_dir(generation, entries).unwrap();
    let commit = [0x44; COMMIT_LEN];
    assemble(header, &dir, body, &commit)
}

fn assert_allowed(err: &anyhow::Error) {
    let msg = err.to_string();
    let allowed = [
        "bad magic",
        "corrupted length",
        "kdf parameters rejected",
        "no password wrap",
    ];
    assert!(
        allowed.contains(&msg.as_str()) || msg.starts_with("unsupported "),
        "unexpected parse error: {msg}"
    );
}

#[test]
fn constants_match_the_spec() {
    assert_eq!(MAGIC, *b"BRBY");
    assert_eq!(VERSION, 2);
    assert_eq!(KDF_ARGON2ID, 0x0001);
    assert_eq!(BODY_AEGIS256, 0xA001);
    assert_eq!(BODY_KUZ_MGM, 0xA002);
    assert_eq!(BODY_KUZ_CTR_HMAC, 0xA003);
    assert_eq!(WRAP_AEGIS256, 0xB001);
    assert_eq!(KIND_PASSWORD, 0x0001);
    assert_eq!(KIND_CHIP, 0x0003);
    assert_eq!(KIND_PRF, 0x0004);
    assert_eq!(DOMAIN_BODY, b"brby/v2/body");
    assert_eq!(DOMAIN_WRAP_PASSWORD, b"brby/v2/wrap-password");
    assert_eq!(DOMAIN_WRAP_CHIP, b"brby/v2/wrap-chip");
    assert_eq!(HEADER_LEN, 72);
    assert_eq!(COMMIT_LEN, 32);
    assert_eq!(PASSWORD_PAYLOAD_LEN, 104);
    assert_eq!(PASSWORD_RECORD_LEN, 110);
}

#[test]
fn roundtrip_password_header_body_and_commit() {
    let header = sample_header(BODY_AEGIS256);
    let entry = password_record();
    assert_eq!(entry.len(), PASSWORD_RECORD_LEN);
    assert_eq!(&entry[..2], &KIND_PASSWORD.to_le_bytes());
    assert_eq!(&entry[2..6], &104u32.to_le_bytes());
    let body = [0x22u8; 64];
    let file = file_from(&header, &[&entry], &body, 42);
    let parsed = file.parse().unwrap();
    assert_eq!(parsed.header, header);
    assert_eq!(
        parsed.header.to_bytes().as_slice(),
        &file.as_bytes()[..HEADER_LEN]
    );
    assert_eq!(parsed.generation, 42);
    assert_eq!(parsed.body, body.as_slice());
    assert_eq!(parsed.commit, [0x44; COMMIT_LEN]);
    let WrapEntry::Password(password) = parsed.entries.first().unwrap() else {
        panic!("expected one password entry");
    };
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(password.kid, [9; 8]);
    assert_eq!(password.nonce, [1; 32]);
    assert_eq!(password.ct, [2; 32]);
    assert_eq!(password.tag, [3; 32]);
    assert_eq!(
        StaticHeader::try_from(header.to_bytes().as_slice()).unwrap(),
        header
    );
}

#[test]
fn bad_magic_is_reported_before_length() {
    assert_eq!(
        VaultFile::new(vec![]).parse().unwrap_err().to_string(),
        "bad magic"
    );
    assert_eq!(
        VaultFile::new(vec![0x01]).parse().unwrap_err().to_string(),
        "bad magic"
    );
    assert_eq!(
        VaultFile::new(b"BRB".to_vec())
            .parse()
            .unwrap_err()
            .to_string(),
        "bad magic"
    );
    assert_eq!(
        VaultFile::new(b"BRBX".to_vec())
            .parse()
            .unwrap_err()
            .to_string(),
        "bad magic"
    );
    let mut long = vec![0xAB; 200];
    long[..4].copy_from_slice(b"nope");
    assert_eq!(
        VaultFile::new(long).parse().unwrap_err().to_string(),
        "bad magic"
    );
}

#[test]
fn short_file_with_magic_is_corrupted_length() {
    for len in [4usize, 20, 71, 72, 103] {
        let mut bytes = vec![0u8; len];
        bytes[..4].copy_from_slice(b"BRBY");
        assert_eq!(
            VaultFile::new(bytes).parse().unwrap_err().to_string(),
            "corrupted length",
            "len {len}"
        );
    }
}

#[test]
fn truncated_prefixes_of_a_valid_file_fail() {
    let entry = password_record();
    let file = file_from(&sample_header(BODY_AEGIS256), &[&entry], &[0x22; 64], 1);
    let bytes = file.as_bytes();
    assert!(bytes.len() > HEADER_LEN);
    for len in 0..bytes.len() {
        let err = VaultFile::new(bytes[..len].to_vec()).parse().unwrap_err();
        assert_allowed(&err);
    }
}

#[test]
fn two_password_entries_are_allowed() {
    let first = password_record();
    let second = encode_password_entry([8; 8], [4; 32], [5; 32], [6; 32]);
    let file = file_from(
        &sample_header(BODY_AEGIS256),
        &[&first, &second],
        &[0x22; 64],
        1,
    );
    let parsed = file.parse().unwrap();
    assert_eq!(parsed.entries.len(), 2);
}

#[test]
fn file_without_password_wrap_is_rejected() {
    let chip = chip_record(0xAB, 0x5A);
    let file = file_from(&sample_header(BODY_AEGIS256), &[&chip], &[0x22; 64], 1);
    assert_eq!(file.parse().unwrap_err().to_string(), "no password wrap");
}

#[test]
fn chip_entry_roundtrip() {
    let entry = chip_record(0xA1, 0x5A);
    assert_eq!(&entry[..2], &KIND_CHIP.to_le_bytes());
    let WrapEntry::Chip(chip) = WrapEntry::try_from(entry.as_slice()).unwrap() else {
        panic!("expected a chip entry");
    };
    assert_eq!(chip.id, [0xA1; 16]);
    assert_eq!(chip.chip_pub, [0x41; 65]);
    assert_eq!(chip.eph_pub, [0x43; 65]);
    assert_eq!(chip.pq_pk, [0x42; PQ_PK_LEN]);
    assert_eq!(chip.kem_ct, &[0x5A; KEM_CT_LEN]);
    assert_eq!(chip.nonce, [1; 32]);
    assert_eq!(chip.ct, [0x5A; 32]);
    assert_eq!(chip.tag, [3; 32]);
    let password = password_record();
    let file = file_from(
        &sample_header(BODY_AEGIS256),
        &[&password, &entry],
        &[0x22; 64],
        1,
    );
    let parsed = file.parse().unwrap();
    assert_eq!(parsed.entries.len(), 2);
}

#[test]
fn prf_entry_roundtrip() {
    let entry =
        encode_prf_entry([0xB2; 16], &[0x77; 32], [9; 32], [1; 32], [2; 32], [3; 32]).unwrap();
    assert_eq!(&entry[..2], &KIND_PRF.to_le_bytes());
    let WrapEntry::Prf(prf) = WrapEntry::try_from(entry.as_slice()).unwrap() else {
        panic!("expected a prf entry");
    };
    assert_eq!(prf.id, [0xB2; 16]);
    assert_eq!(prf.cred_id, &[0x77; 32]);
    assert_eq!(prf.salt, [9; 32]);
    assert_eq!(prf.nonce, [1; 32]);
    assert_eq!(prf.ct, [2; 32]);
    assert_eq!(prf.tag, [3; 32]);
    // Credential ids outside 16..=64 bytes are corruption.
    let short = encode_prf_entry([0; 16], &[0; 15], [0; 32], [0; 32], [0; 32], [0; 32]);
    assert_eq!(short.unwrap_err().to_string(), "corrupted length");
    let long = encode_prf_entry([0; 16], &[0; 65], [0; 32], [0; 32], [0; 32], [0; 32]);
    assert_eq!(long.unwrap_err().to_string(), "corrupted length");
}

#[test]
fn distinct_chip_ids_parse_and_borrow_the_ciphertext() {
    let password = password_record();
    let first = chip_record(0xAB, 0x5A);
    let second = chip_record_with_kem(0xCD, 0x5B, 0x5C);
    let file = file_from(
        &sample_header(BODY_AEGIS256),
        &[&password, first.as_slice(), second.as_slice()],
        &[0x22; 64],
        6,
    );
    let parsed = file.parse().unwrap();
    assert_eq!(parsed.generation, 6);
    assert_eq!(parsed.entries.len(), 3);
    let WrapEntry::Chip(chip) = parsed.entries.get(2).unwrap() else {
        panic!("expected chip");
    };
    assert_eq!(chip.id, [0xCD; 16]);
    assert_eq!(chip.kem_ct, &[0x5C; KEM_CT_LEN]);
    let bytes = file.as_bytes();
    assert!(bytes.as_ptr_range().contains(&chip.kem_ct.as_ptr()));
}

#[test]
fn duplicate_chip_and_prf_ids_are_rejected() {
    // Every id-carrying kind must reject a repeat: "remove this id" would
    // otherwise be ambiguous and could leave a hidden unlock path behind.
    let password = password_record();
    let chip_first = chip_record(0xAB, 0x5A);
    let chip_dupe = chip_record(0xAB, 0x5B);
    let chip_file = file_from(
        &sample_header(BODY_AEGIS256),
        &[&password, chip_first.as_slice(), chip_dupe.as_slice()],
        &[0x22; 64],
        2,
    );
    assert_eq!(
        chip_file.parse().unwrap_err().to_string(),
        "corrupted length"
    );

    let prf_first =
        encode_prf_entry([0xB2; 16], &[0x77; 32], [9; 32], [1; 32], [2; 32], [3; 32]).unwrap();
    let prf_dupe =
        encode_prf_entry([0xB2; 16], &[0x78; 32], [9; 32], [1; 32], [2; 32], [3; 32]).unwrap();
    let prf_file = file_from(
        &sample_header(BODY_AEGIS256),
        &[&password, prf_first.as_slice(), prf_dupe.as_slice()],
        &[0x22; 64],
        2,
    );
    assert_eq!(
        prf_file.parse().unwrap_err().to_string(),
        "corrupted length"
    );

    // Distinct ids of the same kind still parse.
    let prf_other =
        encode_prf_entry([0xB3; 16], &[0x77; 32], [9; 32], [1; 32], [2; 32], [3; 32]).unwrap();
    let ok = file_from(
        &sample_header(BODY_AEGIS256),
        &[&password, prf_first.as_slice(), prf_other.as_slice()],
        &[0x22; 64],
        2,
    );
    assert_eq!(ok.parse().unwrap().entries.len(), 3);
}

#[test]
fn entry_len_mismatch_does_not_allocate_the_claimed_size() {
    let entry = password_record();
    let mut bytes = file_from(&sample_header(BODY_AEGIS256), &[&entry], &[0x22; 64], 1)
        .as_bytes()
        .to_vec();
    let entry_len_at = HEADER_LEN + 2 + 8 + 2;
    bytes[entry_len_at..entry_len_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        VaultFile::new(bytes).parse().unwrap_err().to_string(),
        "corrupted length"
    );

    let mut minimal = sample_header(BODY_AEGIS256).to_bytes().to_vec();
    minimal.extend_from_slice(&1u16.to_le_bytes());
    minimal.extend_from_slice(&1u64.to_le_bytes());
    minimal.extend_from_slice(&KIND_PASSWORD.to_le_bytes());
    minimal.extend_from_slice(&103u32.to_le_bytes());
    minimal.extend_from_slice(&[0u8; COMMIT_LEN]);
    assert_eq!(
        VaultFile::new(minimal).parse().unwrap_err().to_string(),
        "corrupted length"
    );
}

#[test]
fn unknown_kind_is_not_skipped() {
    let password = password_record();
    let unknown = {
        let mut raw = vec![0u8; 6];
        raw[..2].copy_from_slice(&0x0003u16.to_le_bytes());
        raw[2..6].copy_from_slice(&0u32.to_le_bytes());
        raw
    };
    let file = file_from(
        &sample_header(BODY_AEGIS256),
        &[unknown.as_slice(), &password],
        &[0x22; 64],
        1,
    );
    assert_eq!(file.parse().unwrap_err().to_string(), "corrupted length");
}

#[test]
fn kdf_floor_and_ceiling_are_inclusive() {
    let cases = [
        (KDF_M_KIB_MIN - 1, KDF_T_MIN, KDF_P_MIN, true),
        (KDF_M_KIB_MAX + 1, KDF_T_MIN, KDF_P_MIN, true),
        (1_048_577, 2, 1, true),
        (19_455, 2, 1, true),
        (KDF_M_KIB_MIN, KDF_T_MIN - 1, KDF_P_MIN, true),
        (KDF_M_KIB_MIN, KDF_T_MAX + 1, KDF_P_MIN, true),
        (KDF_M_KIB_MIN, KDF_T_MIN, KDF_P_MIN - 1, true),
        (KDF_M_KIB_MIN, KDF_T_MIN, KDF_P_MAX + 1, true),
        (KDF_M_KIB_MIN, KDF_T_MIN, KDF_P_MIN, false),
        (KDF_M_KIB_MAX, KDF_T_MAX, KDF_P_MAX, false),
    ];
    for (m_kib, t, p, rejected) in cases {
        let mut bytes = header_with(BODY_AEGIS256, m_kib, t, p).to_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; COMMIT_LEN]);
        let err = VaultFile::new(bytes).parse().unwrap_err();
        if rejected {
            assert_eq!(
                err.to_string(),
                "kdf parameters rejected",
                "m={m_kib} t={t} p={p}"
            );
        } else {
            assert_eq!(err.to_string(), "corrupted length", "m={m_kib} t={t} p={p}");
        }
    }
}

#[test]
fn algorithm_ids_are_checked_before_kdf_params() {
    let mut bytes = sample_header(BODY_AEGIS256).to_bytes().to_vec();
    bytes.extend_from_slice(&[0u8; COMMIT_LEN]);

    let mut version_and_m = bytes.clone();
    version_and_m[4..6].copy_from_slice(&9u16.to_le_bytes());
    version_and_m[8..12].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        VaultFile::new(version_and_m)
            .parse()
            .unwrap_err()
            .to_string(),
        "unsupported version 0x0009"
    );

    let mut kdf_and_wrap = bytes.clone();
    kdf_and_wrap[6..8].copy_from_slice(&2u16.to_le_bytes());
    kdf_and_wrap[70..72].copy_from_slice(&1u16.to_le_bytes());
    kdf_and_wrap[8..12].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        VaultFile::new(kdf_and_wrap)
            .parse()
            .unwrap_err()
            .to_string(),
        "unsupported kdf 0x0002"
    );

    let mut wrap_and_body = bytes.clone();
    wrap_and_body[70..72].copy_from_slice(&1u16.to_le_bytes());
    wrap_and_body[68..70].copy_from_slice(&1u16.to_le_bytes());
    wrap_and_body[8..12].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        VaultFile::new(wrap_and_body)
            .parse()
            .unwrap_err()
            .to_string(),
        "unsupported wrap algorithm 0x0001"
    );

    let mut body_and_m = bytes;
    body_and_m[68..70].copy_from_slice(&9u16.to_le_bytes());
    body_and_m[8..12].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        VaultFile::new(body_and_m).parse().unwrap_err().to_string(),
        "unsupported body algorithm 0x0009"
    );
}

#[test]
fn retired_device_kind_and_recognized_body_minimums() {
    let password = password_record();
    // The X25519 device wrap is retired: a well-formed record of its kind no
    // longer parses as a standalone entry or inside a file.
    let retired = retired_device_record();
    assert_eq!(
        WrapEntry::try_from(retired.as_slice())
            .unwrap_err()
            .to_string(),
        "corrupted length"
    );
    let file = file_from(
        &sample_header(BODY_AEGIS256),
        &[&password, retired.as_slice()],
        &[0x22; 64],
        1,
    );
    assert_eq!(file.parse().unwrap_err().to_string(), "corrupted length");

    let minimums = [
        (BODY_AEGIS256, 64usize),
        (BODY_KUZ_MGM, 32usize),
        (BODY_KUZ_CTR_HMAC, 40usize),
    ];
    for (alg, min_len) in minimums {
        let ok = file_from(&sample_header(alg), &[&password], &vec![0x22; min_len], 1);
        assert!(ok.parse().is_ok(), "alg {alg:#06x} len {min_len}");
        let short = file_from(
            &sample_header(alg),
            &[&password],
            &vec![0x22; min_len - 1],
            1,
        );
        assert_eq!(short.parse().unwrap_err().to_string(), "corrupted length");
    }
}

#[test]
fn exact_wrap_directory_rejects_a_trailing_body() {
    let entry = password_record();
    let dir = encode_wrap_dir(7, &[&entry]).unwrap();
    let parsed = WrapDir::try_from(dir.as_slice()).unwrap();
    assert_eq!(parsed.generation, 7);
    assert_eq!(parsed.entries.len(), 1);
    let mut with_tail = dir;
    with_tail.push(0);
    assert_eq!(
        WrapDir::try_from(with_tail.as_slice())
            .unwrap_err()
            .to_string(),
        "corrupted length"
    );
}

#[test]
fn wrap_count_must_fit_in_u16() {
    let empty: &[u8] = &[];
    let entries = vec![empty; 65_536];
    assert_eq!(
        encode_wrap_dir(1, &entries).unwrap_err().to_string(),
        "corrupted length"
    );
}

#[test]
fn one_byte_and_random_inputs_only_return_format_errors() {
    assert_eq!(
        VaultFile::new(vec![0x7F]).parse().unwrap_err().to_string(),
        "bad magic"
    );

    let mut rng = Lcg(0x1234_5678_9ABC_DEF0);
    for index in 0..400 {
        let len = rng.next_len();
        let mut bytes = vec![0u8; len];
        rng.fill(&mut bytes);
        if index % 2 == 0 && bytes.len() >= 4 {
            bytes[..4].copy_from_slice(b"BRBY");
        }
        let err = VaultFile::from(bytes).parse().unwrap_err();
        assert_allowed(&err);
    }
}

struct Lcg(u64);

impl Lcg {
    const fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn next_len(&mut self) -> usize {
        usize::try_from(self.next_u64() % 2048).unwrap_or(0)
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for slot in bytes {
            *slot = u8::try_from(self.next_u64() & 0xff).unwrap_or(0);
        }
    }
}

#[test]
fn human_password_roundtrip_and_floor() {
    // In-range parameters parse; sub-floor parameters do not.
    let ok = encode_human_password_entry(
        [7u8; 8],
        [8u8; 32],
        HumanKdf {
            m_kib: KDF_M_KIB_MIN,
            t: KDF_T_MIN,
            p: KDF_P_MIN,
        },
        [9u8; 32],
        [0x66; 32],
        [0x77; 32],
    );
    let file = file_from(
        &sample_header(BODY_AEGIS256),
        &[&password_record(), ok.as_slice()],
        &[0x55; 64],
        2,
    );
    let parsed = file.parse().unwrap();
    assert_eq!(parsed.entries.len(), 2);
    let WrapEntry::HumanPassword(human) = parsed.entries.get(1).unwrap() else {
        panic!("second entry must be the human password wrap");
    };
    assert_eq!(human.kid, [7u8; 8]);
    assert_eq!(
        human.kdf,
        HumanKdf {
            m_kib: KDF_M_KIB_MIN,
            t: KDF_T_MIN,
            p: KDF_P_MIN
        }
    );

    // Downgrade attempt: memory below the floor.
    let weak = encode_human_password_entry(
        [7u8; 8],
        [8u8; 32],
        HumanKdf {
            m_kib: KDF_M_KIB_MIN - 1,
            t: KDF_T_MIN,
            p: KDF_P_MIN,
        },
        [9u8; 32],
        [0x66; 32],
        [0x77; 32],
    );
    let weak_file = file_from(
        &sample_header(BODY_AEGIS256),
        &[&password_record(), weak.as_slice()],
        &[0x55; 64],
        2,
    );
    assert_eq!(
        weak_file.parse().unwrap_err().to_string(),
        "kdf parameters rejected"
    );

    // Time above the ceiling: also refused.
    let hot = encode_human_password_entry(
        [7u8; 8],
        [8u8; 32],
        HumanKdf {
            m_kib: KDF_M_KIB_MIN,
            t: KDF_T_MAX + 1,
            p: KDF_P_MIN,
        },
        [9u8; 32],
        [0x66; 32],
        [0x77; 32],
    );
    let hot_file = file_from(
        &sample_header(BODY_AEGIS256),
        &[&password_record(), hot.as_slice()],
        &[0x55; 64],
        2,
    );
    assert_eq!(
        hot_file.parse().unwrap_err().to_string(),
        "kdf parameters rejected"
    );
}
