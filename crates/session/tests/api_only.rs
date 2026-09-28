//! The full user flow must compile and run against `session::` alone —
//! no internal workspace crates in scope. Guards the re-exports in lib.rs.

#![allow(clippy::unwrap_used, reason = "tests may unwrap")]

use session::{
    change_master, create, reencrypt_body, unlock, write_records, BodyAlg, KdfProfile, UnlockCreds,
    VaultFile,
};

const SEED: [u8; 64] = [0x11; 64];
const SEED2: [u8; 64] = [0x22; 64];
const SEED3: [u8; 64] = [0x33; 64];

#[test]
fn api_only_master_flow() {
    // bytes on disk: consumer only ever calls as_bytes()/VaultFile::new()
    let (mut file, _s) = create(&SEED, KdfProfile::Fast, BodyAlg::Aegis256).unwrap();
    let restored = VaultFile::new(file.as_bytes().to_vec());

    let mut s = unlock(&restored, &UnlockCreds::master(&SEED), None).unwrap();

    write_records(&mut s, &mut file, b"").unwrap();
    change_master(&mut s, &mut file, &SEED2, &[]).unwrap();
    assert!(unlock(&file, &UnlockCreds::master(&SEED), None).is_err());

    reencrypt_body(&mut s, &mut file, &SEED3, &[], &[]).unwrap();
    assert!(unlock(&file, &UnlockCreds::master(&SEED2), None).is_err());
    unlock(&file, &UnlockCreds::master(&SEED3), None).unwrap();
}
