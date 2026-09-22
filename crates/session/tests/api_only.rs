//! The full user flow must compile and run against `session::` alone —
//! no internal workspace crates in scope. Guards the re-exports in lib.rs.

#![allow(clippy::unwrap_used, reason = "tests may unwrap")]

use session::{
    change_password, create, reencrypt_body, unlock, write_records, BodyAlg, KdfProfile, VaultFile,
};

const PW: &str = "correct horse battery staple";
const PW2: &str = "reencrypted body staple";
const PW3: &str = "third rotation staple";

#[test]
fn api_only_password_flow() {
    // bytes on disk: consumer only ever calls as_bytes()/VaultFile::new()
    let (mut file, _s) = create(PW, KdfProfile::Mobile, BodyAlg::Aegis256).unwrap();
    let restored = VaultFile::new(file.as_bytes().to_vec());

    let mut s = unlock(&restored, PW, None, None).unwrap();

    write_records(&mut s, &mut file, b"{}").unwrap();
    change_password(&mut s, &mut file, PW2).unwrap();
    assert!(unlock(&file, PW, None, None).is_err());

    reencrypt_body(&mut s, &mut file, b"{}", PW3, &[]).unwrap();
    assert!(unlock(&file, PW2, None, None).is_err());
    unlock(&file, PW3, None, None).unwrap();
}
