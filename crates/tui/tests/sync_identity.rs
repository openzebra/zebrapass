//! A new vault gets a sealed sync identity chained to the phrase's root key,
//! and no copy of the root seed is kept.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use local::SyncIdentity;
use seed::SeedPhrase;
use session::KdfProfile;
use tui::vault::create::{create, Enrollment, NewVault};
use zeroize::Zeroizing;

#[test]
fn create_enrolls_a_device_identity_under_the_phrase_root() {
    let base = common::temp_dir("syncid");
    let phrase = SeedPhrase::generate_24().unwrap();
    let root_seed = kdf::sync_seed(phrase.seed()).unwrap();
    let expected_vk = session::sync_verifying_key(root_seed.expose()).unwrap();
    let vault = create(NewVault {
        phrase: Box::new(phrase),
        name: String::from("Personal"),
        base: base.clone(),
        profile: KdfProfile::Fast,
        factor: Enrollment::Password(Zeroizing::new(common::PASSWORD.as_bytes().to_vec())),
        records: Vec::new(),
    })
    .unwrap();

    let path = vault.paths.sync_identity();
    let identity = SyncIdentity::load(&path, &vault.session.sync_identity_key().unwrap()).unwrap();
    assert_eq!(identity.root_vk().as_slice(), expected_vk.as_slice());
    assert_eq!(identity.devices()[0].device_id, vault.meta.device_id);
    identity.devices()[0].verify(identity.root_vk(), 0).unwrap();

    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes
        .windows(32)
        .any(|window| window == root_seed.expose().as_slice()));
    std::fs::remove_dir_all(&base).unwrap();
}
