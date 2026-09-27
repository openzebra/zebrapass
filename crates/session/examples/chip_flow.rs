//! End-to-end chip-unlock flow over a software chip backend.
//!
//! Seals the vault key to a password grant and a chip grant, opens the vault
//! with the chip alone, removes the chip grant, and opens the vault with the
//! password again. Run with `cargo run -p session --example chip_flow`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use container::WrapEntry;
use platform::{ChipBackend, SoftwareChip};
use pq::keypair;
use session::{
    add_chip_unlock, create, remove_chip_unlock, unlock, BodyAlg, ChipKeys, ChipPublics, KdfProfile,
    UnlockCreds,
};

const SEED: [u8; 64] = [0x7F; 64];

fn main() -> anyhow::Result<()> {
    // 1. A vault that only the password can open.
    let (mut file, mut session) = create(&SEED, KdfProfile::Mobile, BodyAlg::Aegis256)?;

    // 2. A chip key under the platform alias for this vault. `SoftwareChip`
    //    stands in for Secure Enclave / StrongBox; the secret never leaves it.
    let vault_id = file.parse()?.header.vault_id;
    let alias: String = std::iter::once("zp/".to_owned())
        .chain(vault_id.iter().map(|byte| format!("{byte:02x}")))
        .collect();
    let chip = SoftwareChip::new();
    let chip_pub = chip.generate_pair(&alias)?;

    // 3. The PQ half reuses this phone's `ntrulp` key, the same one the
    //    device wrap uses. The grant is the hybrid AND of both halves.
    let (pq_pk_bytes, pq_sk) = keypair()?;
    let publics = ChipPublics {
        id: [0x11; 16],
        chip_pub,
        pq_pk: pq_pk_bytes.as_slice().try_into()?,
    };
    let grant = add_chip_unlock(&mut session, &mut file, &publics)?;
    println!("chip grant added: {} bytes", grant.as_bytes().len());

    // 4. Chip-only unlock: the platform computes ECDH(chip_sk, eph_pub) and
    //    hands out the 32-byte shared secret; no password is presented.
    let parsed = file.parse()?;
    let wrap = parsed
        .entries
        .iter()
        .find_map(|entry| match entry {
            WrapEntry::Chip(wrap) if wrap.id == publics.id => Some(wrap),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("wrap not found"))?;
    let ss_p256 = chip.ecdh(&alias, &wrap.eph_pub)?;
    let keys = ChipKeys {
        id: publics.id,
        pq_sk,
    };
    let _session = unlock(&file, &UnlockCreds::default().with_chip(&keys, ss_p256), None)?;
    println!("chip unlock ok");

    // 5. The settings toggle: drop the grant, keep the vault key.
    remove_chip_unlock(&mut session, &mut file, &publics.id)?;
    chip.delete(&alias)?;
    let entries = file.parse()?.entries;
    if entries
        .iter()
        .any(|entry| matches!(entry, WrapEntry::Chip(wrap) if wrap.id == publics.id))
    {
        return Err(anyhow::anyhow!("wrap not found"));
    }
    unlock(&file, &UnlockCreds::master(&SEED), None)?;
    println!("password unlock ok");
    Ok(())
}
