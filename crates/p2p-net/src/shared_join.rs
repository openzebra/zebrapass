//! Finishing a fetch: what a device does with the log, file and seed a member
//! sent it.

use std::path::Path;

use anyhow::Result;
use local::{
    adopt_shared_file, prepare_rekey, read_member_log, save_member_log, shared_paths_for, Attested,
    RekeyPlan, SharedRef, SharedVault, SyncIdentity,
};
use secret::Secret;
use session::VaultFile;
use syncwire::decode_snapshot;

use crate::shared::{decode_entries, unavailable};

/// What finishing a fetch produced.
pub enum Joined {
    /// A device that was waiting for its first file now has the vault.
    Opened(Box<SharedVault>),
    /// A new seed was offered and everything checked out, but nothing is
    /// written yet. Store [`RekeyPlan::reference`] in the personal vault,
    /// then [`RekeyPlan::commit`].
    Rekey(Box<RekeyPlan>),
    /// The vault was already open and nothing in the fetch replaces it.
    Unchanged,
}

impl std::fmt::Debug for Joined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Opened(_) => "Opened",
            Self::Rekey(_) => "Rekey",
            Self::Unchanged => "Unchanged",
        })
    }
}

/// What a device already knows about the vault it is fetching.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Known {
    /// Generation of the vault file it has.
    pub generation: u64,
    /// The file only opens with a retired seed: a rotation reached the
    /// reference but not the files.
    pub stale: bool,
}

/// A seed and epoch as a peer offers them.
pub fn parse_rekey(bytes: &[u8]) -> Option<(Secret<[u8; 64]>, u32)> {
    let (seed, epoch) = bytes.split_first_chunk::<64>()?;
    let epoch = u32::from_be_bytes(<[u8; 4]>::try_from(epoch).ok()?);
    let mut secret = Secret::new([0u8; 64]);
    secret.expose_mut().copy_from_slice(seed);
    Some((secret, epoch))
}

/// Finish a fetch from what a member sent: its member log, its vault file,
/// and the seed it offered, if any.
///
/// A seed from a later epoch is taken only if the log (every new entry
/// verified) reached that epoch and the seed hashes to the owner-signed
/// commitment; the file must open with it. The same seed is taken again when
/// the open vault is stale, which finishes a rotation that was cut short.
/// Otherwise a device still waiting for its first file adopts it, and one
/// that already has a vault keeps it. `known` is `None` while pending.
///
/// # Errors
///
/// `shared vault unavailable` for any failed check: a log that does not
/// extend the stored one, a vault whose log no longer lists this account, a
/// seed that does not match its commitment, or a file that is not the vault;
/// storage and key-derivation errors.
pub fn finish_join(
    base: &Path,
    reference: &SharedRef,
    identity: &SyncIdentity,
    log_bytes: &[u8],
    snapshot: Vec<u8>,
    rekey: Option<&[u8]>,
    known: Option<Known>,
) -> Result<Joined> {
    let entries = decode_entries(log_bytes)?;
    let floor = known.map(|known| known.generation);
    let target = rekey.and_then(parse_rekey).and_then(|(seed, epoch)| {
        if epoch > reference.epoch {
            Some(reference.rotated(seed, epoch))
        } else if epoch == reference.epoch
            && known.is_some_and(|known| known.stale)
            && seed.expose() == reference.seed.expose()
        {
            Some(reference.duplicate())
        } else {
            None
        }
    });
    if let Some(next) = target {
        let (file, attestations) = decode_snapshot(snapshot)?;
        let plan = prepare_rekey(
            base,
            reference,
            next,
            Attested {
                file: VaultFile::new(file),
                attestations: &attestations,
            },
            identity,
            &entries,
            floor,
        )?;
        return Ok(Joined::Rekey(Box::new(plan)));
    }
    if known.is_some() {
        return Ok(Joined::Unchanged);
    }
    let (file, attestations) = decode_snapshot(snapshot)?;
    let paths = shared_paths_for(base, &reference.vault_id);
    let key = kdf::shared_members_key(reference.seed.expose(), &reference.vault_id)?;
    let mut log = read_member_log(base, reference)?;
    log.merge(&entries)?;
    let own = identity.devices().first().ok_or_else(unavailable)?;
    let introduced = reference
        .introduction
        .as_ref()
        .is_none_or(|intro| intro.confirms(&log));
    if log.role_of(&own.client_id).is_none() || !introduced {
        return Err(unavailable());
    }
    save_member_log(&paths.members_log(), &key, &log)?;
    let vault = adopt_shared_file(
        base,
        reference,
        VaultFile::new(file),
        &attestations,
        identity,
    )?;
    Ok(Joined::Opened(Box::new(vault)))
}
