//! One helper for wrap-directory edits: parse, edit, commit, publish.
//!
//! Every wrap mutation (add, remove, re-seal) goes through [`rewrap`], so the
//! parse → edit → generation → commit pipeline exists exactly once. The body
//! bytes are reused as-is: the new file is fully assembled inside the parse
//! borrow and only then replaces `file`, so no whole-body copy is needed.

use container::{Parsed, VaultFile, WrapEntry};

use crate::create::{assemble_committed, commit_mode, dir_bytes, next_generation, Session};

/// Rebuild the wrap directory in one place.
///
/// `edit` sees the parsed file and the session vault key (passed in, because a
/// closure over `&mut Session` would fight the helper's own borrow) and
/// returns the full new record list plus a by-product for the caller — a grant
/// for the add paths, `()` for removals. The body is reused unchanged.
/// Generation increases by one and the commit is recomputed. On error, `file`
/// and `session` are left as they were.
///
/// # Errors
///
/// Whatever `edit` returns, plus the parse, encode, and RNG failures of the
/// commit pipeline (`corrupted length`, KDF, and randomness errors).
pub fn rewrap<T>(
    session: &mut Session,
    file: &mut VaultFile,
    edit: impl FnOnce(&Parsed<'_>, &[u8; 32]) -> anyhow::Result<(Vec<Vec<u8>>, T)>,
) -> anyhow::Result<T> {
    let (updated, generation, tag, out) = {
        let parsed = file.parse()?;
        let (records, out) = edit(&parsed, session.vk.expose())?;
        let generation = next_generation(parsed.generation)?;
        let wrap_dir = dir_bytes(generation, &records)?;
        let (updated, tag) = assemble_committed(
            session.k_commit.expose(),
            &parsed.header,
            &wrap_dir,
            parsed.body,
            commit_mode(session.body_alg),
        )?;
        (updated, generation, tag, out)
    };
    *file = updated;
    session.generation = generation;
    session.commit_tag = tag;
    Ok(out)
}

/// Report whether an entry of `kind` with `id` is already in `entries`.
///
/// A repeated id does not parse (duplicate ids are rejected at parse time);
/// the add paths reject it before sealing so the file is left unchanged.
#[must_use]
pub fn id_in_use(entries: &[WrapEntry<'_>], kind: u16, id: &[u8; 16]) -> bool {
    entries
        .iter()
        .any(|entry| entry.kind() == kind && entry.wrap_id() == Some(*id))
}
