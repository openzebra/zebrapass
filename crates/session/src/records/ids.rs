//! New record ids: random, drawn from the operating system's generator.
//!
//! Two devices that create records while apart must not pick the same id, so
//! an id is 32 random bits, the same space the shared vaults use, never `0`
//! (the reserved metadata record) and never one the vault already holds,
//! tombstoned ones included. Older vaults keep the small sequential ids they
//! were given; only creation changed.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use frame::FrameRef;

use super::index;
use crate::create::Session;

/// Draws made for one id before giving up.
const DRAWS: usize = 32;

/// One id from the operating system. Failure is an error, never a fallback.
fn os_draw() -> Result<u32> {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).map_err(|_| anyhow!("os entropy failed"))?;
    Ok(u32::from_be_bytes(bytes))
}

/// The first draw that is not `0` and not `taken`, within [`DRAWS`] tries.
pub(super) fn pick(
    mut draw: impl FnMut() -> Result<u32>,
    taken: impl Fn(u32) -> bool,
) -> Result<u32> {
    for _ in 0..DRAWS {
        let id = draw()?;
        if id != 0 && !taken(id) {
            return Ok(id);
        }
    }
    Err(anyhow!("no free record id"))
}

fn held(refs: &[FrameRef]) -> HashSet<u32> {
    refs.iter().map(|frame| frame.record_id).collect()
}

/// `count` distinct new ids, none of them held in `refs`.
pub(super) fn fresh_many(refs: &[FrameRef], count: usize) -> Result<Vec<u32>> {
    let mut taken = held(refs);
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        let id = pick(os_draw, |id| taken.contains(&id))?;
        taken.insert(id);
        ids.push(id);
    }
    Ok(ids)
}

/// A new record id for `session`: random, not `0`, not one it holds.
///
/// # Errors
///
/// `os entropy failed` when the generator fails; `no free record id` after
/// 32 draws all landed on taken ids; `corrupted length` when the body does
/// not index.
pub fn fresh_record_id(session: &Session) -> Result<u32> {
    let taken = held(&index(session)?);
    pick(os_draw, |id| taken.contains(&id))
}
