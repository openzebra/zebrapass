//! Invitations too big for the terminal clipboard travel as a file. The text
//! is sealed to the invitee's device, so a file holds nothing a stranger could
//! use.

use std::path::PathBuf;

use crate::app::ctx::Ctx;
use crate::app::flows::unlocked::Unlocked;
use crate::ui::widgets::toast::Tone;

const PREFIX: &str = "zp-invite1:";

/// Largest invitation file read back.
const MAX_FILE: u64 = 4 << 20;

impl Unlocked {
    /// Write `invitation` next to the vault files and say where.
    pub(super) fn save_invitation(&self, invitation: &str, number: &str, ctx: &mut Ctx) {
        let name: String = number
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(32)
            .collect();
        let path: PathBuf = self.base.join(format!("invitation-{name}.txt"));
        match local::write_atomic(&path, invitation.as_bytes()) {
            Ok(()) => ctx.toast(
                Tone::Info,
                format!(
                    "Too big to copy here. Saved to {}. Send the file, then paste its path.",
                    path.display()
                ),
            ),
            Err(_) => ctx.toast(Tone::Warn, "Could not copy or save the invitation."),
        }
    }
}

/// The invitation text: `text` itself, or the contents of the file whose path
/// it names.
#[must_use]
pub fn invitation_text(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.starts_with(PREFIX) {
        return trimmed.to_owned();
    }
    let path = std::path::Path::new(trimmed.trim_matches(|c| c == '\'' || c == '"'));
    let readable = std::fs::metadata(path)
        .ok()
        .filter(|meta| meta.is_file() && meta.len() <= MAX_FILE);
    readable
        .and_then(|_| std::fs::read_to_string(path).ok())
        .map_or_else(|| trimmed.to_owned(), |body| body.trim().to_owned())
}
