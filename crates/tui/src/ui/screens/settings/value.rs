//! The value column of each settings row, as text. Drawing only: every
//! fact comes from the draft, the public vault info, or the services.

use kdf::KdfProfile;
use session::Factor;

use crate::app::ctx::Ctx;
use crate::app::flows::settings::posture::{posture, Facts};
use crate::app::flows::settings::rows::Row;
use crate::app::flows::settings::SettingsModal;
use crate::app::flows::unlocked::Unlocked;
use crate::app::prefs::theme_of;
use crate::ui::widgets::chrome::checkbox;
use crate::ui::widgets::fingerprint::{grouped_hex, stripe_print};
use crate::vault::factors::presence;

use super::sync_value::sync_value;

/// Text of `row`'s value.
#[must_use]
pub fn value(row: Row, state: &Unlocked, modal: &SettingsModal, ctx: &Ctx) -> String {
    let draft = &modal.draft;
    let info = &state.info;
    match row {
        Row::AutoLock => human(u64::from(draft.lock_after_s)),
        Row::FocusLock => checkbox(draft.focus_lock).to_owned(),
        Row::RevealHide => format!("{} s", draft.reveal_hide_s),
        Row::PasswordCost => password_cost(state).map_or_else(
            || String::from("none · Enter adds one"),
            |(m_kib, t, p)| format!("Argon2id {} MiB · t{t} · p{p}", m_kib / 1024),
        ),
        Row::Factors => format!("{} on file · open", info.directory.factors.len()),
        Row::DeviceStatus => match info.owned_device() {
            Some(_) => String::from("enrolled · PIN-sealed key file"),
            None => String::from("not enrolled · Enter to enroll"),
        },
        Row::DeviceFingerprint => info.owned_device().map_or_else(
            || String::from("—"),
            |id| {
                format!(
                    "{} {}",
                    stripe_print(&id, ctx.theme.glyphs),
                    grouped_hex(&id, 2)
                )
            },
        ),
        Row::DevicePin => info
            .device
            .map_or_else(|| String::from("—"), |device| profile_text(device.profile)),
        Row::SecureEnclave => String::from("not for terminal apps"),
        Row::SyncStatus
        | Row::LastCheckIn
        | Row::SyncPeers
        | Row::SyncDevices
        | Row::SyncRelays
        | Row::SyncAdvertised
        | Row::SyncBeacon
        | Row::SyncNow => sync_value(row, state, ctx),
        Row::RotateKey | Row::ForgetDevice | Row::ClearHistory | Row::Import => {
            String::from("Enter")
        }
        Row::ClipClear => format!("{} s", draft.clip_clear_s),
        Row::ClipOnLock => String::from("always"),
        Row::Theme if ctx.no_color => format!("{} (NO_COLOR wins)", theme_of(draft.theme).label()),
        Row::Theme => theme_of(draft.theme).label().to_owned(),
        Row::Animation => checkbox(draft.anim).to_owned(),
        Row::Ascii => checkbox(draft.ascii).to_owned(),
        Row::Name => info.label.clone(),
        Row::Cipher => String::from("AEGIS-256 inside Kuznyechik-CTR+HMAC"),
        Row::Generation => info.generation.to_string(),
        Row::Records => state.cache.len().to_string(),
        Row::FilePath => state
            .vaults
            .get(state.current)
            .map_or_else(String::new, |vault| home_relative(&vault.paths.vault_file)),
        Row::Version => format!("zebrapass {}", env!("CARGO_PKG_VERSION")),
        Row::DataDir => home_relative(&ctx.base),
        Row::Primitives => String::from("ML-KEM-768 · ML-DSA-65 · AEGIS-256 · Argon2id"),
        Row::Posture => score(state, modal).advice.to_owned(),
    }
}

/// The posture of the draft against the vault's public facts.
#[must_use]
pub fn score(
    state: &Unlocked,
    modal: &SettingsModal,
) -> crate::app::flows::settings::posture::Posture {
    let info = &state.info;
    let facts = Facts {
        presence: presence(&info.directory, info.owned_device()),
        pin_profile: info.device.map(|device| device.profile),
        password_m_kib: password_cost(state).map(|(m_kib, _, _)| m_kib),
    };
    posture(&modal.draft, &facts)
}

fn password_cost(state: &Unlocked) -> Option<(u32, u32, u32)> {
    state
        .info
        .directory
        .factors
        .iter()
        .find_map(|factor| match factor {
            Factor::Password { m_kib, t, p } => Some((*m_kib, *t, *p)),
            Factor::Recovery | Factor::Chip(_) | Factor::Prf { .. } => None,
        })
}

fn profile_text(profile: KdfProfile) -> String {
    let name = match profile {
        KdfProfile::Fast => "Fast",
        KdfProfile::Balanced => "Balanced",
        KdfProfile::Strong => "Strong",
    };
    format!(
        "Argon2id {} MiB ({name}) · Enter changes",
        profile.m_kib() / 1024
    )
}

/// `30 s`, `5 min`, `1 h`.
fn human(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs / 60),
        _ => format!("{} h", secs / 3600),
    }
}

/// A path with the home directory shortened to `~`.
fn home_relative(path: &std::path::Path) -> String {
    let full = path.display().to_string();
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .and_then(|home| {
            path.strip_prefix(home)
                .ok()
                .map(|rest| format!("~/{}", rest.display()))
        })
        .unwrap_or(full)
}
