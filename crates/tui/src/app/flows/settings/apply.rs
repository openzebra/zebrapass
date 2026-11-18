//! What the settings modal does: save the draft, close it (asking before
//! throwing edits away), and act on rows that open a guarded form.

use crate::app::action::Action;
use crate::app::ctx::{Ctx, Task};
use crate::app::flows::dialog::{Confirm, ConfirmKind, Dialog};
use crate::app::flows::factors::{FactorsState, form, palette_action};
use crate::app::flows::form::Form;
use crate::app::flows::settings::rows::Row;
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::screen::Nav;
use crate::ui::widgets::toast::Tone;
use crate::vault::create::unix_ms;
use crate::vault::factors::presence;
use crate::vault::ops::{FactorRef, Op};

/// Save the draft to this vault's local metadata.
pub fn save(state: &mut Unlocked, ctx: &mut Ctx) {
    let Some(modal) = state.settings.as_deref() else {
        return;
    };
    if modal.unsaved() == 0 {
        ctx.toast(Tone::Info, "Nothing to apply.");
        return;
    }
    let draft = Box::new(modal.draft.clone());
    state.run(Op::SavePrefs(draft), Task::Save, ctx);
}

/// Close; with unsaved edits, ask first.
pub fn close(state: &mut Unlocked, ctx: &mut Ctx) {
    let Some(unsaved) = state.settings.as_deref().map(super::SettingsModal::unsaved) else {
        return;
    };
    if unsaved == 0 {
        discard(state, ctx);
        return;
    }
    let plural = if unsaved == 1 { "" } else { "s" };
    state.dialog = Some(Box::new(Dialog::Confirm(Confirm {
        kind: ConfirmKind::DiscardSettings,
        title: format!("Discard {unsaved} unsaved change{plural}?"),
        body: vec![String::from(
            "Ctrl-S applies them instead. The preview goes back to what is saved.",
        )],
    })));
}

/// Drop the draft and restore the saved look.
pub fn discard(state: &mut Unlocked, ctx: &mut Ctx) {
    if let Some(modal) = state.settings.take() {
        ctx.preview_look(&modal.saved);
    }
}

/// Enter on `row`.
pub fn activate(state: &mut Unlocked, row: Row, ctx: &mut Ctx) -> Nav {
    let found = presence(&state.info.directory, state.info.owned_device());
    let owned = state.info.owned_device();
    match row {
        Row::AutoLock
        | Row::FocusLock
        | Row::RevealHide
        | Row::BackupKeep
        | Row::ClipClear
        | Row::Theme
        | Row::Animation
        | Row::Ascii => {
            if let Some(modal) = state.settings.as_deref_mut() {
                row.adjust(&mut modal.draft, true);
                ctx.preview_look(&modal.draft);
            }
        }
        Row::PasswordCost if found.password => form(state, Form::change_password()),
        Row::PasswordCost => form(state, Form::add_password()),
        Row::Factors => leave_for(state, View::Factors(FactorsState::default()), ctx),
        Row::DeviceStatus if owned.is_some() => {
            ctx.toast(
                Tone::Info,
                "This device is enrolled. Revoke it in the danger zone.",
            );
        }
        Row::DeviceStatus => form(state, Form::add_device()),
        Row::DevicePin if owned.is_some() => form(state, Form::change_pin()),
        Row::SyncNow => state.sync_now(ctx),
        Row::SyncServers => form(state, sync_servers_form(state)),
        Row::SyncProxy => form(state, sync_proxy_form(state)),
        Row::BackupDir => form(state, backup_dir_form(state)),
        Row::BackupExport => form(state, backup_export_form(state)),
        Row::CloudBackupPush => cloud_backup_push(state, ctx),
        Row::CloudBackupPull => cloud_backup_pull(state, ctx),
        Row::SyncDevices => state.open_addresses(false),
        Row::Name => form(state, Form::rename(&state.info.label)),
        Row::RotateKey => form(state, Form::rotate(found.password)),
        Row::ForgetDevice if owned.is_some() => {
            if let Some(id) = owned {
                form(
                    state,
                    Form::revoke(FactorRef::Device(id), "this device", found.password),
                );
            }
        }
        Row::DevicePin | Row::ForgetDevice => {
            ctx.toast(Tone::Info, "This device is not enrolled for this vault.");
        }
        Row::ClearHistory => return palette_action(state, Action::ClearHistory, ctx),
        Row::Import => crate::app::flows::import_vault::open(state),
        Row::DeviceFingerprint
        | Row::SecureEnclave
        | Row::SyncStatus
        | Row::LastCheckIn
        | Row::SyncPeers
        | Row::SyncRelays
        | Row::SyncAdvertised
        | Row::SyncBeacon
        | Row::ClipOnLock
        | Row::Cipher
        | Row::Generation
        | Row::Records
        | Row::FilePath
        | Row::Version
        | Row::DataDir
        | Row::Primitives => {}
    }
    Nav::Stay
}

fn leave_for(state: &mut Unlocked, view: View, ctx: &mut Ctx) {
    let dirty = state
        .settings
        .as_deref()
        .is_some_and(|modal| modal.unsaved() > 0);
    if dirty {
        ctx.toast(
            Tone::Info,
            "Apply (Ctrl-S) or discard (Esc) your changes first.",
        );
        return;
    }
    discard(state, ctx);
    state.view = view;
}

fn sync_servers_form(state: &Unlocked) -> Form {
    let current = state.settings.as_deref().map_or_else(String::new, |m| {
        m.draft
            .sync_servers
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>()
            .join(", ")
    });
    Form::sync_servers(&current)
}

fn sync_proxy_form(state: &Unlocked) -> Form {
    let current = state
        .settings
        .as_deref()
        .and_then(|m| m.draft.sync_proxy.as_deref())
        .unwrap_or("");
    Form::sync_proxy(current)
}

fn backup_dir_form(state: &Unlocked) -> Form {
    let current = state
        .settings
        .as_deref()
        .and_then(|m| m.draft.backup_dir.as_deref())
        .unwrap_or("");
    Form::backup_dir(current)
}

fn backup_export_form(state: &Unlocked) -> Form {
    let default_path = state
        .base
        .join("backups")
        .join(format!("zebrapass-{}.zpbackup", unix_ms() / 1000));
    Form::backup_export(&default_path.to_string_lossy())
}

fn cloud_backup_push(state: &Unlocked, ctx: &mut Ctx) {
    match (state.vault.as_deref(), state.https.as_deref()) {
        (Some(vault), Some(https)) => {
            match local::build_backup_bundle(
                &state.base,
                &vault.session,
                &vault.file,
                &vault.meta.name,
            ) {
                Ok(bytes) => {
                    https.push_cloud_backup(bytes);
                    ctx.toast(Tone::Info, "Uploading encrypted backup...");
                }
                Err(err) => ctx.toast(Tone::Warn, err.to_string()),
            }
        }
        (_, None) => ctx.toast(Tone::Info, "Configure and save a sync server first."),
        (None, _) => ctx.toast(Tone::Info, "Vault busy."),
    }
}

fn cloud_backup_pull(state: &Unlocked, ctx: &mut Ctx) {
    if let Some(https) = state.https.as_deref() {
        https.pull_cloud_backup();
        ctx.toast(Tone::Info, "Downloading encrypted backup...");
    } else {
        ctx.toast(Tone::Info, "Configure and save a sync server first.");
    }
}
