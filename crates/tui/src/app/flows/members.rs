//! Interactive participant management modal for the active shared vault.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use memberlog::Role;
use sharing::{Fingerprint, account_fingerprint};

use crate::app::ctx::Ctx;
use crate::app::flows::dialog::Dialog;
use crate::app::flows::share::{ReturnTo, ShareState, Step};
use crate::app::flows::share_nav::ShareFocus;
use crate::app::flows::share_remove::Person;
use crate::app::flows::unlocked::{Unlocked, View};
use crate::app::screen::Nav;
use crate::ui::widgets::toast::Tone;
use crate::vault::shared::Status;

/// One participant row shown in the Members modal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberRow {
    /// Member account identifier.
    pub client_id: [u8; 64],
    /// Verified account fingerprint.
    pub print: Fingerprint,
    /// Current role in the shared vault's member log.
    pub role: Role,
    /// Whether this row belongs to the unlocked local account.
    pub is_self: bool,
}

/// Interactive action buttons at the bottom of the Members modal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembersButton {
    /// Add a new participant (Owner only).
    Add,
    /// Change the highlighted participant's role (Owner only).
    ChangeRole,
    /// Remove the highlighted participant and rekey (Owner only).
    Remove,
    /// Jump to the Share & Sync screen for this vault.
    OpenShare,
    /// Close the modal.
    Close,
}

/// Active focus target inside [`MembersModal`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MembersFocus {
    /// Participant rows list.
    #[default]
    List,
    /// One of the action buttons.
    Button(MembersButton),
}

/// State for the Home screen Shared Vault Members modal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembersModal {
    /// Highlighted participant row index.
    pub cursor: usize,
    /// Shared vault identifier being inspected.
    pub vault_id: [u8; 16],
    /// Whether the list or an action button has focus.
    pub focus: MembersFocus,
}

const OWNER_BUTTONS: [MembersButton; 4] = [
    MembersButton::Add,
    MembersButton::ChangeRole,
    MembersButton::Remove,
    MembersButton::Close,
];

const MEMBER_BUTTONS: [MembersButton; 2] = [MembersButton::OpenShare, MembersButton::Close];

/// Buttons visible for the current user's role.
#[must_use]
pub const fn visible_buttons(is_owner: bool) -> &'static [MembersButton] {
    if is_owner {
        &OWNER_BUTTONS
    } else {
        &MEMBER_BUTTONS
    }
}

impl Unlocked {
    /// Every current member of `vault_id`, with this account listed first.
    #[must_use]
    pub fn vault_members(&self, vault_id: &[u8; 16]) -> Vec<MemberRow> {
        let mine = self
            .identity
            .as_deref()
            .and_then(|identity| identity.devices().first())
            .map(|cert| cert.client_id);
        let Some(open) = self
            .shared_item(vault_id)
            .and_then(|item| match &item.status {
                Status::Ready(vault) => Some(vault),
                Status::Pending | Status::Unavailable => None,
            })
        else {
            return Vec::new();
        };
        let members = open.log.members();
        let mut rows = Vec::with_capacity(members.len());
        for self_pass in [true, false] {
            for member in members {
                let is_self = Some(member.client_id) == mine;
                if is_self == self_pass {
                    rows.push(MemberRow {
                        client_id: member.client_id,
                        print: account_fingerprint(&member.client_id, &member.root_vk),
                        role: member.role,
                        is_self,
                    });
                }
            }
        }
        rows
    }

    /// Open the interactive Members modal for shared vault `vault_id`.
    pub fn open_members_modal(&mut self, vault_id: [u8; 16]) {
        let rows = self.vault_members(&vault_id);
        let cursor = rows.iter().position(|row| !row.is_self).unwrap_or(0);
        self.dialog = Some(Box::new(Dialog::Members(MembersModal {
            cursor,
            vault_id,
            focus: MembersFocus::List,
        })));
    }

    /// Launch the add-participant paste/confirm flow targeting `vault_id`.
    pub fn start_shared_add(&mut self, vault_id: [u8; 16], return_to: ReturnTo, ctx: &mut Ctx) {
        let Some(index) = self
            .shared
            .iter()
            .position(|item| item.reference.vault_id == vault_id)
        else {
            ctx.toast(Tone::Info, "No shared vault is selected.");
            return;
        };
        if let Err(message) = self.prepare_add(index, ctx) {
            ctx.toast(Tone::Info, message);
            return;
        }
        self.enter_shared_step(index, Step::PasteCard, return_to);
    }

    /// Launch the role-change confirm flow for `person` in `vault_id`.
    pub fn start_shared_role(
        &mut self,
        vault_id: [u8; 16],
        person: Person,
        return_to: ReturnTo,
        ctx: &mut Ctx,
    ) {
        let Some(index) = self.owner_ready_index(vault_id, "Only owners can change roles.", ctx)
        else {
            return;
        };
        let step = Step::RoleConfirm {
            target: person.client_id,
            print: person.print,
            from: person.role,
            to: person.role,
        };
        self.enter_shared_step(index, step, return_to);
    }

    /// Launch the remove-participant confirm flow for `person` in `vault_id`.
    pub fn start_shared_remove(
        &mut self,
        vault_id: [u8; 16],
        person: Person,
        return_to: ReturnTo,
        ctx: &mut Ctx,
    ) {
        let Some(index) = self.owner_ready_index(vault_id, "Only owners can remove people.", ctx)
        else {
            return;
        };
        let step = Step::RemoveConfirm {
            target: person.client_id,
            print: person.print,
            role: person.role,
        };
        self.enter_shared_step(index, step, return_to);
    }

    fn owner_ready_index(
        &self,
        vault_id: [u8; 16],
        denied_msg: &'static str,
        ctx: &mut Ctx,
    ) -> Option<usize> {
        let index = self
            .shared
            .iter()
            .position(|item| item.reference.vault_id == vault_id);
        let picked = index.and_then(|idx| {
            self.shared
                .get(idx)
                .map(|item| (idx, item.ready(), item.my_role))
        });
        match picked {
            None => {
                ctx.toast(Tone::Info, "No shared vault is selected.");
                None
            }
            Some((_, false, _)) => {
                ctx.toast(Tone::Info, "That vault is still syncing.");
                None
            }
            Some((_, true, role)) if role != Some(Role::Owner) => {
                ctx.toast(Tone::Info, denied_msg);
                None
            }
            Some((idx, true, _)) => Some(idx),
        }
    }

    fn enter_shared_step(&mut self, cursor: usize, step: Step, return_to: ReturnTo) {
        self.dialog = None;
        let me = self.make_me();
        self.view = View::Sync(Box::new(ShareState {
            step,
            cursor,
            me,
            focus: ShareFocus::default(),
            return_to,
        }));
    }
}

fn cycle_focus(focus: MembersFocus, buttons: &[MembersButton], forward: bool) -> MembersFocus {
    let total = 1 + buttons.len();
    let current = match focus {
        MembersFocus::List => 0,
        MembersFocus::Button(btn) => buttons
            .iter()
            .position(|known| *known == btn)
            .map_or(0, |idx| idx + 1),
    };
    let next = if forward {
        (current + 1) % total
    } else {
        (current + total - 1) % total
    };
    if next == 0 {
        MembersFocus::List
    } else {
        buttons
            .get(next - 1)
            .copied()
            .map_or(MembersFocus::List, MembersFocus::Button)
    }
}

fn step_button(focus: MembersFocus, buttons: &[MembersButton], forward: bool) -> MembersFocus {
    let len = buttons.len();
    if len == 0 {
        return MembersFocus::List;
    }
    match focus {
        MembersFocus::List => {
            let pick = if forward {
                buttons.first()
            } else {
                buttons.last()
            };
            pick.copied()
                .map_or(MembersFocus::List, MembersFocus::Button)
        }
        MembersFocus::Button(btn) => {
            let pos = buttons.iter().position(|known| *known == btn).unwrap_or(0);
            let next = if forward {
                (pos + 1) % len
            } else {
                (pos + len - 1) % len
            };
            buttons
                .get(next)
                .copied()
                .map_or(MembersFocus::List, MembersFocus::Button)
        }
    }
}

fn trigger_add(state: &mut Unlocked, vault_id: [u8; 16], is_owner: bool, ctx: &mut Ctx) {
    if !is_owner {
        ctx.toast(Tone::Info, "Only owners can add people.");
        return;
    }
    state.start_shared_add(vault_id, ReturnTo::HomeMembers(vault_id), ctx);
}

fn trigger_role(
    state: &mut Unlocked,
    vault_id: [u8; 16],
    selected: Option<&MemberRow>,
    is_owner: bool,
    ctx: &mut Ctx,
) {
    if !is_owner {
        ctx.toast(Tone::Info, "Only owners can change roles.");
        return;
    }
    let Some(row) = selected.filter(|row| !row.is_self) else {
        ctx.toast(
            Tone::Info,
            "Select another participant to change their role.",
        );
        return;
    };
    let person = Person {
        client_id: row.client_id,
        print: row.print,
        role: row.role,
    };
    state.start_shared_role(vault_id, person, ReturnTo::HomeMembers(vault_id), ctx);
}

fn trigger_remove(
    state: &mut Unlocked,
    vault_id: [u8; 16],
    selected: Option<&MemberRow>,
    is_owner: bool,
    ctx: &mut Ctx,
) {
    if !is_owner {
        ctx.toast(Tone::Info, "Only owners can remove people.");
        return;
    }
    let Some(row) = selected.filter(|row| !row.is_self) else {
        ctx.toast(
            Tone::Info,
            "Select another participant to remove, or open Share to leave.",
        );
        return;
    };
    let person = Person {
        client_id: row.client_id,
        print: row.print,
        role: row.role,
    };
    state.start_shared_remove(vault_id, person, ReturnTo::HomeMembers(vault_id), ctx);
}

/// Handle a key event while the Members modal is open.
pub fn on_key(state: &mut Unlocked, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
    let Some(Dialog::Members(modal)) = state.dialog.as_deref() else {
        return Nav::Stay;
    };
    let mut modal = *modal;
    let rows = state.vault_members(&modal.vault_id);
    modal.cursor = modal.cursor.min(rows.len().saturating_sub(1));
    let is_owner = state
        .shared_item(&modal.vault_id)
        .is_some_and(|item| item.ready() && item.my_role == Some(Role::Owner));
    let buttons = visible_buttons(is_owner);
    let plain = !event
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);

    match event.code {
        KeyCode::Esc | KeyCode::Char('q') if plain => {
            state.dialog = None;
            return Nav::Stay;
        }
        KeyCode::Up | KeyCode::Char('k') if plain => match modal.focus {
            MembersFocus::List => modal.cursor = modal.cursor.saturating_sub(1),
            MembersFocus::Button(_) => modal.focus = MembersFocus::List,
        },
        KeyCode::Down | KeyCode::Char('j') if plain => {
            if modal.focus == MembersFocus::List && modal.cursor + 1 < rows.len() {
                modal.cursor += 1;
            } else if let Some(&first) = buttons.first() {
                modal.focus = MembersFocus::Button(first);
            }
        }
        KeyCode::Tab => modal.focus = cycle_focus(modal.focus, buttons, true),
        KeyCode::BackTab => modal.focus = cycle_focus(modal.focus, buttons, false),
        KeyCode::Right => modal.focus = step_button(modal.focus, buttons, true),
        KeyCode::Left => modal.focus = step_button(modal.focus, buttons, false),
        KeyCode::Char('a') if plain => {
            trigger_add(state, modal.vault_id, is_owner, ctx);
            return Nav::Stay;
        }
        KeyCode::Char('c') if plain => {
            trigger_role(state, modal.vault_id, rows.get(modal.cursor), is_owner, ctx);
            return Nav::Stay;
        }
        KeyCode::Char('x') | KeyCode::Delete | KeyCode::Backspace if plain => {
            trigger_remove(state, modal.vault_id, rows.get(modal.cursor), is_owner, ctx);
            return Nav::Stay;
        }
        KeyCode::Char('S') if plain => {
            state.dialog = None;
            state.open_share();
            return Nav::Stay;
        }
        KeyCode::Enter | KeyCode::Char(' ') => match modal.focus {
            MembersFocus::List => {
                let target = if !is_owner {
                    MembersButton::Close
                } else if rows.get(modal.cursor).is_some_and(|row| !row.is_self) {
                    MembersButton::ChangeRole
                } else {
                    MembersButton::Add
                };
                modal.focus = MembersFocus::Button(target);
            }
            MembersFocus::Button(btn) => match btn {
                MembersButton::Add => {
                    trigger_add(state, modal.vault_id, is_owner, ctx);
                    return Nav::Stay;
                }
                MembersButton::ChangeRole => {
                    trigger_role(state, modal.vault_id, rows.get(modal.cursor), is_owner, ctx);
                    return Nav::Stay;
                }
                MembersButton::Remove => {
                    trigger_remove(state, modal.vault_id, rows.get(modal.cursor), is_owner, ctx);
                    return Nav::Stay;
                }
                MembersButton::OpenShare => {
                    state.dialog = None;
                    state.open_share();
                    return Nav::Stay;
                }
                MembersButton::Close => {
                    state.dialog = None;
                    return Nav::Stay;
                }
            },
        },
        _ => {}
    }

    if let Some(Dialog::Members(slot)) = state.dialog.as_deref_mut() {
        *slot = modal;
    }
    Nav::Stay
}
