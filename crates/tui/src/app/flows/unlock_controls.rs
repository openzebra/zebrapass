//! Focus navigation, arrow/vim storage switching, and button activation for
//! the unlock screen.

use crossterm::event::{KeyCode, KeyEvent};

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::editing::{edit_secret, printable};
use crate::app::flows::gate::WelcomeState;
use crate::app::flows::unlock::{Mode, REVEAL_PASSWORD, UnlockFocus, UnlockState};
use crate::app::keymap::{Scope, resolve};
use crate::app::screen::{Nav, Screen};
use crate::ui::widgets::toast::Tone;

impl UnlockState {
    /// Handle a key.
    pub fn on_key(&mut self, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
        if let Some(cursor) = self.picker {
            return self.on_picker(event, cursor, ctx);
        }
        // Printable characters always type into the focused secret field so
        // vim bindings (h/j/k/l/[/]/i/space) never eat password characters.
        if self.focus == UnlockFocus::Input && printable(event).is_some() {
            return self.type_into_input(event);
        }
        if let Some(action) = resolve(Scope::Unlock, event) {
            let editing_cursor = self.focus == UnlockFocus::Input
                && !self.active_input_empty()
                && matches!(action, Action::Left | Action::Right);
            if !editing_cursor {
                return self.on_action(action, ctx);
            }
        }
        if self.focus == UnlockFocus::Input {
            return self.type_into_input(event);
        }
        Nav::Stay
    }

    fn type_into_input(&mut self, event: &KeyEvent) -> Nav {
        let input = match self.mode {
            Mode::Password => &mut self.password,
            Mode::Device => &mut self.pin,
        };
        edit_secret(input, event);
        Nav::Stay
    }

    fn active_input_empty(&self) -> bool {
        match self.mode {
            Mode::Password => self.password.is_empty(),
            Mode::Device => self.pin.is_empty(),
        }
    }

    fn on_picker(&mut self, event: &KeyEvent, cursor: usize, ctx: &mut Ctx) -> Nav {
        let resolved = resolve(Scope::Unlock, event);
        if resolved == Some(Action::Quit) {
            return Nav::Quit;
        }
        let count = self.vaults.len();
        if count == 0 {
            self.picker = None;
            return Nav::Stay;
        }
        if matches!(resolved, Some(Action::PrevVault)) {
            self.picker = Some((cursor + count - 1) % count);
            return Nav::Stay;
        }
        if matches!(resolved, Some(Action::NextVault)) {
            self.picker = Some((cursor + 1) % count);
            return Nav::Stay;
        }
        match event.code {
            KeyCode::Up | KeyCode::Left | KeyCode::BackTab | KeyCode::Char('k' | 'h') => {
                self.picker = Some((cursor + count - 1) % count);
            }
            KeyCode::Down | KeyCode::Right | KeyCode::Tab | KeyCode::Char('j' | 'l') => {
                self.picker = Some((cursor + 1) % count);
            }
            KeyCode::Home | KeyCode::Char('g') => self.picker = Some(0),
            KeyCode::End | KeyCode::Char('G') => self.picker = Some(count - 1),
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.picker = None;
                self.choose(cursor, ctx);
            }
            KeyCode::Esc | KeyCode::Char('q') => self.picker = None,
            _ => {}
        }
        Nav::Stay
    }

    /// Paste into the focused field.
    pub fn on_paste(&mut self, text: &str) {
        if self.focus != UnlockFocus::Input || self.picker.is_some() {
            return;
        }
        match self.mode {
            Mode::Password => self.password.insert_str(text),
            Mode::Device => self.pin.insert_str(text),
        };
    }

    /// Handle an action.
    pub fn on_action(&mut self, action: Action, ctx: &mut Ctx) -> Nav {
        match action {
            Action::Confirm => return self.activate(ctx),
            Action::NextField => self.move_focus(true, ctx),
            Action::PrevField => self.move_focus(false, ctx),
            Action::PrevVault => self.cycle_storage(false, ctx),
            Action::NextVault => self.cycle_storage(true, ctx),
            Action::FocusInput => self.focus = UnlockFocus::Input,
            Action::Left => self.horizontal(false, ctx),
            Action::Right => self.horizontal(true, ctx),
            Action::Up => self.vertical(false),
            Action::Down => self.vertical(true),
            Action::RevealField if self.mode == Mode::Password => {
                if self.reveal.toggle(REVEAL_PASSWORD, ctx.now) {
                    ctx.redraw();
                }
            }
            Action::Back => self.on_back(ctx),
            Action::Quit => return Nav::Quit,
            _ => {}
        }
        Nav::Stay
    }

    fn on_back(&mut self, ctx: &mut Ctx) {
        let had_text = !self.password.is_empty() || !self.pin.is_empty();
        let was_revealed = self.reveal.is_shown(REVEAL_PASSWORD);
        self.password.clear();
        self.pin.clear();
        self.reveal_off(ctx);
        if !had_text && !was_revealed && self.focus == UnlockFocus::Input {
            self.focus = if self.vaults.len() > 1 {
                UnlockFocus::Storage
            } else {
                UnlockFocus::Factor
            };
        }
    }

    fn activate(&mut self, ctx: &mut Ctx) -> Nav {
        match self.focus {
            UnlockFocus::Storage if self.vaults.len() > 1 => self.picker = Some(self.current),
            UnlockFocus::Storage => ctx.toast(Tone::Info, "Only one vault card on this device."),
            UnlockFocus::Factor => self.focus = UnlockFocus::Input,
            UnlockFocus::Input | UnlockFocus::Unlock => self.submit(ctx),
            UnlockFocus::New => {
                return Nav::To(Screen::Welcome(WelcomeState::default()));
            }
        }
        Nav::Stay
    }

    const fn move_focus(&mut self, forward: bool, ctx: &mut Ctx) {
        use UnlockFocus::{Factor, Input, New, Storage, Unlock};
        self.focus = if forward {
            match self.focus {
                Storage => Factor,
                Factor => Input,
                Input => Unlock,
                Unlock => New,
                New => Storage,
            }
        } else {
            match self.focus {
                Storage => New,
                Factor => Storage,
                Input => Factor,
                Unlock => Input,
                New => Unlock,
            }
        };
        self.reveal_off(ctx);
    }

    fn horizontal(&mut self, forward: bool, ctx: &mut Ctx) {
        match self.focus {
            UnlockFocus::Storage | UnlockFocus::Input => self.cycle_storage(forward, ctx),
            UnlockFocus::Factor => self.cycle_mode(forward, ctx),
            UnlockFocus::Unlock | UnlockFocus::New => {
                self.focus = if self.focus == UnlockFocus::Unlock {
                    UnlockFocus::New
                } else {
                    UnlockFocus::Unlock
                };
            }
        }
    }

    const fn vertical(&mut self, down: bool) {
        self.focus = match (self.focus, down) {
            (UnlockFocus::Storage, true) | (UnlockFocus::Input, false) => UnlockFocus::Factor,
            (UnlockFocus::Factor, false) if self.vaults.len() > 1 => UnlockFocus::Storage,
            (UnlockFocus::Factor, true) | (UnlockFocus::Unlock | UnlockFocus::New, false) => {
                UnlockFocus::Input
            }
            (UnlockFocus::Input, true) => UnlockFocus::Unlock,
            _ => self.focus,
        };
    }

    fn cycle_mode(&mut self, forward: bool, ctx: &mut Ctx) {
        let modes = self.modes();
        let Some(at) = modes.iter().position(|mode| *mode == self.mode) else {
            return;
        };
        let next = if forward {
            at + 1
        } else {
            at + modes.len() - 1
        } % modes.len();
        if let Some(mode) = modes.get(next) {
            self.mode = *mode;
        }
        self.reveal_off(ctx);
    }

    fn cycle_storage(&mut self, forward: bool, ctx: &mut Ctx) {
        if self.vaults.len() < 2 {
            return;
        }
        let next = if forward {
            self.current + 1
        } else {
            self.current + self.vaults.len() - 1
        } % self.vaults.len();
        self.choose(next, ctx);
    }

    fn choose(&mut self, index: usize, ctx: &mut Ctx) {
        self.reveal_off(ctx);
        self.select(index);
    }
}
