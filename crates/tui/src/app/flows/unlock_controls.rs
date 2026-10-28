//! Focus navigation and button activation for the unlock screen.

use crossterm::event::{KeyCode, KeyEvent};

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::editing::edit_secret;
use crate::app::flows::gate::WelcomeState;
use crate::app::flows::unlock::{Mode, UnlockFocus, UnlockState, REVEAL_PASSWORD};
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::{Nav, Screen};
use crate::ui::widgets::toast::Tone;

impl UnlockState {
    /// Handle a key.
    pub fn on_key(&mut self, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
        if let Some(cursor) = self.picker {
            return self.on_picker(event, cursor, ctx);
        }
        if let Some(action) = resolve(Scope::Unlock, event) {
            let editing_cursor =
                self.focus == UnlockFocus::Input && matches!(action, Action::Left | Action::Right);
            if !editing_cursor {
                return self.on_action(action, ctx);
            }
        }
        if self.focus != UnlockFocus::Input {
            return Nav::Stay;
        }
        let input = match self.mode {
            Mode::Password => &mut self.password,
            Mode::Device => &mut self.pin,
        };
        edit_secret(input, event);
        Nav::Stay
    }

    fn on_picker(&mut self, event: &KeyEvent, cursor: usize, ctx: &mut Ctx) -> Nav {
        if resolve(Scope::Unlock, event) == Some(Action::Quit) {
            return Nav::Quit;
        }
        match event.code {
            KeyCode::Up | KeyCode::Left | KeyCode::BackTab => {
                self.picker = Some(cursor.saturating_sub(1));
            }
            KeyCode::Down | KeyCode::Right | KeyCode::Tab => {
                self.picker = Some((cursor + 1).min(self.vaults.len().saturating_sub(1)));
            }
            KeyCode::Enter => {
                self.picker = None;
                self.choose(cursor, ctx);
            }
            KeyCode::Esc => self.picker = None,
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
            Action::Left => self.horizontal(false, ctx),
            Action::Right => self.horizontal(true, ctx),
            Action::Up => self.vertical(false),
            Action::Down => self.vertical(true),
            Action::RevealField if self.mode == Mode::Password => {
                if self.reveal.toggle(REVEAL_PASSWORD, ctx.now) {
                    ctx.redraw();
                }
            }
            Action::Back => {
                self.password.clear();
                self.pin.clear();
                self.reveal_off(ctx);
            }
            Action::Quit => return Nav::Quit,
            _ => {}
        }
        Nav::Stay
    }

    fn activate(&mut self, ctx: &mut Ctx) -> Nav {
        match self.focus {
            UnlockFocus::Storage if self.vaults.len() > 1 => self.picker = Some(self.current),
            UnlockFocus::Storage => ctx.toast(Tone::Info, "Only one storage on this device."),
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
            UnlockFocus::Storage => self.cycle_storage(forward, ctx),
            UnlockFocus::Factor => self.cycle_mode(forward, ctx),
            UnlockFocus::Unlock | UnlockFocus::New => {
                self.focus = if self.focus == UnlockFocus::Unlock {
                    UnlockFocus::New
                } else {
                    UnlockFocus::Unlock
                };
            }
            UnlockFocus::Input => {}
        }
    }

    const fn vertical(&mut self, down: bool) {
        self.focus = match (self.focus, down) {
            (UnlockFocus::Storage, true) | (UnlockFocus::Factor | UnlockFocus::Input, false) => {
                UnlockFocus::Factor
            }
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
