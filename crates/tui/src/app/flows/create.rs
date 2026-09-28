//! New vault wizard: setup → recovery phrase → verify → enroll.

use crossterm::event::{KeyCode, KeyEvent};
use seed::SeedPhrase;
use session::{BodyAlg, KdfProfile};

use crate::app::action::Action;
use crate::app::ctx::{Ctx, Task};
use crate::app::flows::ceremony::{Ceremony, Verify, VerifyEvent};
use crate::app::flows::editing::edit_text;
use crate::app::flows::enroll::{EnrollEvent, EnrollState};
use crate::app::keymap::{resolve, Scope};
use crate::app::screen::Nav;
use crate::app::worker::Job;
use crate::cli::Flags;
use crate::ui::input::TextInput;
use crate::ui::widgets::toast::Tone;
use crate::vault::create::{Enrollment, NewVault};
use crate::vault::limits::MAX_VAULT_NAME;

/// Argon2id profiles offered, in display order.
pub const PROFILES: [KdfProfile; 2] = [KdfProfile::Desktop, KdfProfile::Mobile];
/// Body ciphers offered, in display order.
pub const CIPHERS: [BodyAlg; 4] = [
    BodyAlg::Aegis256,
    BodyAlg::KuzCtrHmac,
    BodyAlg::KuzMgm,
    BodyAlg::Frames,
];

/// Label, detail, and availability of a body cipher. Exhaustive: a new
/// algorithm is a compile error here.
#[must_use]
pub const fn cipher_info(alg: BodyAlg) -> (&'static str, &'static str, bool) {
    match alg {
        BodyAlg::Aegis256 => ("AEGIS-256", "fast, 256-bit nonce", true),
        BodyAlg::KuzCtrHmac => ("Kuznyechik-CTR + HMAC", "GOST, encrypt-then-MAC", true),
        BodyAlg::KuzMgm => ("Kuznyechik-MGM", "recognized, not implemented", false),
        BodyAlg::Frames => ("Per-record frames", "AEGIS-256 frames, O(1) append", true),
    }
}

/// Label and cost of a profile. Exhaustive.
#[must_use]
pub const fn profile_info(profile: KdfProfile) -> (&'static str, &'static str) {
    match profile {
        KdfProfile::Desktop => ("Desktop", "256 MiB · t=3 · p=4"),
        KdfProfile::Mobile => ("Mobile", " 64 MiB · t=3 · p=2"),
    }
}

/// Wizard step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Name, cost, cipher.
    Setup,
    /// Show the phrase.
    Ceremony,
    /// Prove it was saved.
    Verify,
    /// This device's factor.
    Enroll,
}

/// Focus on the setup step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupField {
    /// Vault name.
    Name,
    /// Argon2id profile.
    Profile,
    /// Body cipher.
    Cipher,
}

/// Wizard state.
#[derive(Debug)]
pub struct CreateState {
    /// Step.
    pub step: Step,
    /// Vault name.
    pub name: TextInput,
    /// Index into [`PROFILES`].
    pub profile: usize,
    /// Index into [`CIPHERS`].
    pub cipher: usize,
    /// Focus on the setup step.
    pub field: SetupField,
    /// The generated phrase (wiped on drop).
    pub phrase: Option<Box<SeedPhrase>>,
    /// Phrase display.
    pub ceremony: Ceremony,
    /// Verify cards.
    pub verify: Option<Box<Verify>>,
    /// Factor step.
    pub enroll: EnrollState,
}

impl CreateState {
    /// Start the wizard; queues the Argon2id timing estimate unless disabled.
    #[must_use]
    pub fn new(ctx: &mut Ctx) -> Self {
        if ctx.flags.has(Flags::BENCH) && ctx.timings == [None, None] {
            for profile in PROFILES {
                ctx.worker.submit(Job::Bench(profile));
            }
        }
        Self {
            step: Step::Setup,
            name: TextInput::with_value("Personal", MAX_VAULT_NAME),
            profile: 0,
            cipher: 0,
            field: SetupField::Name,
            phrase: None,
            ceremony: Ceremony::default(),
            verify: None,
            enroll: EnrollState::new(false),
        }
    }

    /// Keymap scope.
    #[must_use]
    pub const fn scope(&self) -> Scope {
        match self.step {
            Step::Setup => Scope::Setup,
            Step::Ceremony => Scope::Ceremony,
            Step::Verify => Scope::Verify,
            Step::Enroll => Scope::Enroll,
        }
    }

    /// Handle a key.
    pub fn on_key(&mut self, event: &KeyEvent, ctx: &mut Ctx) -> Nav {
        match self.step {
            Step::Setup => {
                if let Some(action) = resolve(Scope::Setup, event) {
                    return self.on_setup(action, ctx);
                }
                if self.field == SetupField::Name {
                    edit_text(&mut self.name, event);
                }
                Nav::Stay
            }
            Step::Ceremony | Step::Verify => {
                resolve(self.scope(), event).map_or(Nav::Stay, |action| self.on_action(action, ctx))
            }
            Step::Enroll => match self.enroll.on_key(event, ctx) {
                EnrollEvent::Stay => Nav::Stay,
                EnrollEvent::Back => {
                    self.step = Step::Ceremony;
                    self.ceremony = Ceremony::default();
                    self.verify = None;
                    Nav::Stay
                }
                EnrollEvent::Done(factor) => self.finish(factor, ctx),
            },
        }
    }

    /// A key was released (key-release terminals only).
    pub fn on_release(&mut self, event: &KeyEvent, ctx: &mut Ctx) {
        if self.step == Step::Ceremony && event.code == KeyCode::Char(' ') {
            self.ceremony.release(ctx);
        }
    }

    /// Paste into the focused field.
    pub fn on_paste(&mut self, text: &str) {
        match self.step {
            Step::Setup if self.field == SetupField::Name => {
                self.name.insert_str(text);
            }
            Step::Enroll => self.enroll.on_paste(text),
            Step::Setup | Step::Ceremony | Step::Verify => {}
        }
    }

    /// Handle an action on the current step.
    pub fn on_action(&mut self, action: Action, ctx: &mut Ctx) -> Nav {
        match self.step {
            Step::Setup => self.on_setup(action, ctx),
            Step::Ceremony => {
                if action == Action::Back {
                    self.phrase = None;
                    self.ceremony = Ceremony::default();
                    self.step = Step::Setup;
                    ctx.redraw();
                    return Nav::Stay;
                }
                if self.ceremony.on_action(action, ctx) {
                    self.start_verify(ctx);
                } else if action == Action::Confirm {
                    ctx.toast(Tone::Info, "Write the phrase down, then tick it with x.");
                }
                Nav::Stay
            }
            Step::Verify => {
                if action == Action::Back {
                    self.verify = None;
                    self.step = Step::Ceremony;
                    return Nav::Stay;
                }
                let (Some(verify), Some(phrase)) = (self.verify.as_mut(), self.phrase.as_ref())
                else {
                    return Nav::Stay;
                };
                match verify.on_action(action, phrase, ctx.now) {
                    VerifyEvent::Stay | VerifyEvent::Failed => {}
                    VerifyEvent::Passed => {
                        self.verify = None;
                        self.step = Step::Enroll;
                    }
                }
                Nav::Stay
            }
            Step::Enroll => Nav::Stay,
        }
    }

    fn on_setup(&mut self, action: Action, ctx: &mut Ctx) -> Nav {
        match action {
            Action::NextField | Action::PrevField => {
                self.field = match (self.field, action == Action::NextField) {
                    (SetupField::Name, true) | (SetupField::Cipher, false) => SetupField::Profile,
                    (SetupField::Profile, true) | (SetupField::Name, false) => SetupField::Cipher,
                    (SetupField::Cipher, true) | (SetupField::Profile, false) => SetupField::Name,
                };
            }
            Action::Up | Action::Down => {
                let down = action == Action::Down;
                match self.field {
                    SetupField::Name => {}
                    SetupField::Profile => self.profile = step(self.profile, down, PROFILES.len()),
                    SetupField::Cipher => self.cipher = step(self.cipher, down, CIPHERS.len()),
                }
            }
            Action::Confirm => self.leave_setup(ctx),
            Action::Back => return Nav::To(crate::app::flows::gate::initial_screen(ctx)),
            _ => {}
        }
        Nav::Stay
    }

    fn leave_setup(&mut self, ctx: &mut Ctx) {
        let alg = CIPHERS
            .get(self.cipher)
            .copied()
            .unwrap_or(BodyAlg::Aegis256);
        let (label, _, available) = cipher_info(alg);
        if self.name.value().trim().is_empty() {
            ctx.toast(Tone::Warn, "Give the vault a name.");
        } else if !available {
            ctx.toast(
                Tone::Warn,
                format!("{label} is not available in this build."),
            );
        } else {
            match SeedPhrase::generate_24() {
                Ok(phrase) => {
                    self.phrase = Some(Box::new(phrase));
                    self.ceremony = Ceremony::default();
                    self.step = Step::Ceremony;
                }
                Err(_) => ctx.toast(Tone::Danger, "The system random source failed."),
            }
        }
    }

    fn start_verify(&mut self, ctx: &mut Ctx) {
        let Some(phrase) = self.phrase.as_ref() else {
            return;
        };
        match Verify::new(phrase) {
            Ok(verify) => {
                self.verify = Some(Box::new(verify));
                self.step = Step::Verify;
            }
            Err(_) => ctx.toast(Tone::Danger, "The system random source failed."),
        }
    }

    fn finish(&mut self, factor: Enrollment, ctx: &mut Ctx) -> Nav {
        let Some(phrase) = self.phrase.take() else {
            return Nav::Stay;
        };
        let request = NewVault {
            phrase,
            name: self.name.value().trim().to_owned(),
            base: ctx.base.clone(),
            profile: PROFILES
                .get(self.profile)
                .copied()
                .unwrap_or(KdfProfile::Desktop),
            alg: CIPHERS
                .get(self.cipher)
                .copied()
                .unwrap_or(BodyAlg::Aegis256),
            factor,
        };
        ctx.start(Job::Create(Box::new(request)), Task::Create);
        Nav::Stay
    }

    /// The job failed; the phrase is gone, so start over from setup.
    pub fn failed(&mut self, message: &str, ctx: &mut Ctx) {
        ctx.toast(
            Tone::Danger,
            format!("Could not create the vault: {message}"),
        );
        self.step = Step::Setup;
        self.enroll = EnrollState::new(false);
    }
}

fn step(current: usize, down: bool, len: usize) -> usize {
    if down {
        (current + 1).min(len.saturating_sub(1))
    } else {
        current.saturating_sub(1)
    }
}
