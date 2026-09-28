//! Shared helpers for the TUI integration tests.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers: not every test uses every helper, and tests may unwrap"
)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use secrecy::{ExposeSecret, SecretString};
use seed::SeedPhrase;
use session::KdfProfile;
use tui::app::ctx::Caps;
use tui::app::screen::Screen;
use tui::cli::{Config, Flags};
use tui::vault::create::{create, Enrollment, NewVault};
use tui::App;
use zeroize::Zeroizing;

/// Password used by test vaults.
pub const PASSWORD: &str = "correct-horse-battery-staple-42";

/// A fresh empty directory under the system temp dir.
pub fn temp_dir(tag: &str) -> PathBuf {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).unwrap();
    let mut name = format!("zp-tui-{tag}-");
    for byte in suffix {
        write!(name, "{byte:02x}").unwrap();
    }
    let dir = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Deterministic config: no animation, no benchmark.
pub fn config(base: &Path) -> Config {
    Config {
        data_dir: Some(base.to_path_buf()),
        flags: Flags::default(),
        ..Config::default()
    }
}

/// Terminal capabilities used by most tests.
pub const CAPS: Caps = Caps {
    osc52: true,
    key_release: false,
};

/// An app over `base`.
pub fn app(base: &Path) -> App {
    app_with(&config(base), base, CAPS)
}

/// An app with explicit config and caps.
pub fn app_with(config: &Config, base: &Path, caps: Caps) -> App {
    let mut app = App::new(config, base.to_path_buf(), caps).unwrap();
    app.on_resize(120, 40);
    app
}

/// A vault created with the Fast profile; returns its normalized phrase.
pub fn make_vault(base: &Path) -> String {
    let phrase = SeedPhrase::generate_24().unwrap();
    let words = phrase.phrase_normalized().to_owned();
    let vault = create(NewVault {
        phrase: Box::new(phrase),
        name: String::from("Personal"),
        base: base.to_path_buf(),
        profile: KdfProfile::Fast,
        factor: Enrollment::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec())),
        records: Vec::new(),
    })
    .unwrap();
    drop(vault);
    words
}

/// Parse a normalized phrase back.
pub fn phrase(words: &str) -> SeedPhrase {
    let phrase = SecretString::new(words.to_owned().into_boxed_str());
    let passphrase = SecretString::new(String::new().into_boxed_str());
    let parsed = SeedPhrase::parse(&phrase, &passphrase).unwrap();
    assert_eq!(parsed.phrase_normalized(), phrase.expose_secret());
    parsed
}

/// A key press.
pub const fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// A key release (kitty protocol terminals).
pub const fn release(code: KeyCode) -> KeyEvent {
    KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Release)
}

/// Ctrl + `ch`.
pub const fn ctrl(ch: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(ch), KeyModifiers::CONTROL)
}

/// Press `code`.
pub fn press(app: &mut App, code: KeyCode) {
    app.on_key(&key(code));
}

/// Type `text` one key at a time.
pub fn type_text(app: &mut App, text: &str) {
    for ch in text.chars() {
        app.on_key(&key(KeyCode::Char(ch)));
    }
}

/// Wait for the next worker result (Argon2 in debug builds is slow).
pub fn wait(app: &mut App) {
    assert!(
        app.wait_for_job(Duration::from_secs(600)),
        "worker result timed out"
    );
}

/// Type the password on the unlock screen and wait for the result.
pub fn unlock(app: &mut App, password: &str) {
    assert_eq!(app.screen.name(), "unlock");
    type_text(app, password);
    press(app, KeyCode::Enter);
    wait(app);
}

/// Advance the app clock by `by` and run timers.
pub fn tick(app: &mut App, by: Duration) {
    let now = app.ctx.now + by;
    app.on_tick(now);
}

/// Run timers at the current instant.
pub fn settle(app: &mut App) {
    app.on_tick(Instant::now().max(app.ctx.now));
}

/// Render into a `width × height` test terminal; returns the text rows.
pub fn render(app: &App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.view(frame)).unwrap();
    let buffer = terminal.backend().buffer();
    let mut out = String::with_capacity(usize::from(width + 1) * usize::from(height) * 3);
    for y in 0..height {
        for x in 0..width {
            out.push_str(buffer[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// Render at the three reference sizes.
pub fn render_all(app: &App) -> [String; 3] {
    [
        render(app, 100, 30),
        render(app, 60, 20),
        render(app, 140, 40),
    ]
}

/// Answer the three verify cards with the right words.
pub fn pass_verify(app: &mut tui::App, wrong_first: bool) {
    for card in 0..3 {
        let (choices, expected) = {
            let Screen::Create(state) = &app.screen else {
                panic!("not create")
            };
            let verify = state.verify.as_ref().unwrap();
            let phrase = state
                .phrase
                .as_ref()
                .unwrap()
                .phrase_normalized()
                .to_owned();
            let word = phrase
                .split(' ')
                .nth(verify.position(card) - 1)
                .unwrap()
                .to_owned();
            (verify.choices(card), word)
        };
        let right = choices
            .iter()
            .position(|choice| *choice == expected)
            .unwrap();
        let pick = if wrong_first && card == 0 {
            (right + 1) % 4
        } else {
            right
        };
        for _ in 0..pick {
            press(app, KeyCode::Down);
        }
        press(app, KeyCode::Enter);
    }
}
