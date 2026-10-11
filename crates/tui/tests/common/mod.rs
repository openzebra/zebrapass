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

/// Make the node of the vault under `base` listen on this device only, which
/// is the mode where loopback peers are dialed: tests run every device on one
/// machine.
pub fn keep_to_this_device(base: &Path) {
    keep_to_this_device_with(base, PASSWORD);
}

/// As [`keep_to_this_device`], for a vault that opens with `password`.
pub fn keep_to_this_device_with(base: &Path, password: &str) {
    listen_with(base, password, local::Listen::Local);
}

/// Make the vault under `base`, opening with `password`, only dial out: no
/// listener, so on one machine it cannot dial itself.
pub fn fetch_only_with(base: &Path, password: &str) {
    listen_with(base, password, local::Listen::Fetch);
}

fn listen_with(base: &Path, password: &str, listen: local::Listen) {
    use tui::vault::discover::discover;
    use tui::vault::open::{unlock_vault, Credential};
    use tui::vault::ops::{apply, Op};
    let paths = discover(base).first().unwrap().paths.clone();
    let password = Credential::Password(Zeroizing::new(password.as_bytes().to_vec()));
    let mut vault = unlock_vault(paths, password).unwrap();
    let prefs = local::Prefs {
        p2p_listen: listen,
        ..local::Prefs::default()
    };
    apply(&mut vault, Op::SavePrefs(Box::new(prefs))).unwrap();
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
///
/// The node's check-in timer runs on the real clock, so each tick also
/// expires it: a test waiting for sync does not wait out the interval.
pub fn tick(app: &mut App, by: Duration) {
    if let Screen::Unlocked(state) = &mut app.screen {
        if let Some(node) = state.p2p.as_deref_mut() {
            node.expire_check_timer();
        }
    }
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

/// A UDP port nobody holds right now.
pub fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Beacons sent to `send_to_port` and heard on `bind_port`, every 150 ms,
/// carried over loopback unicast instead of multicast.
pub fn beacon(bind_port: u16, send_to_port: u16) -> p2p_net::BeaconConfig {
    p2p_net::BeaconConfig {
        send_to: std::net::SocketAddr::from(([127, 0, 0, 1], send_to_port)),
        bind: std::net::SocketAddr::from(([127, 0, 0, 1], bind_port)),
        join: None,
        every: Duration::from_millis(150),
        loopback: true,
    }
}

/// Save the beacon listening mode in the vault under `base`.
pub fn announce_on_the_network(base: &Path) {
    use tui::vault::discover::discover;
    use tui::vault::open::{unlock_vault, Credential};
    use tui::vault::ops::{apply, Op};
    let paths = discover(base).first().unwrap().paths.clone();
    let password = Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec()));
    let mut vault = unlock_vault(paths, password).unwrap();
    let prefs = local::Prefs {
        p2p_listen: local::Listen::Beacon,
        ..local::Prefs::default()
    };
    apply(&mut vault, Op::SavePrefs(Box::new(prefs))).unwrap();
}

/// A device that is unlocked and announces itself over `cfg`: returns its
/// app and its phrase.
pub fn announcing_device(
    tag: &str,
    cfg: p2p_net::BeaconConfig,
    titles: &[&str],
) -> (App, String, PathBuf) {
    let base = temp_dir(tag);
    let words = make_vault(&base);
    add_records(&base, titles);
    announce_on_the_network(&base);
    let mut config = config(&base);
    config.beacon = Some(cfg);
    let mut first = app_with(&config, &base, CAPS);
    unlock(&mut first, PASSWORD);
    (first, words, base)
}

/// Welcome → restore chooser → the phrase restore.
pub fn open_restore(app: &mut App) {
    press(app, KeyCode::Right);
    press(app, KeyCode::Enter);
    press(app, KeyCode::Enter);
    assert_eq!(app.screen.name(), "restore");
}

/// Type a space-separated phrase into the restore or unlock words grid.
pub fn type_phrase(app: &mut App, words: &str) {
    for word in words.split(' ') {
        type_text(app, word);
        press(app, KeyCode::Char(' '));
    }
}

/// Restore `words` on a new device with no vault file, enrolling `password`.
/// The device is left unlocked on its placeholder vault.
pub fn restore_empty(base: &Path, words: &str, password: &str, cfg: p2p_net::BeaconConfig) -> App {
    let mut config = config(base);
    config.beacon = Some(cfg);
    let mut second = app_with(&config, base, CAPS);
    open_restore(&mut second);
    type_phrase(&mut second, words);
    press(&mut second, KeyCode::Enter);
    type_text(&mut second, password);
    press(&mut second, KeyCode::Tab);
    type_text(&mut second, password);
    press(&mut second, KeyCode::Enter);
    wait(&mut second);
    assert_eq!(second.screen.name(), "unlocked");
    second
}

/// Whether the unlocked vault is still an empty stand-in.
pub fn is_placeholder(app: &App) -> bool {
    let Screen::Unlocked(state) = &app.screen else {
        return false;
    };
    state
        .vault
        .as_ref()
        .is_some_and(|vault| tui::vault::adopt::is_placeholder(&vault.paths))
}

/// Run timers until the placeholder has been replaced by the account's
/// vault, or panic after `within`.
pub fn wait_adopted(app: &mut App, within: Duration) {
    let until = Instant::now() + within;
    while Instant::now() < until {
        tick(app, Duration::from_millis(50));
        if app.screen.name() == "unlocked" && !is_placeholder(app) {
            return;
        }
        app.wait_for_job(Duration::from_millis(50));
    }
    panic!("the vault never arrived");
}

/// Put records titled `titles` into the vault under `base` while no app has
/// it open.
pub fn add_records(base: &Path, titles: &[&str]) {
    use tui::vault::discover::discover;
    use tui::vault::open::{unlock_vault, Credential};
    let paths = discover(base).first().unwrap().paths.clone();
    let mut vault = unlock_vault(
        paths,
        Credential::Password(Zeroizing::new(PASSWORD.as_bytes().to_vec())),
    )
    .unwrap();
    for title in titles {
        let mut doc = record::Document::new();
        doc.set_text(record::TAG_TITLE, title);
        session::write_record(&mut vault.session, &mut vault.file, None, &doc).unwrap();
    }
    vault.persist().unwrap();
}

/// Titles of the records in the unlocked vault, sorted.
pub fn titles_of(app: &App) -> Vec<String> {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked: {}", app.screen.name())
    };
    let mut titles: Vec<String> = state
        .cache
        .iter()
        .map(|row| row.title.to_string())
        .collect();
    titles.sort();
    titles
}
