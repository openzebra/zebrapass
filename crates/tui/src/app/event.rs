//! The terminal run loop: the only place that does terminal IO.
//!
//! The alternate screen is always used, so nothing reaches scrollback. A
//! guard restores the terminal on every exit path, and the panic hook only
//! restores the terminal: it never formats application state.

use std::io::{self, Write};
use std::time::{Duration, Instant};

use crossterm::event::{
    self, DisableBracketedPaste, DisableFocusChange, EnableBracketedPaste, EnableFocusChange,
    Event, KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use zeroize::Zeroize;

use crate::app::ctx::Caps;
use crate::app::App;
use crate::cli::Config;
use crate::secure::clipboard::osc52_likely;
use crate::vault::discover::data_dir;

/// One animation tick.
pub const TICK: Duration = Duration::from_millis(60);

/// Restores the terminal when dropped.
struct TerminalGuard {
    enhanced: bool,
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore(self.enhanced);
    }
}

fn restore(enhanced: bool) {
    let mut out = io::stdout();
    if enhanced {
        let _ = execute!(out, PopKeyboardEnhancementFlags);
    }
    let _ = execute!(
        out,
        DisableFocusChange,
        DisableBracketedPaste,
        LeaveAlternateScreen,
        crossterm::cursor::Show
    );
    let _ = terminal::disable_raw_mode();
}

/// Run the interface until the user quits.
///
/// # Errors
///
/// Terminal IO errors, a missing data directory, or a worker that cannot start.
pub fn run(config: &Config) -> anyhow::Result<()> {
    let base = data_dir(config.data_dir.as_deref())?;
    let caps = Caps {
        osc52: osc52_likely(
            std::env::var("TERM").ok().as_deref(),
            std::env::var("TERM_PROGRAM").ok().as_deref(),
        ),
        key_release: terminal::supports_keyboard_enhancement().unwrap_or(false),
    };
    let mut app = App::new(config, base, caps)?;

    terminal::enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(
        out,
        EnterAlternateScreen,
        EnableBracketedPaste,
        EnableFocusChange
    )?;
    if caps.key_release {
        execute!(
            out,
            PushKeyboardEnhancementFlags(
                KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
                    | KeyboardEnhancementFlags::REPORT_EVENT_TYPES
            )
        )?;
    }
    let guard = TerminalGuard {
        enhanced: caps.key_release,
    };
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |_| {
        restore(caps.key_release);
        let _ = writeln!(
            io::stderr(),
            "zebrapass: internal error; the terminal was restored."
        );
    }));

    let result = event_loop(&mut app);
    let _ = std::panic::take_hook();
    std::panic::set_hook(previous);
    // Quit already locked; write the final clipboard clear before leaving.
    flush_outbox(&mut app);
    drop(app);
    drop(guard);
    result
}

fn event_loop(app: &mut App) -> anyhow::Result<()> {
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let size = terminal.size()?;
    app.on_resize(size.width, size.height);
    terminal.clear()?;
    loop {
        if app.take_full_redraw() {
            terminal.clear()?;
        }
        terminal.draw(|frame| app.view(frame))?;
        flush_outbox(app);
        if app.should_quit() {
            return Ok(());
        }
        if event::poll(TICK)? {
            match event::read()? {
                Event::Key(key) => app.on_key(&key),
                Event::Paste(mut text) => {
                    app.on_paste(&text);
                    text.zeroize();
                }
                Event::Resize(columns, rows) => {
                    app.on_resize(columns, rows);
                    terminal.autoresize()?;
                }
                Event::FocusLost => app.on_focus_lost(),
                Event::FocusGained | Event::Mouse(_) => {}
            }
        }
        app.on_tick(Instant::now());
    }
}

fn flush_outbox(app: &mut App) {
    let pending = app.take_outbox();
    if pending.is_empty() {
        return;
    }
    let mut out = io::stdout();
    for sequence in &pending {
        let _ = out.write_all(sequence);
    }
    let _ = out.flush();
}
