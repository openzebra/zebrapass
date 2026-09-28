//! One module per screen; [`draw`] dispatches on the screen state.

pub mod alert;
pub mod busy;
pub mod ceremony;
pub mod create;
pub mod detail;
pub mod devices;
pub mod dialog;
pub mod editor;
pub mod enroll;
pub mod factors;
pub mod generator;
pub mod health;
pub mod history;
pub mod home;
pub mod locked;
pub mod restore;
pub mod settings;
pub mod sync;
pub mod unlock;
pub mod welcome;

use ratatui::widgets::Block;
use ratatui::Frame;

use crate::app::flows::palette::Overlay;
use crate::app::flows::unlocked::View;
use crate::app::screen::Screen;
use crate::app::App;
use crate::ui::layout::too_small;
use crate::ui::widgets::{chrome, palette, toast};

/// Draw the whole application.
pub fn draw(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    let ctx = &app.ctx;
    frame.render_widget(Block::default().style(ctx.theme.base()), area);
    if too_small(area) {
        chrome::too_small(frame, area, &ctx.theme);
        return;
    }
    match &app.screen {
        Screen::Welcome(state) => welcome::draw(frame, area, state, ctx),
        Screen::Create(state) => create::draw(frame, area, state, ctx),
        Screen::Restore(state) => restore::draw(frame, area, state, ctx),
        Screen::Unlock(state) => unlock::draw(frame, area, state, ctx),
        Screen::Alert(state) => alert::draw(frame, area, state, ctx),
        Screen::Locked(state) => locked::draw(frame, area, state, ctx),
        Screen::Unlocked(state) => {
            match &state.view {
                View::Home => home::draw(frame, area, state, ctx),
                View::Editor(editor) => editor::draw(frame, area, state, editor, ctx),
                View::Factors(factors) => factors::draw(frame, area, state, factors, ctx),
                View::Devices(cursor) => devices::draw(frame, area, state, *cursor, ctx),
                View::Sync => sync::draw(frame, area, state, ctx),
                View::Health(cursor) => health::draw(frame, area, state, *cursor, ctx),
                View::History(history) => history::draw(frame, area, history, ctx),
            }
            if let Some(generator) = state.generator.as_deref() {
                generator::draw(frame, area, generator, ctx);
            }
            if let Some(modal) = state.settings.as_deref() {
                settings::draw(frame, area, state, modal, ctx);
            }
            if let Some(dialog) = state.dialog.as_deref() {
                dialog::draw(frame, area, dialog, ctx);
            }
        }
    }
    if let Some(pending) = ctx.pending {
        busy::draw(frame, area, pending, ctx);
    }
    match &app.overlay {
        Some(Overlay::Palette(state)) => palette::draw_palette(frame, area, state, ctx),
        Some(Overlay::Help(scroll)) => {
            palette::draw_help(frame, area, *scroll, app.screen.scope(), ctx);
        }
        None => {}
    }
    toast::draw(frame, area, ctx);
}
