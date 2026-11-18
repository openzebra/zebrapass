//! Create wizard, step 5 of 5: cloud & relay sync consent and custom servers.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::ctx::Ctx;
use crate::app::flows::create::{CreateState, SyncFocus};
use crate::app::keymap::Scope;
use crate::ui::layout::{body_and_hints, centered, row};
use crate::ui::screens::create::titled;
use crate::ui::widgets::chrome::{button, checkbox, hint_bar, panel};
use crate::ui::widgets::field::{boxed, text_line};

/// Render step 5 (`Step::Sync`) of the create vault wizard.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &CreateState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let card = centered(body, body.width.min(82), 20);
    let block = panel(titled("Server sync", (5, 5), card.width, ctx), theme);
    let inner = block.inner(card);
    frame.render_widget(block, card);

    let [toggle_area, info_area, label_area, input_area, next_area] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(6),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Min(3),
    ])
    .areas(inner);

    let toggle_focus = state.sync.focus == SyncFocus::Toggle;
    let box_glyph = checkbox(state.sync.enabled);
    let toggle_line = Line::from(vec![
        Span::styled(
            format!("  {box_glyph} Enable Zebra Cloud & P2P Relay sync (recommended)"),
            if toggle_focus {
                theme.accent()
            } else {
                theme.strong()
            },
        ),
        if state.sync.enabled {
            Span::styled("  Space toggles", theme.muted())
        } else {
            Span::styled("  local/LAN P2P only", theme.muted())
        },
    ]);
    frame.render_widget(
        Paragraph::new(vec![Line::from(""), toggle_line]),
        toggle_area,
    );

    let info_lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "   Cluster:   ru.zebra.sh · eu.zebra.sh · zh.zebra.sh (parallel mesh)",
            theme.text(),
        )),
        Line::from(Span::styled(
            "   Privacy:   Zero-knowledge · PQ Cascade + ML-DSA-65 signed commits only",
            theme.muted(),
        )),
        Line::from(Span::styled(
            "   Routing:   LAN P2P -> Direct P2P -> Live Server Relay -> Encrypted Repo",
            theme.muted(),
        )),
        Line::from(Span::styled(
            "   Identity:  512-bit storage key derived one-way from your BIP39 phrase",
            theme.muted(),
        )),
    ];
    frame.render_widget(Paragraph::new(info_lines), info_area);

    frame.render_widget(
        Paragraph::new(Span::styled(
            "  Custom server(s) (optional host:port, comma-separated)",
            if state.sync.focus == SyncFocus::Servers {
                theme.accent()
            } else {
                theme.strong()
            },
        )),
        label_area,
    );

    let input_focus = state.sync.focus == SyncFocus::Servers;
    let input_rect = Rect {
        x: input_area.x.saturating_add(2),
        y: input_area.y,
        width: input_area.width.saturating_sub(4).min(64),
        height: input_area.height,
    };
    boxed(
        frame,
        input_rect,
        text_line(
            &state.sync.servers,
            input_rect.width.saturating_sub(2),
            input_focus,
            theme,
        ),
        input_focus,
        theme,
    );

    if let Some(spot) = row(next_area, 0) {
        let rect = Rect {
            x: spot.right().saturating_sub(18),
            y: spot.y,
            width: 16,
            height: 3.min(next_area.height),
        };
        button(frame, rect, "Create  →", true, true, theme);
    }

    hint_bar(frame, hints, Scope::CreateSync, "Space toggle", ctx);
}
