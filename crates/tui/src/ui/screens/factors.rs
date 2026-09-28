//! Constellation: how the vault is locked, and factor management.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::factors::{factor_label, FactorsState};
use crate::app::flows::unlocked::Unlocked;
use crate::app::keymap::Scope;
use crate::ui::layout::body_and_hints;
use crate::ui::screens::home::header;
use crate::ui::widgets::chrome::{hint_bar, panel, row_style};
use crate::ui::widgets::constellation::{self, glyph};
use crate::vault::factors::{views, FactorKind};

/// Draw the constellation.
pub fn draw(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &Unlocked,
    factors: &FactorsState,
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    let [top, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    header(frame, top, state, "factors", ctx);
    let [body, hints] = body_and_hints(rest);
    let block = panel(" Constellation · how your vault is locked ", theme);
    let inner = block.inner(body);
    frame.render_widget(block, body);
    let list = views(&state.info.directory, state.info.owned_device());
    let list_height = u16::try_from(list.len() + 2).unwrap_or(8);
    let [diagram, _, rows] = Layout::vertical([
        Constraint::Min(8),
        Constraint::Length(1),
        Constraint::Length(list_height),
    ])
    .areas(inner);
    constellation::draw(
        frame,
        diagram,
        &list,
        state.info.generation,
        state.cache.len(),
        factors.anim,
        ctx,
    );
    let mut lines: Vec<Line<'_>> = list
        .iter()
        .enumerate()
        .map(|(index, view)| {
            let chosen = index == factors.selected;
            let pointer = if chosen { theme.glyphs.pointer } else { " " };
            let actions = match view.kind {
                FactorKind::Password => "Enter change password",
                FactorKind::Recovery => "Enter drop from this copy (advanced)",
                FactorKind::Device | FactorKind::HwKey => "Enter details · r revoke · ⌫ remove",
            };
            let cost = view
                .cost
                .map(|(m_kib, t, p)| format!("  {} MiB t={t} p={p}", m_kib / 1024))
                .unwrap_or_default();
            Line::from(vec![
                Span::styled(
                    format!("{pointer} {} ", glyph(view.kind, theme)),
                    theme.accent(),
                ),
                Span::styled(
                    format!("{:<34}", format!("{}{cost}", factor_label(view))),
                    row_style(chosen, theme),
                ),
                Span::styled(actions, theme.muted()),
            ])
        })
        .collect();
    let add_chosen = factors.selected >= list.len();
    lines.push(Line::from(vec![
        Span::styled(
            format!(
                "{} + ",
                if add_chosen {
                    theme.glyphs.pointer
                } else {
                    " "
                }
            ),
            theme.accent(),
        ),
        Span::styled("add factor", row_style(add_chosen, theme)),
    ]));
    frame.render_widget(Paragraph::new(lines), rows);
    let right = if theme.anim {
        "edges pulse on change "
    } else {
        ""
    };
    hint_bar(frame, hints, Scope::Factors, right, ctx);
}
