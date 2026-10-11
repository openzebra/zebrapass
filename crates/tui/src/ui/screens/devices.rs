//! Devices and trust.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::unlocked::Unlocked;
use crate::app::keymap::Scope;
use crate::ui::layout::body_and_hints;
use crate::ui::screens::home::header;
use crate::ui::widgets::chrome::{hint_bar, panel, pq_badge, row_style};
use crate::ui::widgets::constellation::glyph;
use crate::ui::widgets::fingerprint::{grouped_hex, stripe_print};
use crate::vault::factors::{views, FactorKind};

/// Draw the device list.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, cursor: usize, ctx: &Ctx) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let [top, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    header(frame, top, state, "devices", ctx);
    let [body, hints] = body_and_hints(rest);
    let block = panel(" Devices ", theme);
    let inner = block.inner(body);
    frame.render_widget(block, body);
    let rule = if theme.ascii { "-" } else { "─" };
    let mut lines = vec![
        Line::from(Span::styled(
            format!(
                "  {:<22}{:<9}{:<30}{:<16}{}",
                "Name", "Kind", "Fingerprint", "Cert", "Last sync"
            ),
            theme.strong(),
        )),
        Line::from(Span::styled(
            rule.repeat(usize::from(inner.width)),
            theme.muted(),
        )),
    ];
    let devices: Vec<_> = views(&state.info.directory, state.info.owned_device())
        .into_iter()
        .filter(|view| matches!(view.kind, FactorKind::Device | FactorKind::HwKey))
        .collect();
    lines.push(Line::from(vec![
        Span::styled(format!("  {:<22}", "this session"), theme.text()),
        Span::styled(format!("{:<9}", "session"), theme.muted()),
        Span::styled(
            format!("{} ", stripe_print(&state.info.origin, glyphs)),
            theme.zebra(),
        ),
        Span::styled(
            format!("{:<13}", grouped_hex(&state.info.origin, 2)),
            theme.muted(),
        ),
        Span::styled(format!("{:<16}", "—"), theme.muted()),
        Span::styled("— (local)", theme.muted()),
    ]));
    for (index, view) in devices.iter().enumerate() {
        let chosen = index == cursor;
        let id = view.id.unwrap_or_default();
        let name = match (view.kind, view.owned) {
            (FactorKind::Device, true) => String::from("this device"),
            (kind, _) => format!("{} {}", kind.noun(), grouped_hex(&id, 1)),
        };
        let mut spans = vec![
            Span::styled(if chosen { glyphs.pointer } else { " " }, theme.accent()),
            Span::styled(format!(" {name:<22}"), row_style(chosen, theme)),
            Span::styled(
                format!("{} {:<5}", glyph(view.kind, theme), short(view.kind)),
                theme.muted(),
            ),
            Span::styled(format!("{} ", stripe_print(&id, glyphs)), theme.zebra()),
            Span::styled(format!("{:<13}", grouped_hex(&id, 2)), theme.muted()),
            Span::styled(format!("{:<16}", "none on file"), theme.warn()),
            Span::styled("—", theme.muted()),
        ];
        if view.kind.post_quantum() {
            spans.push(Span::raw("  "));
            spans.push(pq_badge(theme));
        }
        lines.push(Line::from(spans));
    }
    if devices.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No device, chip, or key wraps yet. This vault opens with its password or phrase.",
            theme.muted(),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  account id  ", theme.text()),
        Span::styled(stripe_print(&state.info.client_id, glyphs), theme.zebra()),
        Span::styled("  (from the phrase)", theme.muted()),
    ]));
    lines.push(Line::from(Span::styled(
        "  Device certificates are kept in sync.id; check-in times are per peer.",
        theme.muted(),
    )));
    frame.render_widget(Paragraph::new(lines), inner);
    hint_bar(frame, hints, Scope::Devices, "", ctx);
}

const fn short(kind: FactorKind) -> &'static str {
    match kind {
        FactorKind::Device => "dev",
        FactorKind::HwKey => "key",
        FactorKind::Password => "pw",
        FactorKind::Recovery => "seed",
    }
}
