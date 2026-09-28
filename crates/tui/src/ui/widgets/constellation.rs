//! The Vault Constellation: the vault key in the middle, one KEK per factor
//! around it, and the keys the vault key derives below. Public metadata only.

use std::time::{Duration, Instant};

use ratatui::layout::{Alignment, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::factors::{factor_label, Anim};
use crate::ui::theme::Theme;
use crate::ui::widgets::meter::filled;
use crate::vault::factors::{FactorKind, FactorView};

/// How long each animation runs.
pub const ANIM_TIME: Duration = Duration::from_millis(1400);

/// Glyph of a factor kind.
#[must_use]
pub const fn glyph(kind: FactorKind, theme: &Theme) -> &'static str {
    match kind {
        FactorKind::Recovery => theme.glyphs.recovery,
        FactorKind::Password => theme.glyphs.password,
        FactorKind::Device => theme.glyphs.device,
        FactorKind::Chip => theme.glyphs.chip,
        FactorKind::HwKey => theme.glyphs.hw_key,
    }
}

/// Phase of a running animation, `0.0..1.0`, or `None` when idle.
#[must_use]
pub fn phase(anim: Option<(Anim, Instant)>, now: Instant, theme: &Theme) -> Option<(Anim, f64)> {
    let (kind, since) = anim?;
    if !theme.anim {
        return None;
    }
    let elapsed = now.saturating_duration_since(since);
    (elapsed < ANIM_TIME).then(|| (kind, elapsed.as_secs_f64() / ANIM_TIME.as_secs_f64()))
}

fn edge_style(
    anim: Option<(Anim, f64)>,
    newest: bool,
    theme: &Theme,
    tick: u64,
) -> (Style, &'static str) {
    let ascii = theme.ascii;
    let plain = if ascii { "-" } else { "─" };
    match anim {
        Some((Anim::Revoke, progress)) if progress < 0.35 => {
            (theme.danger(), if ascii { "x" } else { "╳" })
        }
        Some((Anim::Revoke | Anim::Rotate, _)) if tick % 2 == 0 => {
            (theme.warn(), if ascii { "=" } else { "━" })
        }
        Some((Anim::Add, _)) if newest => (theme.accent(), if ascii { "=" } else { "━" }),
        _ => (theme.muted(), plain),
    }
}

/// Draw the diagram for `factors` into `area`.
pub fn draw(
    frame: &mut Frame<'_>,
    area: Rect,
    factors: &[FactorView],
    generation: u64,
    records: usize,
    anim: Option<(Anim, Instant)>,
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let running = phase(anim, ctx.now, theme);
    let mut lines: Vec<Line<'_>> = Vec::with_capacity(usize::from(area.height));
    let edge_room = usize::from(area.width / 2).saturating_sub(18).clamp(4, 24);
    for (index, factor) in factors.iter().enumerate() {
        let newest = index + 1 == factors.len();
        let (style, stroke) = edge_style(running, newest, theme, ctx.tick);
        let reach = match running {
            Some((Anim::Add, progress)) if newest => filled(progress, edge_room),
            _ => edge_room,
        };
        let mut spans = vec![
            Span::styled(format!("{} ", glyph(factor.kind, theme)), theme.strong()),
            Span::styled(format!("{:<28}", factor_label(factor)), theme.text()),
            Span::styled(format!("{} ", glyphs.kek), theme.accent()),
            Span::styled(stroke.repeat(reach), style),
            Span::styled(if theme.ascii { ">" } else { "▶" }, style),
            Span::styled(format!(" {}", glyphs.vk), theme.accent()),
        ];
        if factor.kind.post_quantum() {
            spans.push(Span::styled("  PQ", theme.pq()));
        }
        lines.push(Line::from(spans));
    }
    let rotating = matches!(running, Some((Anim::Revoke | Anim::Rotate, _)));
    let vk_style = if rotating {
        theme.warn()
    } else {
        theme.accent()
    };
    let rotate_mark = if rotating {
        format!(" {} rotating", glyphs.rotate)
    } else {
        String::new()
    };
    let (top, bottom, side) = if theme.ascii {
        (
            "+------------------------+",
            "+-----------+------------+",
            "|",
        )
    } else {
        (
            "╔════════════════════════╗",
            "╚═══════════╤════════════╝",
            "║",
        )
    };
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(top, vk_style)).alignment(Alignment::Center));
    lines.push(
        Line::from(vec![
            Span::styled(side, vk_style),
            Span::styled(
                format!("   {}  VAULT KEY (VK)    ", glyphs.vk),
                theme.strong(),
            ),
            Span::styled(side, vk_style),
        ])
        .alignment(Alignment::Center),
    );
    lines.push(
        Line::from(vec![
            Span::styled(side, vk_style),
            Span::styled("   256-bit · random     ", theme.muted()),
            Span::styled(side, vk_style),
        ])
        .alignment(Alignment::Center),
    );
    lines.push(Line::from(Span::styled(bottom, vk_style)).alignment(Alignment::Center));
    lines.push(
        Line::from(Span::styled(
            format!("generation {generation}{rotate_mark}"),
            vk_style,
        ))
        .alignment(Alignment::Center),
    );
    lines.push(
        Line::from(Span::styled("HKDF(vault_id)", theme.muted())).alignment(Alignment::Center),
    );
    lines.push(
        Line::from(Span::styled("k_body     k_bmac     k_commit", theme.text()))
            .alignment(Alignment::Center),
    );
    lines.push(
        Line::from(Span::styled(
            format!("{records} records sealed per frame  {}  file commitment (HMAC, checked before decrypt)", glyphs.dot),
            theme.muted(),
        ))
        .alignment(Alignment::Center),
    );
    frame.render_widget(Paragraph::new(lines), area);
}
