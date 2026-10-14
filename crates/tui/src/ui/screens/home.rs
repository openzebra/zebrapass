//! Vault home: 2-panel top deck (telemetry + action bar), then three panes
//! (wide), two panes (medium), or a stack (narrow).

use std::time::Duration;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::home::{Filter, Pane};
use crate::app::flows::unlocked::Unlocked;
use crate::app::idle::clock;
use crate::ui::layout::Breakpoint;
use crate::ui::screens::detail;
use crate::ui::screens::p2p_status::{peers_text, summary};
use crate::ui::widgets::chrome::row_style;
use crate::ui::widgets::field::text_line;
use crate::ui::widgets::list;

/// The unlocked header: vault, optional subview title, countdown, status dot.
pub fn header(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, title: &str, ctx: &Ctx) {
    let theme = &ctx.theme;
    let left = ctx.idle.remaining(ctx.now);
    let countdown_style: Style = match left {
        l if l < Duration::from_secs(10) => theme.danger(),
        l if l < Duration::from_secs(60) => theme.warn(),
        _ => theme.muted(),
    };
    let head = format!(" {} {} ", theme.glyphs.vk, state.info.label);
    let rest = if title.is_empty() {
        format!(
            " CAS-0xA005 · gen {} · {} rec ",
            state.info.generation,
            state.cache.len()
        )
    } else {
        format!(" {title} ")
    };
    let countdown = format!(" {} {} ", theme.glyphs.rotate, clock(left));
    let fill = if theme.ascii { "-" } else { "─" };
    let p2p_sum = summary(state, theme);
    let (sync_text, sync_style) = link_indicator(state, &p2p_sum, ctx);
    let light = p2p_sum.light;
    let used = head.chars().count()
        + 1
        + rest.chars().count()
        + sync_text.chars().count()
        + countdown.chars().count()
        + 3;
    let line = Line::from(vec![
        Span::styled(head, theme.strong()),
        Span::styled(fill, theme.muted()),
        Span::styled(
            rest,
            if title.is_empty() {
                theme.muted()
            } else {
                theme.accent()
            },
        ),
        Span::styled(
            fill.repeat(usize::from(area.width).saturating_sub(used)),
            theme.muted(),
        ),
        Span::styled(sync_text, sync_style),
        Span::styled(countdown, countdown_style),
        Span::styled(fill, theme.muted()),
        Span::styled(format!(" {}", theme.glyphs.on), light.style(theme)),
    ]);
    frame.render_widget(Paragraph::new(line).style(theme.base()), area);
}

fn link_indicator(
    state: &Unlocked,
    p2p_sum: &crate::ui::screens::p2p_status::Summary,
    ctx: &Ctx,
) -> (String, Style) {
    let theme = &ctx.theme;
    let Some(p2p) = state.p2p.as_ref() else {
        return (String::from(" p2p:off "), theme.muted());
    };
    let status = p2p.service.status();
    let glyph = theme.glyphs.sync;
    if status.fetching > 0 {
        (format!(" {glyph} sync "), theme.warn())
    } else if status.peers > 0 {
        (format!(" {glyph} {}p ", status.peers), theme.accent())
    } else {
        (format!(" {} ", peers_text(p2p_sum)), theme.muted())
    }
}

fn draw_action_bar(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, ctx: &Ctx) {
    let theme = &ctx.theme;
    if state.home.searching {
        let line = Line::from(vec![
            Span::styled(" SEARCH ", theme.accent()),
            Span::styled(" [Enter] done  [Esc] clear  [↑↓] move", theme.muted()),
        ]);
        frame.render_widget(Paragraph::new(line).style(theme.base()), area);
        return;
    }
    let sep = if theme.ascii { " | " } else { " │ " };
    let btn = |k: &'static str, label: &'static str| {
        [
            Span::styled(format!(" [{k}]"), theme.accent()),
            Span::styled(format!(" {label} "), theme.text()),
        ]
    };
    let mut spans = Vec::with_capacity(24);
    for pair in [btn("n", "NEW"), btn("E", "EDIT"), btn("d", "DEL")] {
        spans.extend(pair);
    }
    spans.push(Span::styled(sep, theme.muted()));
    for pair in [
        btn("g", "RNG"),
        btn("i", "P2P"),
        btn("S", "SHARE"),
        btn("F", "KEYS"),
        btn("D", "DEV"),
        btn("H", "AUDIT"),
    ] {
        spans.extend(pair);
    }
    spans.push(Span::styled(sep, theme.muted()));
    for pair in [
        btn(",", "settings"),
        btn("L", "LOCK"),
        btn("?", "HELP"),
        btn("q", "QUIT"),
    ] {
        spans.extend(pair);
    }
    frame.render_widget(Paragraph::new(Line::from(spans)).style(theme.base()), area);
}

fn pane_block<'a>(title: Line<'a>, focused: bool, ctx: &Ctx) -> Block<'a> {
    let theme = &ctx.theme;
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if focused {
            theme.accent()
        } else {
            theme.muted()
        })
        .title(title)
}

/// Draw the home view.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, ctx: &Ctx) {
    let [top, actions, body] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
    ])
    .areas(area);
    header(frame, top, state, "", ctx);
    draw_action_bar(frame, actions, state, ctx);
    match Breakpoint::from(area.width) {
        Breakpoint::Wide => {
            let [filters, records, detail_area] = Layout::horizontal([
                Constraint::Length(22),
                Constraint::Percentage(45),
                Constraint::Min(30),
            ])
            .areas(body);
            draw_filters(frame, filters, state, ctx);
            draw_list(frame, records, state, ctx);
            detail::draw_pane(frame, detail_area, state, ctx);
        }
        Breakpoint::Medium => {
            let [records, detail_area] =
                Layout::horizontal([Constraint::Percentage(50), Constraint::Min(30)]).areas(body);
            draw_list(frame, records, state, ctx);
            detail::draw_pane(frame, detail_area, state, ctx);
        }
        Breakpoint::Narrow => {
            if state.home.stacked || state.home.pane == Pane::Detail {
                detail::draw_pane(frame, body, state, ctx);
            } else {
                draw_list(frame, body, state, ctx);
            }
        }
    }
}

fn draw_filters(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, ctx: &Ctx) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let focused = state.home.pane == Pane::Filters;
    let block = pane_block(
        Line::from(Span::styled(" Filters ", theme.strong())),
        focused,
        ctx,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rule = if theme.ascii { "-" } else { "─" };
    let sep_width = usize::from(inner.width).saturating_sub(2);
    let mut lines = Vec::new();
    let mut section = "CAT";
    for (index, (filter, count)) in state.filters().iter().enumerate() {
        let (glyph, heading) = match filter {
            Filter::Favorites => (glyphs.star, "CAT"),
            Filter::All => (glyphs.login, "CAT"),
            Filter::Logins => (glyphs.password, "CAT"),
            Filter::Notes => (glyphs.note, "CAT"),
            Filter::Totp => (glyphs.clock, "CAT"),
            Filter::Weak | Filter::Reused | Filter::Old => (glyphs.attention, "AUDIT"),
            Filter::Tag(_) => ("#", "TAGS"),
            Filter::Shared(..) => (glyphs.sync, "SHARED"),
        };
        if heading != section {
            section = heading;
            let fill = rule.repeat(sep_width.saturating_sub(heading.len() + 2));
            lines.push(Line::from(Span::styled(
                format!(" {heading} {fill}"),
                theme.muted(),
            )));
        }
        let chosen = index == state.home.filter_cursor && focused;
        let active = *filter == state.home.filter;
        let style = if active {
            theme.accent()
        } else {
            row_style(chosen, theme)
        };
        let label = filter.label();
        let label = label.trim_start_matches('#');
        let waiting = matches!(filter, Filter::Shared(id, _)
            if state.shared_item(id).is_some_and(|item| !item.ready()));
        let count_text = if waiting {
            String::from("sync")
        } else {
            format!("{count:>4}")
        };
        let width = usize::from(inner.width).saturating_sub(9);
        lines.push(Line::from(vec![
            Span::styled(format!(" {glyph} "), style),
            Span::styled(
                format!("{:<width$}", list::fit(label, width)),
                row_style(chosen, theme).patch(style),
            ),
            Span::styled(count_text, theme.muted()),
        ]));
    }
    if state.shared.is_empty() {
        let fill = rule.repeat(sep_width.saturating_sub(8));
        lines.push(Line::from(Span::styled(
            format!(" SHARED {fill}"),
            theme.muted(),
        )));
        lines.push(Line::from(Span::styled("   [S] mount/join", theme.muted())));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_list(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, ctx: &Ctx) {
    let theme = &ctx.theme;
    let focused = state.home.pane == Pane::List;
    let title = Line::from(vec![
        Span::styled(" / ", theme.accent()),
        Span::styled("search ", theme.strong()),
        Span::styled(format!("{} ", state.home.filter.label()), theme.muted()),
    ]);
    let block = pane_block(title, focused || state.home.searching, ctx);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [search, rule_row, rows] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
    ])
    .areas(inner);
    let visible = state.visible();
    let counts = format!(
        "{} {} {}",
        state.active_cache().len(),
        if theme.ascii { "->" } else { "→" },
        visible.len()
    );
    let [query, count] = Layout::horizontal([
        Constraint::Min(1),
        Constraint::Length(u16::try_from(counts.len() + 1).unwrap_or(12)),
    ])
    .areas(search);
    if !state.home.searching && state.home.query.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(" / search", theme.muted())),
            query,
        );
    } else {
        frame.render_widget(
            Paragraph::new(text_line(
                &state.home.query,
                query.width,
                state.home.searching,
                theme,
            )),
            query,
        );
    }
    frame.render_widget(Paragraph::new(Span::styled(counts, theme.muted())), count);
    let rule = if theme.ascii { "-" } else { "─" };
    frame.render_widget(
        Paragraph::new(Span::styled(
            rule.repeat(usize::from(rule_row.width)),
            theme.muted(),
        )),
        rule_row,
    );
    if visible.is_empty() {
        let hint = if state.in_shared() && state.active_cache().is_empty() {
            "Nothing here yet."
        } else if state.cache.is_empty() {
            "No records yet. Press n to add one."
        } else {
            "Nothing matches. Esc clears the search."
        };
        frame.render_widget(
            Paragraph::new(Span::styled(format!(" {hint}"), theme.muted())),
            rows,
        );
    } else {
        list::draw(
            frame,
            rows,
            state.active_cache(),
            &visible,
            state.home.selected,
            focused || state.home.searching,
            ctx,
        );
    }
}
