//! Vault home: header with the auto-lock countdown, then three panes (wide),
//! two panes (medium), or a stack (narrow).

use std::time::Duration;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::home::{filter_entries, Filter, Pane};
use crate::app::flows::unlocked::Unlocked;
use crate::app::idle::clock;
use crate::ui::layout::{body_and_hints, Breakpoint};
use crate::ui::screens::detail;
use crate::ui::widgets::chrome::{hint_bar, pq_badge, row_style};
use crate::ui::widgets::field::text_line;
use crate::ui::widgets::list;

/// The unlocked header: vault, state, countdown, PQ badge.
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
        String::from(" unlocked ")
    } else {
        format!(" {title} ")
    };
    let countdown = format!(" {} {} ", theme.glyphs.rotate, clock(left));
    let fill = if theme.ascii { "-" } else { "─" };
    let used = head.chars().count() + rest.chars().count() + countdown.chars().count() + 6;
    let line = Line::from(vec![
        Span::styled(head, theme.strong()),
        Span::styled(fill, theme.muted()),
        Span::styled(rest, theme.accent()),
        Span::styled(
            fill.repeat(usize::from(area.width).saturating_sub(used)),
            theme.muted(),
        ),
        Span::styled(countdown, countdown_style),
        Span::styled(fill, theme.muted()),
        pq_badge(theme),
    ]);
    frame.render_widget(Paragraph::new(line).style(theme.base()), area);
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
    let [top, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    header(frame, top, state, "", ctx);
    let [body, hints] = body_and_hints(rest);
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
    let scope = state.scope();
    hint_bar(frame, hints, scope, "", ctx);
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
    let mut lines = Vec::new();
    let mut section = "";
    for (index, (filter, count)) in filter_entries(&state.cache, state.health.as_deref())
        .iter()
        .enumerate()
    {
        let (glyph, heading) = match filter {
            Filter::Favorites => (glyphs.star, ""),
            Filter::All => (glyphs.login, ""),
            Filter::Logins => (glyphs.password, ""),
            Filter::Notes => (glyphs.note, ""),
            Filter::Totp => (glyphs.clock, ""),
            Filter::Weak | Filter::Reused | Filter::Old => (glyphs.attention, "Health"),
            Filter::Tag(_) => ("#", "Tags"),
        };
        if heading != section {
            section = heading;
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!(" {heading}"),
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
        let width = usize::from(inner.width).saturating_sub(9);
        lines.push(Line::from(vec![
            Span::styled(format!(" {glyph} "), style),
            Span::styled(
                format!("{:<width$}", list::fit(label, width)),
                row_style(chosen, theme).patch(style),
            ),
            Span::styled(format!("{count:>4}"), theme.muted()),
        ]));
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
        state.cache.len(),
        if theme.ascii { "->" } else { "→" },
        visible.len()
    );
    let [query, count] = Layout::horizontal([
        Constraint::Min(1),
        Constraint::Length(u16::try_from(counts.len() + 1).unwrap_or(12)),
    ])
    .areas(search);
    frame.render_widget(
        Paragraph::new(text_line(
            &state.home.query,
            query.width,
            state.home.searching,
            theme,
        )),
        query,
    );
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
        let hint = if state.cache.is_empty() {
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
            &state.cache,
            &visible,
            state.home.selected,
            focused || state.home.searching,
            ctx,
        );
    }
}
