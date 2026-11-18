//! Vault home: 2-panel top deck (telemetry + action bar), then three panes
//! (wide), two panes (medium), or a stack (narrow).

use std::time::Duration;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};

use crate::app::ctx::Ctx;
use crate::app::flows::home::{Filter, Pane};
use crate::app::flows::unlocked::Unlocked;
use crate::app::idle::clock;
use crate::ui::layout::Breakpoint;
use crate::ui::screens::p2p_status::{Light, summary};
use crate::ui::screens::{detail, members};
use crate::ui::theme::{Theme, ThemeName};
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
        String::from(" CAS-0xA005 ")
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
    let glyph = format!(" {}", theme.glyphs.sync);
    let Some(p2p) = state.p2p.as_ref() else {
        return (glyph, theme.muted());
    };
    let status = p2p.service.status();
    let style = if (status.peers > 0 && status.fetching == 0) || p2p_sum.light == Light::Green {
        theme.accent()
    } else {
        theme.warn()
    };
    (glyph, style)
}

fn active_permissions(state: &Unlocked) -> (bool, bool, bool) {
    let Filter::Shared(vault_id, _) = &state.home.filter else {
        return (true, true, false);
    };
    let Some(item) = state.shared_item(vault_id) else {
        return (false, false, true);
    };
    let ready = item.ready();
    let can_edit = ready && item.my_role.is_some_and(memberlog::Role::can_write);
    let can_delete = ready && item.my_role.is_some_and(memberlog::Role::can_delete);
    (can_edit, can_delete, true)
}

fn action_chip(
    key: &'static str,
    label: &'static str,
    enabled: bool,
    danger: bool,
    theme: &Theme,
) -> [Span<'static>; 3] {
    let chip_bg = if matches!(theme.name, ThemeName::Mono) || !enabled {
        Style::new()
    } else {
        Style::new().bg(theme.palette.surface)
    };
    let (key_style, lbl_style) = if !enabled {
        (theme.muted(), theme.muted())
    } else if danger {
        (theme.danger().patch(chip_bg), theme.text().patch(chip_bg))
    } else {
        (theme.accent().patch(chip_bg), theme.text().patch(chip_bg))
    };
    [
        Span::raw(" "),
        Span::styled(format!("[{key}] "), key_style),
        Span::styled(label, lbl_style),
    ]
}

fn draw_action_bar(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, ctx: &Ctx) {
    let theme = &ctx.theme;
    if state.home.searching {
        let line = Line::from(vec![
            Span::styled(" SEARCH ", theme.accent()),
            Span::styled(" [Enter] open  [Esc] clear  [↑↓] move", theme.muted()),
        ]);
        frame.render_widget(Paragraph::new(line).style(theme.base()), area);
        return;
    }
    let (can_edit, can_delete, in_shared) = active_permissions(state);
    let compact = area.width < 136;
    let sep = if theme.ascii || compact {
        " | "
    } else {
        " │ "
    };
    let mut spans = Vec::with_capacity(48);
    spans.extend(action_chip("n", "NEW", can_edit, false, theme));
    spans.extend(action_chip("E", "EDIT", can_edit, false, theme));
    spans.extend(action_chip("d", "DEL", can_delete, true, theme));
    spans.push(Span::styled(sep, theme.muted()));
    for (key, label) in [("g", "RNG"), ("i", "P2P")] {
        spans.extend(action_chip(key, label, true, false, theme));
    }
    if in_shared {
        let lbl = if compact { "MEM" } else { "MEMBERS" };
        spans.extend(action_chip("m", lbl, true, false, theme));
    }
    for (key, label) in [("S", "SHARE"), ("F", "KEYS"), ("D", "DEV"), ("H", "AUDIT")] {
        spans.extend(action_chip(key, label, true, false, theme));
    }
    spans.push(Span::styled(sep, theme.muted()));
    let cfg_lbl = if compact { "cfg" } else { "settings" };
    for (key, label) in [(",", cfg_lbl), ("L", "LOCK"), ("?", "HELP"), ("q", "QUIT")] {
        spans.extend(action_chip(key, label, true, false, theme));
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
    if state.in_shared() {
        let [top, actions, shared_bar, body] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .areas(area);
        header(frame, top, state, "", ctx);
        draw_action_bar(frame, actions, state, ctx);
        members::draw_shared_banner(frame, shared_bar, state, ctx);
        draw_body(frame, body, state, ctx);
    } else {
        let [top, actions, body] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .areas(area);
        header(frame, top, state, "", ctx);
        draw_action_bar(frame, actions, state, ctx);
        draw_body(frame, body, state, ctx);
    }
}

fn draw_body(frame: &mut Frame<'_>, body: Rect, state: &Unlocked, ctx: &Ctx) {
    match Breakpoint::from(body.width) {
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
            if state.home.pane == Pane::Filters {
                let [filters, records] =
                    Layout::horizontal([Constraint::Length(22), Constraint::Min(30)]).areas(body);
                draw_filters(frame, filters, state, ctx);
                draw_list(frame, records, state, ctx);
            } else {
                let [records, detail_area] =
                    Layout::horizontal([Constraint::Percentage(50), Constraint::Min(30)])
                        .areas(body);
                draw_list(frame, records, state, ctx);
                detail::draw_pane(frame, detail_area, state, ctx);
            }
        }
        Breakpoint::Narrow => {
            if state.home.pane == Pane::Filters {
                draw_filters(frame, body, state, ctx);
            } else if state.home.stacked || state.home.pane == Pane::Detail {
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
        } else if state.cache.is_empty() && state.home.searching {
            "No records yet. Esc, then n to add one."
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
