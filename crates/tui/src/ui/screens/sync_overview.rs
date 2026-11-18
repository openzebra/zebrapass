//! Split-screen share overview: left pane with shared vaults, node telemetry,
//! and real focusable buttons; right pane with fingerprint, QR card, and URL.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Wrap};
use sharing::ShareUri;

use crate::app::ctx::Ctx;
use crate::app::flows::share::ShareState;
use crate::app::flows::share_nav::ShareFocus;
use crate::app::flows::unlocked::Unlocked;
use crate::ui::screens::sync::{role_name, status};
use crate::ui::screens::sync_actions::{
    copy_button_row, net_listen_row, net_relay_row, vault_button_rows,
};
use crate::ui::screens::sync_buttons::draw_button_row;
use crate::ui::screens::sync_lines::build_node_lines;
use crate::ui::theme::Theme;
use crate::ui::widgets::chrome::pq_badge;
use crate::ui::widgets::fingerprint::stripe_print;
use crate::ui::widgets::list::fit;
use crate::ui::widgets::qr::render::draw_qr_card;

const SPLIT_MIN_WIDTH: u16 = 84;
const SPACER_MIN_WIDTH: u16 = 104;

/// Draw the share overview into `area`.
pub(super) fn draw(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &Unlocked,
    share: &ShareState,
    ctx: &Ctx,
) {
    if area.width < SPLIT_MIN_WIDTH {
        draw_narrow(frame, area, state, share, ctx);
        return;
    }
    let right_w = u16::try_from((usize::from(area.width) * 41 / 100).clamp(41, 58)).unwrap_or(41);
    let spacer = u16::from(area.width >= SPACER_MIN_WIDTH);
    let [left_area, _, right_area] = Layout::horizontal([
        Constraint::Min(38),
        Constraint::Length(spacer),
        Constraint::Length(right_w),
    ])
    .areas(area);

    draw_left_pane(frame, left_area, state, share, ctx);
    draw_right_pane(frame, right_area, state, share, ctx);
}

fn pane_block<'a>(title: &'a str, focused: bool, theme: &Theme) -> Block<'a> {
    let border_type = if theme.ascii {
        BorderType::Plain
    } else {
        BorderType::Rounded
    };
    Block::default()
        .borders(Borders::ALL)
        .border_type(border_type)
        .border_style(if focused {
            theme.accent()
        } else {
            theme.muted()
        })
        .title(Span::styled(format!(" {title} "), theme.strong()))
        .style(theme.base())
}

fn draw_left_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &Unlocked,
    share: &ShareState,
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    let block = pane_block("Vaults & Actions", !share.focus.is_right_pane(), theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width < 10 || inner.height < 8 {
        return;
    }

    let node_lines = build_node_lines(state, theme);
    let node_rows = u16::try_from(node_lines.len()).unwrap_or(1);
    let vault_count = u16::try_from(state.shared.len()).unwrap_or(0);
    let min_vault_rows = if vault_count == 0 {
        1
    } else {
        vault_count.min(2)
    };
    let fixed_rows = 1 + min_vault_rows + 1 + 1 + node_rows;
    let boxed = inner.height >= fixed_rows + 12;
    let btn_h: u16 = if boxed { 3 } else { 1 };
    let max_vault_rows = inner
        .height
        .saturating_sub(1 + 1 + 1 + node_rows + btn_h * 4)
        .max(1);
    let vault_rows = if vault_count == 0 {
        1
    } else {
        vault_count.min(max_vault_rows)
    };

    let [
        vault_hdr,
        vault_list,
        _gap0,
        v_row0,
        v_row1,
        _gap1,
        node_hdr,
        node_area,
        n_row0,
        n_row1,
        _rest,
    ] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(vault_rows),
        Constraint::Length(1),
        Constraint::Length(btn_h),
        Constraint::Length(btn_h),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(node_rows),
        Constraint::Length(btn_h),
        Constraint::Length(btn_h),
        Constraint::Min(0),
    ])
    .areas(inner);

    let vaults_focused = share.focus == ShareFocus::Vaults;
    let vaults_title = if vaults_focused {
        Line::from(vec![
            Span::styled(format!(" {} ", theme.glyphs.pointer), theme.accent()),
            Span::styled("SHARED VAULTS", theme.accent()),
        ])
    } else {
        Line::from(Span::styled(" SHARED VAULTS", theme.muted()))
    };
    frame.render_widget(Paragraph::new(vaults_title), vault_hdr);

    let vault_lines = build_vault_lines(state, share, usize::from(vault_rows), inner.width, theme);
    frame.render_widget(Paragraph::new(vault_lines), vault_list);

    let focused_btn = share.focus.button();
    let (row0, row1) = vault_button_rows(state, share, theme);
    draw_button_row(frame, v_row0, &row0, focused_btn, boxed, theme);
    draw_button_row(frame, v_row1, &row1, focused_btn, boxed, theme);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(" NODE & NETWORK", theme.muted()))),
        node_hdr,
    );
    frame.render_widget(Paragraph::new(node_lines), node_area);

    let net_row0 = net_listen_row(state, theme);
    draw_button_row(frame, n_row0, &net_row0, focused_btn, boxed, theme);
    let net_row1 = net_relay_row(state, theme);
    draw_button_row(frame, n_row1, &net_row1, focused_btn, boxed, theme);
}

fn draw_right_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &Unlocked,
    share: &ShareState,
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    let block = pane_block("your key", share.focus.is_right_pane(), theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width < 12 || inner.height < 8 {
        return;
    }

    let Some(me) = &share.me else {
        let msg = Paragraph::new(Line::from(Span::styled(
            "This vault has no sync identity. Restore it with its recovery phrase to share.",
            theme.warn(),
        )))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
        frame.render_widget(msg, inner);
        return;
    };

    let full_uri = state.share_uri(me.print).to_uri();
    let base_uri = ShareUri::new(me.print, None).to_uri();
    let boxed_buttons = inner.height >= 25;
    let btn_h: u16 = if boxed_buttons { 3 } else { 1 };
    let url_h: u16 = if inner.height >= 28 { 2 } else { 1 };
    let caption_h: u16 = u16::from(inner.height >= 32);

    let [fp_area, qr_area, caption_area, url_area, btn_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(6),
        Constraint::Length(caption_h),
        Constraint::Length(url_h),
        Constraint::Length(btn_h),
    ])
    .areas(inner);

    let text = me.print.to_string();
    let (first, second) = text.split_at(text.len().min(24));
    let second = second.trim_start();
    let fp_lines = vec![
        Line::from(vec![
            Span::styled(stripe_print(me.print.bytes(), theme.glyphs), theme.accent()),
            Span::raw("  "),
            pq_badge(theme),
        ]),
        Line::from(Span::styled(first.to_owned(), theme.strong())),
        Line::from(Span::styled(second.to_owned(), theme.strong())),
    ];
    frame.render_widget(
        Paragraph::new(fp_lines).alignment(Alignment::Center),
        fp_area,
    );

    let shown_uri = draw_qr_card(frame, qr_area, &full_uri, &base_uri, theme).unwrap_or(full_uri);
    if caption_h > 0 {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Scan QR or copy full PQ key.",
                theme.muted(),
            )))
            .alignment(Alignment::Center),
            caption_area,
        );
    }

    let [_, url_inset, _] = Layout::horizontal([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(url_area);
    if url_h >= 2 {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(shown_uri, theme.accent())))
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: false }),
            url_inset,
        );
    } else {
        let fitted = fit(&shown_uri, usize::from(url_inset.width));
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(fitted, theme.accent())))
                .alignment(Alignment::Center),
            url_inset,
        );
    }

    let copy_row = copy_button_row(theme);
    draw_button_row(
        frame,
        btn_area,
        &copy_row,
        share.focus.button(),
        boxed_buttons,
        theme,
    );
}

fn draw_narrow(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, share: &ShareState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let block = pane_block("your key", true, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines = Vec::new();
    match &share.me {
        Some(me) => {
            let text = me.print.to_string();
            let (first, second) = text.split_at(text.len().min(24));
            let second = second.trim_start();
            lines.push(Line::from(vec![
                Span::raw(" "),
                Span::styled(stripe_print(me.print.bytes(), theme.glyphs), theme.accent()),
                Span::raw("  "),
                Span::styled(first.to_owned(), theme.strong()),
            ]));
            lines.push(Line::from(Span::styled(
                format!("                   {second}"),
                theme.strong(),
            )));
            let uri = state.share_uri(me.print).to_uri();
            lines.push(Line::from(Span::styled(
                format!(" {}", fit(&uri, usize::from(inner.width).saturating_sub(2))),
                theme.accent(),
            )));
        }
        None => lines.push(Line::from(Span::styled(
            " This vault has no sync identity. Restore with phrase.",
            theme.warn(),
        ))),
    }
    lines.push(Line::from(""));
    lines.extend(build_vault_lines(state, share, 3, inner.width, theme));
    lines.push(Line::from(""));
    lines.extend(build_node_lines(state, theme));

    let body_h = inner.height.saturating_sub(2);
    let [content_area, btn_row0, btn_row1] = Layout::vertical([
        Constraint::Length(body_h),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    frame.render_widget(Paragraph::new(lines), content_area);

    let [copy_key, copy_url] = copy_button_row(theme);
    let ([new_btn, join_btn, ..], _) = vault_button_rows(state, share, theme);
    let key_row = [copy_key, copy_url, new_btn, join_btn];
    let net_row = net_listen_row(state, theme);
    draw_button_row(
        frame,
        btn_row0,
        &key_row,
        share.focus.button(),
        false,
        theme,
    );
    draw_button_row(
        frame,
        btn_row1,
        &net_row,
        share.focus.button(),
        false,
        theme,
    );
}

fn build_vault_lines(
    state: &Unlocked,
    share: &ShareState,
    max_rows: usize,
    width: u16,
    theme: &Theme,
) -> Vec<Line<'static>> {
    if state.shared.is_empty() {
        return vec![Line::from(Span::styled(
            "  none yet · create or join",
            theme.muted(),
        ))];
    }
    let fetching = state
        .p2p
        .as_deref()
        .is_some_and(|p2p| p2p.service.status().fetching > 0);
    let roomy = width >= 68;
    let name_w = if roomy { 16 } else { 9 };
    let total = state.shared.len();
    let visible = max_rows.max(1);
    let start = share
        .cursor
        .saturating_sub(visible / 2)
        .min(total.saturating_sub(visible));

    state
        .shared
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(index, item)| {
            let chosen = index == share.cursor;
            let pointer = if chosen { theme.glyphs.pointer } else { " " };
            let role = item.my_role.map_or("", role_name);
            let row_style = if chosen { theme.strong() } else { theme.text() };
            let who = people_label(item.people, roomy);
            let who_w = if roomy { 10 } else { 6 };
            let role_w = if roomy { 7 } else { 6 };
            Line::from(vec![
                Span::styled(format!(" {pointer} "), theme.accent()),
                Span::styled(format!("{:<name_w$}", fit(item.name(), name_w)), row_style),
                Span::styled(format!(" {role:<role_w$}"), theme.muted()),
                Span::styled(format!(" {who:<who_w$}"), theme.muted()),
                status(item, fetching, theme),
            ])
        })
        .collect()
}

fn people_label(count: usize, roomy: bool) -> String {
    match (count, roomy) {
        (0 | 1, true) => String::from("just you"),
        (0 | 1, false) => String::from("solo"),
        (more, true) => format!("you + {}", more - 1),
        (more, false) => format!("you+{}", more - 1),
    }
}
