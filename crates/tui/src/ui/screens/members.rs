//! Interactive Shared Vault Members modal and Home shared-vault banner.

use memberlog::Role;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::ctx::Ctx;
use crate::app::flows::home::Filter;
use crate::app::flows::members::{MembersButton, MembersFocus, MembersModal, visible_buttons};
use crate::app::flows::unlocked::Unlocked;
use crate::ui::layout::centered;
use crate::ui::screens::sync::{role_name, status};
use crate::ui::screens::sync_buttons::{ButtonSpec, ButtonTone, draw_button_row};
use crate::ui::theme::{Theme, ThemeName};
use crate::ui::widgets::chrome::{modal as modal_panel, row_style};
use crate::ui::widgets::fingerprint::stripe_print;
use crate::ui::widgets::list::fit;
use crate::vault::shared::SharedItem;

/// Compact role pill styled contrast-safely across Dark, Light, and Mono themes.
#[must_use]
pub fn role_badge(role: Role, theme: &Theme) -> Span<'static> {
    let text = match role {
        Role::Owner => " OWNER ",
        Role::Admin => " ADMIN ",
        Role::Writer => " WRITER ",
        Role::Reader => " READER ",
    };
    let style = if matches!(theme.name, ThemeName::Mono) {
        match role {
            Role::Owner | Role::Admin => {
                Style::new().add_modifier(Modifier::REVERSED.union(Modifier::BOLD))
            }
            Role::Writer => Style::new().add_modifier(Modifier::BOLD),
            Role::Reader => Style::new().add_modifier(Modifier::DIM),
        }
    } else {
        match role {
            Role::Owner => Style::new()
                .fg(theme.palette.bg)
                .bg(theme.palette.accent)
                .add_modifier(Modifier::BOLD),
            Role::Admin => Style::new()
                .fg(theme.palette.bg)
                .bg(theme.palette.warn)
                .add_modifier(Modifier::BOLD),
            Role::Writer => Style::new()
                .fg(theme.palette.text)
                .bg(theme.palette.surface)
                .add_modifier(Modifier::BOLD),
            Role::Reader => Style::new()
                .fg(theme.palette.muted)
                .bg(theme.palette.surface),
        }
    };
    Span::styled(text, style)
}

const fn capability_short(role: Role) -> &'static str {
    match role {
        Role::Owner => "all + members",
        Role::Admin => "edit + delete",
        Role::Writer => "edit only",
        Role::Reader => "view only",
    }
}

/// Draw the 1-line contextual banner below the Home action bar for a shared vault.
pub fn draw_shared_banner(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, ctx: &Ctx) {
    let Filter::Shared(vault_id, name) = &state.home.filter else {
        return;
    };
    let theme = &ctx.theme;
    let Some(item) = state.shared_item(vault_id) else {
        return;
    };
    let mut left_spans = vec![
        Span::styled(format!(" {} ", theme.glyphs.sync), theme.accent()),
        Span::styled(
            format!("{} ", fit(name, usize::from(area.width).clamp(8, 22))),
            theme.strong(),
        ),
    ];
    if let Some(role) = item.my_role {
        left_spans.push(role_badge(role, theme));
    }
    let noun = if item.people == 1 {
        "member"
    } else {
        "members"
    };
    if area.width >= 76 {
        left_spans.push(Span::styled(
            format!(" {} {} {noun}", theme.glyphs.dot, item.people),
            theme.muted(),
        ));
    }
    if !item.ready() {
        left_spans.push(Span::styled(
            format!(" {} syncing", theme.glyphs.dot),
            theme.warn(),
        ));
    } else if item.my_role == Some(Role::Owner) && item.leaves > 0 {
        left_spans.push(Span::styled(
            format!(" {} rekey recommended", theme.glyphs.dot),
            theme.warn(),
        ));
    }

    let mut right_spans = Vec::new();
    let chip = |key: &'static str, label: &'static str, key_style: Style, lbl_style: Style| {
        [
            Span::styled(format!(" [{key}]"), key_style),
            Span::styled(format!(" {label}"), lbl_style),
        ]
    };
    right_spans.extend(chip("m", "Members", theme.accent(), theme.text()));
    if item.ready() {
        match item.my_role {
            Some(Role::Owner) if area.width >= 72 => {
                right_spans.extend(chip("a", "+ Add", theme.accent(), theme.strong()));
                if area.width >= 96 {
                    right_spans.extend(chip("d", "Del record", theme.danger(), theme.text()));
                }
            }
            Some(Role::Admin) if area.width >= 72 => {
                right_spans.extend(chip("d", "Del record", theme.danger(), theme.text()));
            }
            Some(Role::Writer) if area.width >= 72 => {
                right_spans.push(Span::styled(
                    format!(" {} can edit, no delete", theme.glyphs.dot),
                    theme.muted(),
                ));
            }
            Some(Role::Reader) if area.width >= 72 => {
                right_spans.push(Span::styled(
                    format!(" {} view only", theme.glyphs.dot),
                    theme.muted(),
                ));
            }
            _ => {}
        }
    }
    let right_width: usize = right_spans
        .iter()
        .map(|span| span.content.chars().count())
        .sum();
    let right_len = u16::try_from(right_width + 1).unwrap_or(24);
    if area.width > right_len + 18 {
        let [left_area, right_area] =
            Layout::horizontal([Constraint::Min(18), Constraint::Length(right_len)]).areas(area);
        frame.render_widget(
            Paragraph::new(Line::from(left_spans)).style(theme.base()),
            left_area,
        );
        frame.render_widget(
            Paragraph::new(Line::from(right_spans)).style(theme.base()),
            right_area,
        );
    } else {
        left_spans.extend(right_spans);
        frame.render_widget(
            Paragraph::new(Line::from(left_spans)).style(theme.base()),
            area,
        );
    }
}

/// Draw the centered Shared Vault Participants modal.
pub fn draw(frame: &mut Frame<'_>, area: Rect, modal: &MembersModal, state: &Unlocked, ctx: &Ctx) {
    let theme = &ctx.theme;
    let Some(item) = state.shared_item(&modal.vault_id) else {
        return;
    };
    let rows = state.vault_members(&modal.vault_id);
    let compact_vertical = area.height <= 22;
    let visible_rows = rows.len().clamp(1, 8);
    let inner_need_for_boxed = 6 + visible_rows + 3;
    let max_width = area.width.saturating_sub(2).max(20);
    let width = max_width.min(84).max(max_width.min(54));
    let boxed =
        usize::from(area.height.saturating_sub(2)) > inner_need_for_boxed && !compact_vertical;
    let want_height = 2
        + 1
        + usize::from(!compact_vertical)
        + 1
        + visible_rows
        + 1
        + usize::from(area.height >= 24)
        + if boxed { 3 } else { 1 }
        + 1;
    let height = u16::try_from(want_height)
        .unwrap_or(area.height)
        .min(area.height.saturating_sub(1).max(10));
    let rect = centered(area, width, height);
    let title = format!(" Shared · «{}» ", item.name());
    let inner = modal_panel(frame, rect, &title, theme);
    if inner.width < 12 || inner.height < 6 {
        return;
    }

    let btn_h = if boxed { 3 } else { 1 };
    let gap_top = u16::from(inner.height >= 12);
    let legend_h = u16::from(inner.height >= 13);
    let [
        summary_area,
        _gap0,
        list_hdr,
        list_area,
        legend_area,
        btn_area,
        hint_area,
    ] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(gap_top),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(legend_h),
        Constraint::Length(btn_h),
        Constraint::Length(1),
    ])
    .areas(inner);

    draw_summary(frame, summary_area, item, rows.len(), state, theme);

    let list_focused = modal.focus == MembersFocus::List;
    let hdr_style = if list_focused {
        theme.accent()
    } else {
        theme.muted()
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(" PARTICIPANTS", hdr_style))).style(theme.panel()),
        list_hdr,
    );

    draw_member_rows(frame, list_area, &rows, modal.cursor, list_focused, theme);
    if legend_h > 0 {
        draw_legend(frame, legend_area, inner.width, theme);
    }

    let is_owner = item.ready() && item.my_role == Some(Role::Owner);
    let selected_is_self = rows.get(modal.cursor).is_none_or(|row| row.is_self);
    let specs = button_specs(is_owner, selected_is_self, theme);
    let focused_btn = match modal.focus {
        MembersFocus::Button(btn) => Some(btn),
        MembersFocus::List => None,
    };
    draw_button_row(frame, btn_area, &specs, focused_btn, boxed, theme);
    draw_hint(frame, hint_area, is_owner, theme);
}

fn draw_legend(frame: &mut Frame<'_>, area: Rect, width: u16, theme: &Theme) {
    let legend = if width >= 66 {
        " Owner: all + members · Admin: edit + del · Writer: edit · Reader: view"
    } else {
        " Owner: all · Admin: edit+del · Writer: edit · Reader: view"
    };
    frame.render_widget(
        Paragraph::new(Span::styled(
            fit(legend, usize::from(area.width)),
            theme.muted(),
        ))
        .style(theme.panel()),
        area,
    );
}

fn draw_hint(frame: &mut Frame<'_>, area: Rect, is_owner: bool, theme: &Theme) {
    let hint = match (is_owner, theme.ascii) {
        (true, true) => " Up/Dn pick  Tab/Lt/Rt button  Enter run  a add  c role  x rem  Esc close",
        (true, false) => {
            " ↑↓ pick  Tab/←→ button  Enter activate  a add  c role  x remove  Esc close"
        }
        (false, true) => " Up/Dn inspect  Tab/Lt/Rt button  Enter run  S share  Esc close",
        (false, false) => " ↑↓ inspect  Tab/←→ button  Enter activate  S share  Esc close",
    };
    frame.render_widget(
        Paragraph::new(Span::styled(
            fit(hint, usize::from(area.width)),
            theme.muted(),
        ))
        .style(theme.panel()),
        area,
    );
}

fn draw_summary(
    frame: &mut Frame<'_>,
    area: Rect,
    item: &SharedItem,
    count: usize,
    state: &Unlocked,
    theme: &Theme,
) {
    let glyphs = theme.glyphs;
    let mut spans = vec![Span::styled(" role ", theme.muted())];
    if let Some(role) = item.my_role {
        spans.push(role_badge(role, theme));
    } else {
        spans.push(Span::styled("none", theme.warn()));
    }
    spans.push(Span::styled(
        format!("  {count} participants  "),
        theme.text(),
    ));
    let fetching = state
        .p2p
        .as_deref()
        .is_some_and(|p2p| p2p.service.status().fetching > 0);
    spans.push(status(item, fetching, theme));
    if item.my_role == Some(Role::Owner) && item.leaves > 0 && area.width >= 68 {
        spans.push(Span::styled(
            format!(" {} {} left (k in Share rekeys)", glyphs.dot, item.leaves),
            theme.warn(),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)).style(theme.panel()), area);
}

fn draw_member_rows(
    frame: &mut Frame<'_>,
    area: Rect,
    rows: &[crate::app::flows::members::MemberRow],
    cursor: usize,
    list_focused: bool,
    theme: &Theme,
) {
    let glyphs = theme.glyphs;
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("  No participant data yet.", theme.muted()))
                .style(theme.panel()),
            area,
        );
        return;
    }
    let max_vis = usize::from(area.height).max(1);
    let clamped = cursor.min(rows.len().saturating_sub(1));
    let start = clamped.saturating_sub(max_vis.saturating_sub(1));
    let end = (start + max_vis).min(rows.len());
    let show_stripes = area.width >= 54;
    let print_len = if area.width >= 68 { 19 } else { 14 };
    let mut lines = Vec::with_capacity(end - start);

    for (idx, row) in rows
        .iter()
        .enumerate()
        .skip(start)
        .take(end.saturating_sub(start))
    {
        let chosen = idx == clamped;
        let pointer = if chosen && list_focused {
            glyphs.pointer
        } else if chosen {
            glyphs.dot
        } else {
            " "
        };
        let row_bg = if chosen && list_focused {
            row_style(true, theme)
        } else {
            theme.panel()
        };
        let full = row.print.to_string();
        let short = full.get(..print_len).unwrap_or(&full);
        let mut spans = vec![Span::styled(
            format!(" {pointer} "),
            if chosen {
                theme.accent()
            } else {
                theme.muted()
            },
        )];
        if show_stripes {
            spans.push(Span::styled(
                stripe_print(row.print.bytes(), glyphs),
                theme.accent(),
            ));
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(
            format!("{short:<print_len$}  "),
            if chosen { theme.strong() } else { theme.text() },
        ));
        spans.push(role_badge(row.role, theme));
        if area.width >= 60 {
            let tag = if row.is_self {
                String::from(" (you)")
            } else if area.width >= 72 {
                format!(" {} {}", glyphs.dot, capability_short(row.role))
            } else {
                format!(" {}", role_name(row.role))
            };
            spans.push(Span::styled(
                tag,
                if row.is_self {
                    theme.accent()
                } else {
                    theme.muted()
                },
            ));
        }
        lines.push(Line::from(spans).style(row_bg));
    }
    frame.render_widget(Paragraph::new(lines).style(theme.panel()), area);
}

fn button_specs(
    is_owner: bool,
    selected_is_self: bool,
    theme: &Theme,
) -> Vec<ButtonSpec<MembersButton>> {
    let glyphs = theme.glyphs;
    let target_tone = if selected_is_self {
        ButtonTone::Muted
    } else {
        ButtonTone::Normal
    };
    let remove_tone = if selected_is_self {
        ButtonTone::Muted
    } else {
        ButtonTone::Danger
    };
    visible_buttons(is_owner)
        .iter()
        .map(|&id| match id {
            MembersButton::Add => ButtonSpec {
                id,
                glyph: glyphs.spark,
                label: "+ Add",
                short_label: "Add",
                key: "a",
                tone: ButtonTone::Primary,
            },
            MembersButton::ChangeRole => ButtonSpec {
                id,
                glyph: glyphs.note,
                label: "Role",
                short_label: "Role",
                key: "c",
                tone: target_tone,
            },
            MembersButton::Remove => ButtonSpec {
                id,
                glyph: glyphs.fail,
                label: "Remove",
                short_label: "Rem",
                key: "x",
                tone: remove_tone,
            },
            MembersButton::OpenShare => ButtonSpec {
                id,
                glyph: glyphs.sync,
                label: "Share",
                short_label: "Share",
                key: "S",
                tone: ButtonTone::Normal,
            },
            MembersButton::Close => ButtonSpec {
                id,
                glyph: glyphs.arrows[2],
                label: "Close",
                short_label: "Close",
                key: "Esc",
                tone: if is_owner {
                    ButtonTone::Normal
                } else {
                    ButtonTone::Primary
                },
            },
        })
        .collect()
}
