//! The settings modal.
//!
//! Posture meter and search on top, the section rail on the left (a
//! one-line switcher when narrow), rows with staged values, the reason
//! behind the selected row, and the unsaved count.

mod value;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::settings::rows::{changes, Row, Section};
use crate::app::flows::settings::{Focus, SettingsModal};
use crate::app::flows::unlocked::Unlocked;
use crate::ui::layout::centered;
use crate::ui::theme::Theme;
use crate::ui::widgets::chrome::{modal as modal_frame, row_style};
use crate::ui::widgets::field::text_line;
use crate::ui::widgets::meter::bar;

/// Below this inner width the rail folds into a one-line switcher.
const RAIL_MIN_WIDTH: u16 = 70;
/// Rail width in the wide layout.
const RAIL_WIDTH: u16 = 18;
/// Label column width.
const LABEL_WIDTH: usize = 28;

/// Draw the modal over the current view.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, modal: &SettingsModal, ctx: &Ctx) {
    let theme = &ctx.theme;
    let rect = centered(
        area,
        area.width.saturating_sub(4).min(100),
        area.height.saturating_sub(2).min(21),
    );
    let inner = modal_frame(frame, rect, "Settings", theme);
    let [top, _, body, why, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .areas(inner);
    draw_top(frame, top, state, modal, ctx);
    let rows_area = if inner.width >= RAIL_MIN_WIDTH {
        let [rail, _, rows] = Layout::horizontal([
            Constraint::Length(RAIL_WIDTH),
            Constraint::Length(1),
            Constraint::Min(10),
        ])
        .areas(body);
        draw_rail(frame, rail, modal, theme);
        rows
    } else {
        let [switcher, rows] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(body);
        draw_switcher(frame, switcher, modal, theme);
        rows
    };
    draw_rows(frame, rows_area, state, modal, ctx);
    draw_why(frame, why, modal, theme);
    draw_status(frame, footer, modal, theme);
}

/// Unsaved count and how to settle it; the screen's hint bar has the keys.
fn draw_status(frame: &mut Frame<'_>, area: Rect, modal: &SettingsModal, theme: &Theme) {
    let line = match modal.unsaved() {
        0 => Line::from(Span::styled(
            " saved · stored encrypted with this vault",
            theme.muted(),
        )),
        count => {
            let plural = if count == 1 { "" } else { "s" };
            Line::from(vec![
                Span::styled(
                    format!(" {} {count} unsaved change{plural}", theme.glyphs.dot),
                    theme.warn(),
                ),
                Span::styled("  ·  Ctrl-S apply  ·  Esc discard", theme.muted()),
            ])
        }
    };
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_top(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, modal: &SettingsModal, ctx: &Ctx) {
    let theme = &ctx.theme;
    let posture = value::score(state, modal);
    let meter = format!(
        "posture {} {:>3} ",
        bar(f64::from(posture.score) / 100.0, 10, theme.glyphs),
        posture.score
    );
    let meter_width = u16::try_from(meter.chars().count()).unwrap_or(0);
    let [search, right] =
        Layout::horizontal([Constraint::Min(10), Constraint::Length(meter_width)]).areas(area);
    let focused = modal.focus == Focus::Filter;
    let search_line = if focused || !modal.filter.is_empty() {
        let mut spans = vec![Span::styled(" / ", theme.accent())];
        spans.extend(
            text_line(
                &modal.filter,
                search.width.saturating_sub(4),
                focused,
                theme,
            )
            .spans,
        );
        Line::from(spans)
    } else {
        Line::from(Span::styled(" / search every setting", theme.muted()))
    };
    frame.render_widget(Paragraph::new(search_line), search);
    let style = match posture.score {
        80..=100 => theme.accent(),
        50..=79 => theme.warn(),
        _ => theme.danger(),
    };
    frame.render_widget(Paragraph::new(Span::styled(meter, style)), right);
}

fn draw_rail(frame: &mut Frame<'_>, area: Rect, modal: &SettingsModal, theme: &Theme) {
    let searching = !modal.filter.is_empty();
    let hits = modal.visible();
    let changed: Vec<Section> = changes(&modal.draft, &modal.saved)
        .map(Row::section)
        .collect();
    let lines: Vec<Line<'_>> = Section::ALL
        .iter()
        .map(|section| {
            let current = !searching && *section == modal.section;
            let lit = !searching || hits.iter().any(|row| row.section() == *section);
            let pointer = if current { theme.glyphs.pointer } else { " " };
            let style = if current {
                row_style(true, theme)
            } else if lit {
                theme.text()
            } else {
                theme.muted()
            };
            let mut spans = vec![Span::styled(
                format!(" {pointer} {}", section.label()),
                style,
            )];
            if changed.contains(section) {
                spans.push(Span::styled(format!(" {}", theme.glyphs.dot), theme.warn()));
            }
            if *section == Section::Sync {
                spans.push(Span::styled(" soon", theme.muted()));
            }
            Line::from(spans)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_switcher(frame: &mut Frame<'_>, area: Rect, modal: &SettingsModal, theme: &Theme) {
    let text = if modal.filter.is_empty() {
        let (left, right) = if theme.ascii {
            ("<", ">")
        } else {
            ("‹", "›")
        };
        format!(" {left} {} {right}  Tab", modal.section.label())
    } else {
        format!(" {} matches", modal.visible().len())
    };
    frame.render_widget(Paragraph::new(Span::styled(text, theme.accent())), area);
}

fn draw_rows(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &Unlocked,
    modal: &SettingsModal,
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    let rows = modal.visible();
    if rows.is_empty() {
        let line = Span::styled("  No setting matches that search.", theme.muted());
        frame.render_widget(Paragraph::new(line), area);
        return;
    }
    let height = usize::from(area.height).max(1);
    let first = modal.cursor.saturating_sub(height.saturating_sub(1));
    let value_width = usize::from(area.width).saturating_sub(LABEL_WIDTH + 6);
    let lines: Vec<Line<'_>> = rows
        .iter()
        .enumerate()
        .skip(first)
        .take(height)
        .map(|(index, row)| {
            let chosen = index == modal.cursor;
            let pointer = if chosen { theme.glyphs.pointer } else { " " };
            let label = format!(" {pointer} {:<LABEL_WIDTH$}", row.label());
            let mut spans = vec![Span::styled(label, row_style(chosen, theme))];
            let editing = chosen && modal.focus == Focus::Edit;
            if editing {
                let width = u16::try_from(value_width).unwrap_or(u16::MAX);
                spans.extend(text_line(&modal.edit, width, true, theme).spans);
            } else {
                spans.extend(value_spans(*row, chosen, value_width, state, modal, ctx));
            }
            if row.changed(&modal.draft, &modal.saved) {
                spans.push(Span::styled(
                    format!("  {}", theme.glyphs.dot),
                    theme.warn(),
                ));
            }
            Line::from(spans)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn value_spans(
    row: Row,
    chosen: bool,
    width: usize,
    state: &Unlocked,
    modal: &SettingsModal,
    ctx: &Ctx,
) -> Vec<Span<'static>> {
    let theme = &ctx.theme;
    let text = value::value(row, state, modal, ctx);
    let text = if matches!(row, Row::FilePath | Row::DataDir) {
        keep_tail(&text, width)
    } else {
        text
    };
    let danger = row.section() == Section::Danger;
    let style = match (chosen, danger) {
        (_, true) => theme.danger(),
        (true, false) => theme.accent(),
        (false, false) => theme.text(),
    };
    if chosen && row.adjustable() {
        let (left, right) = if theme.ascii {
            ("< ", " >")
        } else {
            ("◂ ", " ▸")
        };
        vec![
            Span::styled(left, theme.muted()),
            Span::styled(text, style),
            Span::styled(right, theme.muted()),
        ]
    } else {
        vec![Span::styled(text, style)]
    }
}

/// `text` cut from the left to `width` characters, marked with an ellipsis.
fn keep_tail(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width || width < 2 {
        return text.to_owned();
    }
    let tail: String = text.chars().skip(count - (width - 1)).collect();
    format!("…{tail}")
}

fn draw_why(frame: &mut Frame<'_>, area: Rect, modal: &SettingsModal, theme: &Theme) {
    let area = Rect {
        x: area.x.saturating_add(1),
        width: area.width.saturating_sub(2),
        ..area
    };
    let mut lines = Vec::with_capacity(3);
    if let Some(error) = modal.error {
        lines.push(Line::from(Span::styled(
            format!("{} {error}", theme.glyphs.fail),
            theme.danger(),
        )));
    }
    if let Some(row) = modal.row() {
        lines.push(Line::from(Span::styled(row.why(), theme.muted())));
        if row == Row::Theme {
            lines.push(swatch(theme));
        }
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

/// The live theme's palette, one block per role.
fn swatch(theme: &Theme) -> Line<'static> {
    let block = if theme.ascii { "##" } else { "██" };
    Line::from(
        [
            theme.text(),
            theme.accent(),
            theme.zebra(),
            theme.pq(),
            theme.warn(),
            theme.danger(),
        ]
        .into_iter()
        .flat_map(|style| [Span::styled(block, style), Span::raw(" ")])
        .collect::<Vec<_>>(),
    )
}
