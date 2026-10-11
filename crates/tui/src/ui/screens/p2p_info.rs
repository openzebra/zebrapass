//! The peer-to-peer dialog: the node, its peers, and what happened this
//! session. Every row is one line, cut to the dialog's width.

use local::Listen;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::unlocked::Unlocked;
use crate::app::node::log::LastResult;
use crate::ui::layout::centered;
use crate::ui::screens::p2p_status::{ago, mode_word, peer_rows, peers_text, summary};
use crate::ui::widgets::chrome::modal;
use crate::ui::widgets::list::fit;

const ADDRESS_CELLS: usize = 30;
const SOURCE_CELLS: usize = 8;

fn clock(at_ms: u64) -> String {
    let day = at_ms / 1000 % 86_400;
    format!("{:02}:{:02}:{:02}", day / 3600, day / 60 % 60, day % 60)
}

/// Draw the dialog over `area`; `scroll` lines back from the newest event.
pub fn draw(frame: &mut Frame<'_>, area: Rect, scroll: usize, state: &Unlocked, ctx: &Ctx) {
    let theme = &ctx.theme;
    let width = area.width.saturating_sub(2).min(100);
    let height = area.height.saturating_sub(2).min(30);
    let inner = modal(frame, centered(area, width, height), "Peer-to-peer", theme);
    let cells = usize::from(inner.width).saturating_sub(2);
    let line = |label: &str, value: String| {
        Line::from(vec![
            Span::styled(format!(" {label:<12}"), theme.muted()),
            Span::styled(fit(&value, cells.saturating_sub(13)), theme.text()),
        ])
    };
    let status = summary(state, theme);
    let p2p = state.p2p.as_deref();
    let listen = state.listen_mode();
    let relay = match p2p {
        Some(p2p) if p2p.relayed.is_some() => {
            let slot = p2p.relayed.map(|hint| hint.to_string()).unwrap_or_default();
            format!("holding {slot}")
        }
        Some(p2p) if p2p.holds => String::from("hold wanted · no slot yet"),
        _ => String::from("not holding a slot"),
    };
    let mut lines = vec![
        line("node", status.node.clone()),
        line("peers", peers_text(&status)),
        line("listen mode", mode_word(listen).to_owned()),
        line("advertised", state.advertised().unwrap_or("—").to_owned()),
        line(
            "beacon",
            String::from(if listen == Listen::Beacon {
                "on"
            } else {
                "off"
            }),
        ),
        line("relay", relay),
        Line::from(""),
        Line::from(Span::styled(
            fit(
                &format!(
                    " {:<ADDRESS_CELLS$} {:<SOURCE_CELLS$} last check-in",
                    "address", "source"
                ),
                cells,
            ),
            theme.strong(),
        )),
    ];
    let peers = peer_rows(state);
    if peers.is_empty() {
        lines.push(Line::from(Span::styled(" no addresses yet", theme.muted())));
    }
    lines.extend(peers.iter().take(10).map(|(address, source)| {
        let last = p2p.and_then(|p2p| p2p.log.result(address)).map_or_else(
            || String::from("—"),
            |result| match result {
                LastResult::Pulled(at) => format!("ok · {}", ago(at)),
                LastResult::Failed(reason, at) => format!("{reason} · {}", ago(at)),
            },
        );
        let text = format!(
            " {:<ADDRESS_CELLS$} {:<SOURCE_CELLS$} {last}",
            fit(address, ADDRESS_CELLS).trim_end(),
            source.word()
        );
        Line::from(Span::styled(fit(&text, cells), theme.text()))
    }));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        fit(" events this session (not saved)", cells),
        theme.strong(),
    )));
    let room = usize::from(inner.height).saturating_sub(lines.len() + 1);
    let events: Vec<_> = p2p.map(|p2p| p2p.log.lines().collect()).unwrap_or_default();
    let end = events
        .len()
        .saturating_sub(scroll.min(events.len().saturating_sub(room)));
    let start = end.saturating_sub(room);
    lines.extend(
        events
            .get(start..end)
            .unwrap_or_default()
            .iter()
            .map(|event| {
                Line::from(Span::styled(
                    fit(&format!(" {} {}", clock(event.at_ms), event.text), cells),
                    theme.muted(),
                ))
            }),
    );
    lines.truncate(usize::from(inner.height).saturating_sub(1));
    frame.render_widget(Paragraph::new(lines), inner);
    frame.render_widget(
        Paragraph::new(Span::styled(" ↑↓ scroll    Esc close", theme.muted())),
        Rect {
            y: inner.y + inner.height.saturating_sub(1),
            height: 1,
            ..inner
        },
    );
}
