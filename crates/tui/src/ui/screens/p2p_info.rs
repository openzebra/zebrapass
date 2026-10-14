//! The peer-to-peer dialog (`p2p net`) and the restore-sync modal
//! (`p2p sync // restore`): the node, its network interfaces, protocols,
//! peers, and session event log. Every row is one line, cut to width.

use std::fmt::Write as _;

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
const DEFAULT_BEACON_PORT: u16 = 7448;

fn clock(at_ms: u64) -> String {
    let day = at_ms / 1000 % 86_400;
    format!("{:02}:{:02}:{:02}", day / 3600, day / 60 % 60, day % 60)
}

fn local_ips_text() -> String {
    let ips = p2p_net::local_ips();
    if ips.is_empty() {
        String::from("none")
    } else {
        ips.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn bcast_targets_text(port: u16) -> String {
    let targets = p2p_net::broadcast_targets(port);
    if targets.is_empty() {
        String::from("none")
    } else {
        targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn relay_text(p2p: Option<&crate::app::node::P2p>) -> String {
    match p2p {
        Some(p2p) if p2p.relayed.is_some() => {
            let slot = p2p.relayed.map(|hint| hint.to_string()).unwrap_or_default();
            format!("ZPRY · holding {slot}")
        }
        Some(p2p) if p2p.holds => String::from("ZPRY · hold wanted · no slot yet"),
        _ => String::from("ZPRY · off"),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Draw the `p2p net` dialog over `area`; `scroll` lines back from newest.
pub fn draw(frame: &mut Frame<'_>, area: Rect, scroll: usize, state: &Unlocked, ctx: &Ctx) {
    let theme = &ctx.theme;
    let width = area.width.saturating_sub(2).min(100);
    let height = area.height.saturating_sub(2).min(34);
    let inner = modal(frame, centered(area, width, height), "p2p net", theme);
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
    let bcast_port = state
        .beacon
        .map_or(DEFAULT_BEACON_PORT, |cfg| cfg.send_to.port());
    let beacon_str = if listen == Listen::Beacon {
        format!(
            "on · UDP :{bcast_port} · mcast 239.255.90.80 + bcast [{}]",
            bcast_targets_text(bcast_port)
        )
    } else {
        String::from("off")
    };
    let observed = match p2p.and_then(|node| node.observed.as_ref()) {
        Some(local::Offer::Public(addr) | local::Offer::Local(addr)) => addr.to_string(),
        Some(local::Offer::Unusable) | None => String::from("—"),
    };
    let advertised = format!(
        "{} · local [{}] · obs {observed}",
        state.advertised().unwrap_or("—"),
        local_ips_text()
    );
    let mut lines = vec![
        line("node", status.node.clone()),
        line("peers", peers_text(&status)),
        line("listen mode", mode_word(listen).to_owned()),
        line("advertised", advertised),
        line("beacon", beacon_str),
        line("relay", relay_text(p2p)),
        line(
            "proto.on",
            String::from(
                "TCP/ZPMX:7447 · UDP/ZPBCv2:7448 · KEM/ML-KEM-1024+P256 · SIG/ML-DSA-87 · AEAD/CAS-0xA005",
            ),
        ),
        line(
            "proto.off",
            String::from("QUIC:off · DHT:off · uTP:off · STUN/UPnP:off · NOSTR:off"),
        ),
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
    lines.extend(peers.iter().take(6).map(|(address, source)| {
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
    lines.push(Line::from(Span::styled(
        fit(" events:", cells),
        theme.strong(),
    )));
    append_events(&mut lines, p2p, scroll, inner.height, cells, theme);
    frame.render_widget(Paragraph::new(lines), inner);
    frame.render_widget(
        Paragraph::new(Span::styled(" [↑↓] scroll   [Esc] close", theme.muted())),
        Rect {
            y: inner.y + inner.height.saturating_sub(1),
            height: 1,
            ..inner
        },
    );
}

/// Draw the interactive restore-sync modal while waiting for another device's
/// vault after an empty restore.
pub fn draw_restore_sync(
    frame: &mut Frame<'_>,
    area: Rect,
    scroll: usize,
    state: &Unlocked,
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    let width = area.width.saturating_sub(4).min(92);
    let height = area.height.saturating_sub(4).min(24);
    let inner = modal(
        frame,
        centered(area, width, height),
        "p2p sync // restore",
        theme,
    );
    let cells = usize::from(inner.width).saturating_sub(2);
    let line = |label: &str, value: String| {
        Line::from(vec![
            Span::styled(format!(" {label:<12}"), theme.muted()),
            Span::styled(fit(&value, cells.saturating_sub(13)), theme.text()),
        ])
    };
    let status = summary(state, theme);
    let p2p = state.p2p.as_deref();
    let bcast_port = state
        .beacon
        .map_or(DEFAULT_BEACON_PORT, |cfg| cfg.send_to.port());
    let route = p2p
        .and_then(|node| node.identity.account_gate())
        .and_then(|gate| kdf::account_route_id(gate).ok())
        .map_or_else(|| String::from("—"), |bytes| hex_bytes(&bytes));
    let mut lines = vec![
        Line::from(Span::styled(
            fit(
                " Searching LAN + configured peers for account vault snapshot...",
                cells,
            ),
            theme.accent(),
        )),
        line("route.id", route),
        line("node", status.node.clone()),
        line("local.ip", local_ips_text()),
        line(
            "tx.bcast",
            format!(
                "239.255.90.80:{bcast_port}, {}",
                bcast_targets_text(bcast_port)
            ),
        ),
        line("peers", peers_text(&status)),
        Line::from(""),
        Line::from(Span::styled(fit(" live sync log", cells), theme.strong())),
    ];
    append_events(&mut lines, p2p, scroll, inner.height, cells, theme);
    frame.render_widget(Paragraph::new(lines), inner);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" [Esc]", theme.accent()),
            Span::styled(" cancel   ", theme.text()),
            Span::styled("[↑↓]", theme.muted()),
            Span::styled(" scroll", theme.muted()),
        ])),
        Rect {
            y: inner.y + inner.height.saturating_sub(1),
            height: 1,
            ..inner
        },
    );
}

fn append_events(
    lines: &mut Vec<Line<'static>>,
    p2p: Option<&crate::app::node::P2p>,
    scroll: usize,
    inner_height: u16,
    cells: usize,
    theme: &crate::ui::theme::Theme,
) {
    let room = usize::from(inner_height).saturating_sub(lines.len() + 1);
    let events: Vec<_> = p2p.map(|p2p| p2p.log.lines().collect()).unwrap_or_default();
    if events.is_empty() {
        lines.push(Line::from(Span::styled(
            " waiting for network events...",
            theme.muted(),
        )));
    } else {
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
    }
    lines.truncate(usize::from(inner_height).saturating_sub(1));
}
