//! The phrase prompt that upgrades an old sync identity.

use ratatui::text::{Line, Span};

use crate::app::flows::restore::REVEAL_LAST;
use crate::app::flows::share_upgrade::UpgradePrompt;
use crate::ui::screens::restore::word_grid;
use crate::ui::screens::sync::{blank, heading, say, INDENT};
use crate::ui::theme::Theme;
use crate::ui::widgets::field::secret_line;

/// The prompt: the masked word grid the restore screen draws, the optional
/// passphrase, and the last problem.
pub(super) fn upgrade_lines(prompt: &UpgradePrompt, theme: &Theme) -> Vec<Line<'static>> {
    let reveal_last = prompt.reveal.is_shown(REVEAL_LAST);
    let mut lines = vec![
        blank(),
        heading("upgrade this device's identity", theme),
        say(
            "Type the recovery phrase of this account. It is checked here and never kept.",
            theme.text(),
        ),
        blank(),
    ];
    for line in word_grid(
        &prompt.phrase,
        !prompt.on_passphrase,
        false,
        reveal_last,
        theme,
    ) {
        let mut spans = vec![Span::raw(INDENT)];
        spans.extend(
            line.spans
                .into_iter()
                .map(|span| Span::styled(span.content.into_owned(), span.style)),
        );
        lines.push(Line::from(spans));
    }
    lines.push(blank());
    let mut pass = vec![Span::styled(format!("{INDENT}passphrase  "), theme.muted())];
    pass.extend(
        secret_line(&prompt.passphrase, prompt.on_passphrase, false, theme)
            .spans
            .into_iter()
            .map(|span| Span::styled(span.content.into_owned(), span.style)),
    );
    lines.push(Line::from(pass));
    lines.push(blank());
    lines.push(prompt.error.map_or_else(
        || {
            say(
                "Enter upgrades, Tab moves to the passphrase, ctrl-r shows the last word.",
                theme.muted(),
            )
        },
        |problem| say(problem, theme.warn()),
    ));
    lines
}
