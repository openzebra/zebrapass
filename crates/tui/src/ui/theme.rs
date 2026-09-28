//! Palettes, glyph vocabulary, and the style roles screens draw with.
//!
//! Color never carries meaning alone: every state also has a glyph and a
//! word, so the `mono` theme loses nothing but tint.

use std::str::FromStr;

use ratatui::style::{Color, Modifier, Style};

/// A named theme.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ThemeName {
    /// Near-black canvas, the default.
    #[default]
    StripesDark,
    /// Light canvas.
    StripesLight,
    /// No color: terminal default foreground and background.
    Mono,
}

impl ThemeName {
    /// Every theme, in cycle order.
    pub const ALL: [Self; 3] = [Self::StripesDark, Self::StripesLight, Self::Mono];

    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::StripesDark => "stripes-dark",
            Self::StripesLight => "stripes-light",
            Self::Mono => "mono",
        }
    }

    /// The next theme in cycle order.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::StripesDark => Self::StripesLight,
            Self::StripesLight => Self::Mono,
            Self::Mono => Self::StripesDark,
        }
    }
}

impl FromStr for ThemeName {
    type Err = ();

    fn from_str(name: &str) -> Result<Self, ()> {
        Self::ALL
            .into_iter()
            .find(|theme| theme.label() == name)
            .ok_or(())
    }
}

/// The colors of one theme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    /// Canvas.
    pub bg: Color,
    /// Panels.
    pub surface: Color,
    /// Secondary text and borders.
    pub muted: Color,
    /// Primary text.
    pub text: Color,
    /// Light stripe of a masked secret.
    pub zebra: Color,
    /// Unlocked, verified, primary button.
    pub accent: Color,
    /// Attention.
    pub warn: Color,
    /// Delete, revoke, rollback.
    pub danger: Color,
    /// Post-quantum badges.
    pub pq: Color,
}

const DARK: Palette = Palette {
    bg: Color::Rgb(0x0E, 0x0F, 0x11),
    surface: Color::Rgb(0x17, 0x19, 0x1C),
    muted: Color::Rgb(0x6B, 0x70, 0x78),
    text: Color::Rgb(0xE6, 0xE6, 0xE6),
    zebra: Color::Rgb(0xF5, 0xF5, 0xF5),
    accent: Color::Rgb(0x7C, 0xFF, 0xB2),
    warn: Color::Rgb(0xFF, 0xC8, 0x57),
    danger: Color::Rgb(0xFF, 0x5C, 0x7A),
    pq: Color::Rgb(0x9D, 0x8C, 0xFF),
};

const LIGHT: Palette = Palette {
    bg: Color::Rgb(0xF7, 0xF7, 0xF5),
    surface: Color::Rgb(0xEC, 0xEC, 0xE8),
    muted: Color::Rgb(0x6B, 0x70, 0x78),
    text: Color::Rgb(0x16, 0x17, 0x1A),
    zebra: Color::Rgb(0x11, 0x11, 0x11),
    accent: Color::Rgb(0x0B, 0x8A, 0x4C),
    warn: Color::Rgb(0x9A, 0x62, 0x00),
    danger: Color::Rgb(0xC0, 0x1F, 0x45),
    pq: Color::Rgb(0x5B, 0x46, 0xD6),
};

const MONO: Palette = Palette {
    bg: Color::Reset,
    surface: Color::Reset,
    muted: Color::Reset,
    text: Color::Reset,
    zebra: Color::Reset,
    accent: Color::Reset,
    warn: Color::Reset,
    danger: Color::Reset,
    pq: Color::Reset,
};

/// The symbols screens draw with. Each has an ASCII twin.
#[derive(Debug, PartialEq, Eq)]
pub struct Glyphs {
    /// One cell of a masked secret.
    pub mask: &'static str,
    /// Vault key.
    pub vk: &'static str,
    /// Key-encryption key / wrap.
    pub kek: &'static str,
    /// Device factor.
    pub device: &'static str,
    /// Chip / secure enclave factor.
    pub chip: &'static str,
    /// Password factor.
    pub password: &'static str,
    /// Hardware key (PRF) factor.
    pub hw_key: &'static str,
    /// Recovery phrase.
    pub recovery: &'static str,
    /// Verified.
    pub ok: &'static str,
    /// Failed.
    pub fail: &'static str,
    /// Attention.
    pub attention: &'static str,
    /// Rotation.
    pub rotate: &'static str,
    /// Sync.
    pub sync: &'static str,
    /// Filled meter cell.
    pub bar_on: &'static str,
    /// Empty meter cell.
    pub bar_off: &'static str,
    /// Fingerprint bit 1.
    pub bit_one: &'static str,
    /// Fingerprint bit 0.
    pub bit_zero: &'static str,
    /// Selection pointer.
    pub pointer: &'static str,
    /// Selected radio / step dot.
    pub on: &'static str,
    /// Unselected radio / step dot.
    pub off: &'static str,
    /// Favorite.
    pub star: &'static str,
    /// Login record.
    pub login: &'static str,
    /// Secure note record.
    pub note: &'static str,
    /// Time-based code.
    pub clock: &'static str,
    /// Locked.
    pub lock: &'static str,
    /// Text cursor.
    pub cursor: &'static str,
    /// Create.
    pub spark: &'static str,
    /// Command palette.
    pub command: &'static str,
    /// Separator dot.
    pub dot: &'static str,
    /// Up / down / left / right arrows.
    pub arrows: [&'static str; 4],
    /// Horizontal slider track and knob.
    pub track: [&'static str; 2],
}

const UNICODE: Glyphs = Glyphs {
    mask: "▚",
    vk: "◆",
    kek: "◇",
    device: "⌁",
    chip: "⌂",
    password: "⚿",
    hw_key: "⎔",
    recovery: "↺",
    ok: "✓",
    fail: "✗",
    attention: "!",
    rotate: "⟲",
    sync: "⇅",
    bar_on: "▰",
    bar_off: "▱",
    bit_one: "▐",
    bit_zero: "▌",
    pointer: "▸",
    on: "●",
    off: "○",
    star: "★",
    login: "◉",
    note: "✎",
    clock: "⏱",
    lock: "⏻",
    cursor: "▏",
    spark: "✦",
    command: "⌘",
    dot: "·",
    arrows: ["↑", "↓", "←", "→"],
    track: ["━", "●"],
};

const ASCII: Glyphs = Glyphs {
    mask: "#",
    vk: "<>",
    kek: "<>",
    device: "[D]",
    chip: "[C]",
    password: "[P]",
    hw_key: "[K]",
    recovery: "[R]",
    ok: "+",
    fail: "x",
    attention: "!",
    rotate: "@",
    sync: "<>",
    bar_on: "#",
    bar_off: "-",
    bit_one: "|",
    bit_zero: ":",
    pointer: ">",
    on: "*",
    off: "o",
    star: "*",
    login: "o",
    note: "N",
    clock: "T",
    lock: "L",
    cursor: "_",
    spark: "+",
    command: "K",
    dot: "-",
    arrows: ["Up", "Dn", "Lt", "Rt"],
    track: ["=", "O"],
};

/// Everything a screen needs to draw: colors, glyphs, and motion.
#[derive(Clone, Copy, Debug)]
pub struct Theme {
    /// Which theme.
    pub name: ThemeName,
    /// Colors.
    pub palette: Palette,
    /// Symbols.
    pub glyphs: &'static Glyphs,
    /// Animations run when `true`.
    pub anim: bool,
    /// ASCII glyphs are in use.
    pub ascii: bool,
}

impl Theme {
    /// Build a theme.
    #[must_use]
    pub const fn new(name: ThemeName, ascii: bool, anim: bool) -> Self {
        let palette = match name {
            ThemeName::StripesDark => DARK,
            ThemeName::StripesLight => LIGHT,
            ThemeName::Mono => MONO,
        };
        let glyphs = if ascii { &ASCII } else { &UNICODE };
        Self {
            name,
            palette,
            glyphs,
            anim,
            ascii,
        }
    }

    const fn mono(&self) -> bool {
        matches!(self.name, ThemeName::Mono)
    }

    /// Canvas style.
    #[must_use]
    pub const fn base(&self) -> Style {
        Style::new().fg(self.palette.text).bg(self.palette.bg)
    }

    /// Primary text.
    #[must_use]
    pub const fn text(&self) -> Style {
        Style::new().fg(self.palette.text)
    }

    /// Secondary text and borders.
    #[must_use]
    pub const fn muted(&self) -> Style {
        if self.mono() {
            Style::new().add_modifier(Modifier::DIM)
        } else {
            Style::new().fg(self.palette.muted)
        }
    }

    /// Emphasized primary text.
    #[must_use]
    pub const fn strong(&self) -> Style {
        self.text().add_modifier(Modifier::BOLD)
    }

    /// Block text cursor: the cell under the cursor, reversed (vim style).
    #[must_use]
    pub const fn cursor(&self) -> Style {
        Style::new()
            .fg(self.palette.text)
            .add_modifier(Modifier::REVERSED)
    }

    /// Unlocked, verified, primary.
    #[must_use]
    pub const fn accent(&self) -> Style {
        if self.mono() {
            Style::new().add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(self.palette.accent)
        }
    }

    /// Attention.
    #[must_use]
    pub const fn warn(&self) -> Style {
        if self.mono() {
            Style::new().add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(self.palette.warn)
        }
    }

    /// Danger.
    #[must_use]
    pub const fn danger(&self) -> Style {
        if self.mono() {
            Style::new().add_modifier(Modifier::BOLD.union(Modifier::UNDERLINED))
        } else {
            Style::new().fg(self.palette.danger)
        }
    }

    /// Post-quantum badge.
    #[must_use]
    pub const fn pq(&self) -> Style {
        if self.mono() {
            Style::new().add_modifier(Modifier::BOLD)
        } else {
            Style::new()
                .fg(self.palette.pq)
                .add_modifier(Modifier::BOLD)
        }
    }

    /// Masked-secret stripes.
    #[must_use]
    pub const fn zebra(&self) -> Style {
        if self.mono() {
            Style::new()
        } else {
            Style::new().fg(self.palette.zebra)
        }
    }

    /// The one bright button of a screen.
    #[must_use]
    pub const fn primary_button(&self) -> Style {
        if self.mono() {
            Style::new().add_modifier(Modifier::REVERSED.union(Modifier::BOLD))
        } else {
            Style::new()
                .fg(self.palette.bg)
                .bg(self.palette.accent)
                .add_modifier(Modifier::BOLD)
        }
    }

    /// Selected row.
    #[must_use]
    pub const fn selected(&self) -> Style {
        if self.mono() {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new()
                .fg(self.palette.text)
                .bg(self.palette.surface)
                .add_modifier(Modifier::BOLD)
        }
    }

    /// Panel background.
    #[must_use]
    pub const fn panel(&self) -> Style {
        Style::new().fg(self.palette.text).bg(self.palette.surface)
    }
}
