//! Color schemes and style helpers for Scry's TUI.

use ratatui::style::{Color, Modifier, Style};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ColorScheme {
    #[default]
    #[serde(alias = "imbas", alias = "charon")]
    Scry,
    Catppuccin,
    Nord,
    Dracula,
    Github,
    RosePine,
    Gruvbox,
    TokyoNight,
}

impl ColorScheme {
    pub fn label(self) -> &'static str {
        match self {
            Self::Scry => "Scry (default)",
            Self::Catppuccin => "Catppuccin Mocha",
            Self::Nord => "Nord",
            Self::Dracula => "Dracula",
            Self::Github => "GitHub Dark",
            Self::RosePine => "Rosé Pine",
            Self::Gruvbox => "Gruvbox Dark",
            Self::TokyoNight => "Tokyo Night",
        }
    }

    pub fn all() -> &'static [ColorScheme] {
        &[
            Self::Scry,
            Self::Catppuccin,
            Self::Nord,
            Self::Dracula,
            Self::Github,
            Self::RosePine,
            Self::Gruvbox,
            Self::TokyoNight,
        ]
    }

    pub fn palette(self) -> Palette {
        match self {
            Self::Scry => Palette {
                bg: rgb(10, 14, 18),
                panel: rgb(16, 22, 28),
                panel_focus: rgb(22, 36, 40),
                border: rgb(42, 64, 74),
                border_focus: rgb(90, 196, 186),
                title: rgb(232, 220, 196),
                text: rgb(196, 210, 214),
                muted: rgb(110, 130, 138),
                accent: rgb(56, 168, 158),
                warn: rgb(214, 158, 72),
                danger: rgb(196, 82, 74),
                ok: rgb(110, 186, 120),
                progress: rgb(72, 180, 170),
                progress_bg: rgb(28, 40, 46),
            },
            Self::Catppuccin => Palette {
                bg: rgb(30, 30, 46),
                panel: rgb(24, 24, 37),
                panel_focus: rgb(36, 36, 58),
                border: rgb(69, 71, 90),
                border_focus: rgb(137, 180, 250),
                title: rgb(205, 214, 244),
                text: rgb(186, 194, 222),
                muted: rgb(108, 112, 134),
                accent: rgb(203, 166, 247),
                warn: rgb(249, 226, 175),
                danger: rgb(243, 139, 168),
                ok: rgb(166, 227, 161),
                progress: rgb(137, 180, 250),
                progress_bg: rgb(49, 50, 68),
            },
            Self::Nord => Palette {
                bg: rgb(46, 52, 64),
                panel: rgb(59, 66, 82),
                panel_focus: rgb(67, 76, 94),
                border: rgb(76, 86, 106),
                border_focus: rgb(136, 192, 208),
                title: rgb(236, 239, 244),
                text: rgb(216, 222, 233),
                muted: rgb(129, 161, 193),
                accent: rgb(136, 192, 208),
                warn: rgb(235, 203, 139),
                danger: rgb(191, 97, 106),
                ok: rgb(163, 190, 140),
                progress: rgb(129, 161, 193),
                progress_bg: rgb(67, 76, 94),
            },
            Self::Dracula => Palette {
                bg: rgb(40, 42, 54),
                panel: rgb(33, 34, 44),
                panel_focus: rgb(48, 42, 66),
                border: rgb(68, 71, 90),
                border_focus: rgb(189, 147, 249),
                title: rgb(248, 248, 242),
                text: rgb(248, 248, 242),
                muted: rgb(98, 114, 164),
                accent: rgb(139, 233, 253),
                warn: rgb(241, 250, 140),
                danger: rgb(255, 85, 85),
                ok: rgb(80, 250, 123),
                progress: rgb(189, 147, 249),
                progress_bg: rgb(68, 71, 90),
            },
            Self::Github => Palette {
                bg: rgb(13, 17, 23),
                panel: rgb(22, 27, 34),
                panel_focus: rgb(28, 36, 48),
                border: rgb(48, 54, 61),
                border_focus: rgb(88, 166, 255),
                title: rgb(230, 237, 243),
                text: rgb(201, 209, 217),
                muted: rgb(139, 148, 158),
                accent: rgb(88, 166, 255),
                warn: rgb(210, 153, 34),
                danger: rgb(248, 81, 73),
                ok: rgb(63, 185, 80),
                progress: rgb(88, 166, 255),
                progress_bg: rgb(33, 38, 45),
            },
            Self::RosePine => Palette {
                bg: rgb(25, 23, 36),
                panel: rgb(31, 29, 46),
                panel_focus: rgb(42, 36, 58),
                border: rgb(38, 35, 58),
                border_focus: rgb(196, 167, 231),
                title: rgb(224, 222, 244),
                text: rgb(224, 222, 244),
                muted: rgb(110, 106, 134),
                accent: rgb(235, 188, 186),
                warn: rgb(246, 193, 119),
                danger: rgb(235, 111, 146),
                ok: rgb(49, 116, 143),
                progress: rgb(156, 207, 216),
                progress_bg: rgb(38, 35, 58),
            },
            Self::Gruvbox => Palette {
                bg: rgb(40, 40, 40),
                panel: rgb(50, 48, 47),
                panel_focus: rgb(60, 54, 46),
                border: rgb(80, 73, 69),
                border_focus: rgb(215, 153, 33),
                title: rgb(235, 219, 178),
                text: rgb(213, 196, 161),
                muted: rgb(146, 131, 116),
                accent: rgb(142, 192, 124),
                warn: rgb(250, 189, 47),
                danger: rgb(251, 73, 52),
                ok: rgb(184, 187, 38),
                progress: rgb(131, 165, 152),
                progress_bg: rgb(60, 56, 54),
            },
            Self::TokyoNight => Palette {
                bg: rgb(26, 27, 38),
                panel: rgb(36, 40, 59),
                panel_focus: rgb(42, 48, 74),
                border: rgb(65, 72, 104),
                border_focus: rgb(122, 162, 247),
                title: rgb(192, 202, 245),
                text: rgb(169, 177, 214),
                muted: rgb(86, 95, 137),
                accent: rgb(125, 207, 255),
                warn: rgb(224, 175, 104),
                danger: rgb(247, 118, 142),
                ok: rgb(158, 206, 106),
                progress: rgb(122, 162, 247),
                progress_bg: rgb(41, 46, 66),
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub bg: Color,
    pub panel: Color,
    /// Elevated fill for the currently active panel (static highlight, not animated).
    pub panel_focus: Color,
    pub border: Color,
    pub border_focus: Color,
    pub title: Color,
    pub text: Color,
    pub muted: Color,
    pub accent: Color,
    pub warn: Color,
    pub danger: Color,
    pub ok: Color,
    pub progress: Color,
    pub progress_bg: Color,
}

impl Palette {
    pub fn panel_border(self, focused: bool) -> Style {
        Style::default().fg(if focused {
            self.border_focus
        } else {
            self.border
        })
    }

    pub fn panel_fill(self, focused: bool) -> Color {
        if focused {
            self.panel_focus
        } else {
            self.panel
        }
    }

    pub fn title_style(self) -> Style {
        Style::default()
            .fg(self.title)
            .add_modifier(Modifier::BOLD)
    }

    pub fn focused_title_style(self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn muted_style(self) -> Style {
        Style::default().fg(self.muted)
    }

    pub fn accent_style(self) -> Style {
        Style::default().fg(self.accent)
    }

    pub fn selected(self) -> Style {
        Style::default()
            .fg(self.bg)
            .bg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn warn_style(self) -> Style {
        Style::default().fg(self.warn)
    }

    pub fn ok_style(self) -> Style {
        Style::default().fg(self.ok)
    }

    pub fn danger_style(self) -> Style {
        Style::default().fg(self.danger)
    }

    pub fn text_style(self) -> Style {
        Style::default().fg(self.text)
    }
}

const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::Rgb(r, g, b)
}
