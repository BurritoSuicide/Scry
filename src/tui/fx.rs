//! TachyonFX-powered transitions and ambient panel animations.

use crate::app::Screen;
use crate::theme::{ColorScheme, Palette};
use ratatui::layout::{Margin, Position, Rect};
use ratatui::style::Color;
use ratatui::Frame;
use std::time::Instant;
use tachyonfx::pattern::SweepPattern;
use tachyonfx::{
    fx, CellFilter, Effect, EffectManager, Interpolatable, Interpolation, Motion, RefRect,
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FxKey {
    #[default]
    ScreenIn,
    FocusBorder,
    ProgressPulse,
}

/// Layout regions effects need after each draw pass.
#[derive(Debug, Clone, Copy, Default)]
pub struct FxAreas {
    pub header: Rect,
    pub progress: Rect,
    pub body: Rect,
    pub left: Rect,
    /// Main-menu panel only (excludes the threat chart under it).
    pub menu: Rect,
    pub center: Rect,
    pub right: Rect,
    /// Currently focused panel (gradient border + window fade target).
    pub focus: Rect,
    pub full_width_body: bool,
}

pub struct FxEngine {
    manager: EffectManager<FxKey>,
    last_frame: Instant,
    last_screen: Option<Screen>,
    last_scheme: Option<ColorScheme>,
    last_focus: Rect,
    last_progress_active: bool,
    focus_rect: RefRect,
    progress_rect: RefRect,
    bootstrapped: bool,
}

impl Default for FxEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FxEngine {
    pub fn new() -> Self {
        Self {
            manager: EffectManager::default(),
            last_frame: Instant::now(),
            last_screen: None,
            last_scheme: None,
            last_focus: Rect::default(),
            last_progress_active: false,
            focus_rect: RefRect::new(Rect::default()),
            progress_rect: RefRect::new(Rect::default()),
            bootstrapped: false,
        }
    }

    /// Call after widgets are rendered so effects can transform the buffer.
    pub fn process(
        &mut self,
        frame: &mut Frame<'_>,
        areas: FxAreas,
        screen: Screen,
        scheme: ColorScheme,
        theme: Palette,
        progress_active: bool,
    ) {
        self.focus_rect.set(areas.focus);
        self.progress_rect.set(areas.progress);

        let screen_changed = self.last_screen != Some(screen);
        let scheme_changed = self.last_scheme != Some(scheme);
        let focus_changed = self.last_focus != areas.focus;
        let progress_changed = self.last_progress_active != progress_active;

        if !self.bootstrapped {
            // Full chrome fade once at launch.
            self.queue_startup_enter(areas, theme);
            self.queue_focus_border_gradient(theme);
            self.queue_progress_effect(theme, progress_active);
            self.bootstrapped = true;
        } else {
            if screen_changed {
                // Only the newly active window fades in on navigation.
                if !areas.focus.is_empty() {
                    self.queue_active_window_enter(areas.focus, theme);
                }
                self.queue_focus_border_gradient(theme);
            } else if focus_changed || scheme_changed {
                self.queue_focus_border_gradient(theme);
            }

            if progress_changed || scheme_changed {
                self.queue_progress_effect(theme, progress_active);
            }
        }

        self.last_screen = Some(screen);
        self.last_scheme = Some(scheme);
        self.last_focus = areas.focus;
        self.last_progress_active = progress_active;

        let elapsed = self.last_frame.elapsed();
        self.last_frame = Instant::now();
        let screen_area = frame.area();
        self.manager
            .process_effects(elapsed, frame.buffer_mut(), screen_area);
    }

    fn queue_startup_enter(&mut self, areas: FxAreas, theme: Palette) {
        let mut parts: Vec<Effect> = Vec::new();

        if !areas.header.is_empty() {
            parts.push(fx::delay(
                0,
                panel_enter(theme, areas.header, Motion::UpToDown, 10),
            ));
        }
        if !areas.progress.is_empty() {
            parts.push(fx::delay(
                40,
                panel_enter(theme, areas.progress, Motion::LeftToRight, 18),
            ));
        }

        if areas.full_width_body {
            if !areas.center.is_empty() {
                parts.push(fx::delay(
                    80,
                    panel_enter(theme, areas.center, Motion::LeftToRight, 14),
                ));
            }
        } else {
            if !areas.left.is_empty() {
                parts.push(fx::delay(
                    60,
                    panel_enter(theme, areas.left, Motion::LeftToRight, 12),
                ));
            }
            if !areas.center.is_empty() {
                parts.push(fx::delay(
                    120,
                    panel_enter(theme, areas.center, Motion::UpToDown, 10),
                ));
            }
            if !areas.right.is_empty() {
                parts.push(fx::delay(
                    180,
                    panel_enter(theme, areas.right, Motion::RightToLeft, 12),
                ));
            }
        }

        if parts.is_empty() {
            return;
        }

        self.manager
            .add_unique_effect(FxKey::ScreenIn, fx::parallel(&parts));
    }

    fn queue_active_window_enter(&mut self, area: Rect, theme: Palette) {
        self.manager.add_unique_effect(
            FxKey::ScreenIn,
            panel_enter(theme, area, Motion::LeftToRight, 14),
        );
    }

    fn queue_focus_border_gradient(&mut self, theme: Palette) {
        let stops = [
            theme.border_focus,
            theme.accent,
            theme.title,
            theme.border_focus,
        ];

        let gradient = fx::never_complete(fx::effect_fn(
            Instant::now(),
            1_000,
            move |started, ctx, cells| {
                let area = ctx.area;
                if area.width < 2 || area.height < 2 {
                    return;
                }
                let phase = (started.elapsed().as_millis() as f32) / 2_200.0;
                for (pos, cell) in cells {
                    let t = (perimeter_t(area, pos) + phase).rem_euclid(1.0);
                    cell.set_fg(sample_gradient(&stops, t));
                }
            },
        ))
        .with_filter(CellFilter::Outer(Margin::new(1, 1)));

        let wrapped = fx::dynamic_area(self.focus_rect.clone(), gradient);
        self.manager
            .add_unique_effect(FxKey::FocusBorder, wrapped);
    }

    fn queue_progress_effect(&mut self, theme: Palette, active: bool) {
        // Continuous phase-based shimmer (never snaps): wave rises to a peak and
        // returns to the cell's resting shade, same idea as the border gradient loop.
        // Important: do NOT filter on FgColor — mutating fg would desync the filter
        // and make the animation stop after one pass.
        let progress = theme.progress;
        let progress_bg = theme.progress_bg;
        let accent = theme.accent;
        let highlight = if active {
            accent.lerp(&theme.title, 0.35)
        } else {
            progress_bg.lerp(&theme.muted, 0.55)
        };

        let shimmer = fx::never_complete(fx::effect_fn(
            Instant::now(),
            1_000,
            move |started, ctx, cells| {
                let area = ctx.area;
                let width = area.width.max(1) as f32;
                let phase = (started.elapsed().as_millis() as f32)
                    / if active { 1_800.0 } else { 2_600.0 };

                for (pos, cell) in cells {
                    let rest = match cell.symbol().chars().next() {
                        Some('█') => progress,
                        Some('▓') => accent,
                        _ => progress_bg,
                    };
                    let x = pos.x.saturating_sub(area.x) as f32 / width;
                    // Smooth triangle 0→1→0 so each cycle lands back on `rest`.
                    let t = (x * 0.65 + phase).rem_euclid(1.0);
                    let wave = if t < 0.5 { t * 2.0 } else { (1.0 - t) * 2.0 };
                    let strength = if active { 0.9 } else { 0.7 };
                    cell.set_fg(rest.lerp(&highlight, wave * strength));
                }
            },
        ))
        .with_filter(CellFilter::Inner(Margin::new(1, 1)));

        let wrapped = fx::dynamic_area(self.progress_rect.clone(), shimmer);
        self.manager
            .add_unique_effect(FxKey::ProgressPulse, wrapped);
    }
}

fn panel_enter(theme: Palette, area: Rect, motion: Motion, gradient: u16) -> Effect {
    let pattern = match motion {
        Motion::LeftToRight => SweepPattern::left_to_right(gradient),
        Motion::RightToLeft => SweepPattern::right_to_left(gradient),
        Motion::UpToDown => SweepPattern::up_to_down(gradient),
        Motion::DownToUp => SweepPattern::down_to_up(gradient),
    };

    fx::parallel(&[
        fx::fade_from(theme.bg, theme.bg, (460, Interpolation::CubicOut)).with_pattern(pattern),
        fx::coalesce((340, Interpolation::QuadOut)),
    ])
    .with_area(area)
}

/// Clockwise perimeter parameter in `[0, 1)`, starting at the top-left corner.
fn perimeter_t(area: Rect, pos: Position) -> f32 {
    let w = area.width.saturating_sub(1) as f32;
    let h = area.height.saturating_sub(1) as f32;
    let peri = 2.0 * (w + h);
    if peri <= 0.0 {
        return 0.0;
    }

    let x = pos.x.saturating_sub(area.x) as f32;
    let y = pos.y.saturating_sub(area.y) as f32;

    let dist = if y <= 0.0 {
        x.clamp(0.0, w)
    } else if x >= w {
        w + y.clamp(0.0, h)
    } else if y >= h {
        w + h + (w - x.clamp(0.0, w))
    } else {
        w + h + w + (h - y.clamp(0.0, h))
    };

    dist / peri
}

fn sample_gradient(stops: &[Color], t: f32) -> Color {
    let n = stops.len();
    if n == 0 {
        return Color::Reset;
    }
    if n == 1 {
        return stops[0];
    }

    let scaled = t.rem_euclid(1.0) * (n as f32 - 1.0);
    let i = scaled.floor() as usize;
    let next = (i + 1).min(n - 1);
    let local = scaled - i as f32;
    stops[i].lerp(&stops[next], local)
}

/// Which panel should receive the ambient focus animation.
pub fn focus_area_for(screen: Screen, areas: &FxAreas) -> Rect {
    match screen {
        Screen::MainMenu => {
            if areas.menu.width > 0 {
                areas.menu
            } else {
                areas.left
            }
        }
        _ => areas.center,
    }
}
