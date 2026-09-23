//! TUI Widget helpers - Reusable styled components for RustCrash TUI
//!
//! Inspired by ShellCrash's tui_layout.sh which uses TABLE_WIDTH=60 and
//! provides consistent styling for all menu/table/dialog components.

use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, BorderType, Paragraph},
    layout::Alignment,
};

// ---------------------------------------------------------------------------
// Constants (matching ShellCrash TABLE_WIDTH=60)
// ---------------------------------------------------------------------------

pub const TABLE_WIDTH: u16 = 60;
pub const ACCENT_COLOR: Color = Color::Rgb(200, 160, 60);   // Gold
pub const BG_COLOR: Color = Color::Rgb(15, 15, 26);          // Dark background
pub const TEXT_COLOR: Color = Color::Rgb(200, 200, 220);   // Light text
pub const DIM_COLOR: Color = Color::Rgb(80, 80, 120);      // Dim text
pub const SUCCESS_COLOR: Color = Color::Rgb(80, 200, 120); // Green
pub const ERROR_COLOR: Color = Color::Rgb(220, 80, 80);     // Red
pub const INFO_COLOR: Color = Color::Rgb(80, 160, 220);     // Blue
pub const WARN_COLOR: Color = Color::Rgb(220, 180, 60);    // Yellow

// ---------------------------------------------------------------------------
// Style helpers
// ---------------------------------------------------------------------------

pub fn title_style() -> Style {
    Style::default()
        .fg(ACCENT_COLOR)
        .add_modifier(Modifier::BOLD)
}

pub fn selected_style() -> Style {
    Style::default()
        .fg(BG_COLOR)
        .bg(ACCENT_COLOR)
        .add_modifier(Modifier::BOLD)
}

pub fn normal_style() -> Style {
    Style::default().fg(TEXT_COLOR)
}

pub fn dim_style() -> Style {
    Style::default().fg(DIM_COLOR)
}

pub fn success_style() -> Style {
    Style::default().fg(SUCCESS_COLOR)
}

pub fn error_style() -> Style {
    Style::default().fg(ERROR_COLOR)
}

// ---------------------------------------------------------------------------
// Box drawing helpers (ASCII, matching ShellCrash's look)
// ---------------------------------------------------------------------------

/// Draw a horizontal separator line
pub fn hline(width: u16) -> String {
    "─".repeat(width as usize)
}

/// Build a box title line like: ┌─ Title ─┐
pub fn box_title(title: &str, width: u16) -> String {
    let title_len = title.len() as u16;
    let remaining = if title_len + 4 >= width { 0 } else { width - title_len - 4 };
    let left = remaining / 2;
    let right = remaining - left;
    format!("{}{}{}{}{}",
        "┌─ ", title, " ",
        "─".repeat(right as usize),
        "─┐")
}

// ---------------------------------------------------------------------------
// Paragraph builders
// ---------------------------------------------------------------------------

pub fn centered_para<'a>(text: &'a str, style: Style) -> Paragraph<'a> {
    Paragraph::new(text)
        .style(style)
        .alignment(Alignment::Center)
}

pub fn left_para<'a>(text: &'a str, style: Style) -> Paragraph<'a> {
    Paragraph::new(text)
        .style(style)
        .alignment(Alignment::Left)
}

// ---------------------------------------------------------------------------
// Confirm dialog
// ---------------------------------------------------------------------------

pub fn confirm_dialog(title: &str, message: &str) -> (String, Style) {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(message, normal_style())),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("[Y] Yes  ", success_style().add_modifier(Modifier::BOLD)),
            Span::styled("[N] No   ", error_style().add_modifier(Modifier::BOLD)),
            Span::raw("  "),
        ]),
        Line::from(""),
    ];
    (lines.join("\n"), Style::default())
}

// ---------------------------------------------------------------------------
// Progress bar
// ---------------------------------------------------------------------------

pub fn progress_bar_style(fraction: f32) -> Style {
    if fraction < 0.5 {
        Style::default().fg(INFO_COLOR)
    } else if fraction < 0.8 {
        Style::default().fg(WARN_COLOR)
    } else {
        Style::default().fg(SUCCESS_COLOR)
    }
}
