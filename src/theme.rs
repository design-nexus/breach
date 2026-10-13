use ratatui::style::{Color, Modifier, Style};

#[path = "theme/palette.rs"]
#[allow(dead_code, unused_imports)]
mod palette;
use std::cell::RefCell;
thread_local! { static ACTIVE: RefCell<(String, palette::Theme)> = RefCell::new(("crimson".into(), palette::crimson())); }
pub fn set(id: &str) {
    let om = if id == "omarchy" {
        palette::find_omarchy().map(|(_, t, _)| t)
    } else {
        None
    };
    ACTIVE.with(|a| *a.borrow_mut() = (id.into(), palette::resolve(id, om.as_ref())));
}
pub fn refresh() {
    let id = ACTIVE.with(|a| a.borrow().0.clone());
    if id == "omarchy" {
        set(&id);
    }
}
pub fn bg() -> Style {
    Style::default().bg(bg_color()).fg(fg())
}

pub fn title() -> Style {
    Style::default().fg(purple()).add_modifier(Modifier::BOLD)
}

pub fn accent() -> Style {
    Style::default().fg(pink()).add_modifier(Modifier::BOLD)
}

pub fn muted() -> Style {
    Style::default().fg(muted_color())
}

pub fn selected() -> Style {
    ACTIVE.with(|a| a.borrow().1.selected().add_modifier(Modifier::BOLD))
}

pub fn ok() -> Style {
    Style::default().fg(green())
}

pub fn warn() -> Style {
    Style::default().fg(orange())
}

pub fn err() -> Style {
    Style::default().fg(red())
}

pub fn ip() -> Style {
    Style::default().fg(cyan())
}

pub fn hostname() -> Style {
    Style::default().fg(yellow())
}

pub fn flag() -> Style {
    Style::default().fg(pink())
}

pub fn script() -> Style {
    Style::default().fg(purple())
}

pub fn rank_style(rank: &str) -> Style {
    match rank.to_ascii_lowercase().as_str() {
        "excellent" => Style::default().fg(green()).add_modifier(Modifier::BOLD),
        "great" => Style::default().fg(green()),
        "good" => Style::default().fg(cyan()),
        "normal" => Style::default().fg(yellow()),
        "average" => Style::default().fg(orange()),
        "low" | "manual" => Style::default().fg(red()),
        _ => Style::default().fg(fg()),
    }
}

pub fn pane_border(focused: bool) -> Style {
    if focused {
        Style::default().fg(pink())
    } else {
        Style::default().fg(comment())
    }
}

pub fn bg_color() -> Color {
    ACTIVE.with(|a| a.borrow().1.bg)
}

pub fn current() -> Color {
    ACTIVE.with(|a| a.borrow().1.bg_raised)
}

pub fn deep() -> Color {
    ACTIVE.with(|a| a.borrow().1.bg_deep)
}

pub fn fg() -> Color {
    ACTIVE.with(|a| a.borrow().1.fg)
}

pub fn comment() -> Color {
    ACTIVE.with(|a| a.borrow().1.border)
}

pub fn cyan() -> Color {
    ACTIVE.with(|a| a.borrow().1.cyan)
}

pub fn green() -> Color {
    ACTIVE.with(|a| a.borrow().1.green)
}

pub fn orange() -> Color {
    ACTIVE.with(|a| a.borrow().1.yellow)
}

pub fn pink() -> Color {
    ACTIVE.with(|a| a.borrow().1.accent)
}

pub fn purple() -> Color {
    ACTIVE.with(|a| a.borrow().1.accent)
}

pub fn red() -> Color {
    ACTIVE.with(|a| a.borrow().1.red)
}

pub fn yellow() -> Color {
    ACTIVE.with(|a| a.borrow().1.yellow)
}

pub fn muted_color() -> Color {
    ACTIVE.with(|a| a.borrow().1.muted)
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    #[test]
    fn theme_save_keeps_existing_settings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "theme = \"dracula\"\nhost = \"localhost\"\n").unwrap();
        set(&crate::persist::load_config(&path).theme);
        assert_eq!(bg_color(), Color::Rgb(0x28, 0x2a, 0x36));
        let mut config = crate::persist::load_config(&path);
        config.theme = "terminal".into();
        crate::persist::save_config(&path, &config).unwrap();
        set(&crate::persist::load_config(&path).theme);
        assert_eq!(bg_color(), Color::Reset);
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.contains("localhost"));
        set("aurora");
        assert_eq!(bg_color(), Color::Rgb(0x17, 0x18, 0x20));
    }
}

#[cfg(test)]
mod security_theme_persistence {
    use super::*;
    #[test]
    fn default_and_explicit_theme_choices_survive_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        set(&crate::persist::load_config(&path).theme);
        assert_eq!(bg_color(), palette::hex("0b0d10"));
        for id in ["aurora", "crimson", "terminal", "omarchy"] {
            let mut config = crate::persist::load_config(&path);
            config.theme = id.into();
            crate::persist::save_config(&path, &config).unwrap();
            set(&crate::persist::load_config(&path).theme);
            let saved: toml::Value =
                toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(saved.get("theme").unwrap().as_str(), Some(id));
            if id == "aurora" {
                assert_eq!(bg_color(), palette::hex("171820"));
            }
            if id == "crimson" {
                assert_eq!(selected().bg, Some(palette::hex("211218")));
                assert_eq!(selected().fg, Some(palette::hex("cf6578")));
            }
        }
        std::fs::write(&path, "host = \"localhost\"\n").unwrap();
        set(&crate::persist::load_config(&path).theme);
        assert_eq!(bg_color(), palette::hex("0b0d10"));
    }
}
