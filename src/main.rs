mod app;
#[cfg(test)]
mod audit;
mod aurora;
mod catalog;
mod chains;
mod commands;
mod demo;
mod input;
mod macros;
mod match_plan;
mod model;
mod navigation;
mod persist;
mod reports;
mod rpc;
mod theme;
mod ui;
mod venom;
mod workflow;

use crate::app::{App, Tab};
use clap::Parser;
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures::StreamExt;
use ratatui::style::{Color, Modifier};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "breach",
    version,
    about = "breach — Aurora TUI frontend for Metasploit Framework",
    after_help = "Only use against systems you own or have permission to test.\n\
                  Set NEXUS_MSF_RPC_PASS or config.toml password before connecting."
)]
struct Cli {
    /// Disable terminal mouse capture
    #[arg(long)]
    no_mouse: bool,
    /// Walk the UI with sample data (no RPC)
    #[arg(long)]
    demo: bool,
    /// RPC host (default from config, 127.0.0.1)
    #[arg(long)]
    host: Option<String>,
    /// RPC port
    #[arg(long)]
    port: Option<u16>,
    /// Disable SSL
    #[arg(long)]
    no_ssl: bool,
    /// Render demo UI to a PNG (uses ImageMagick `convert`)
    #[arg(long, hide = true)]
    screenshot: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut app = App::new(cli.demo || cli.screenshot.is_some())?;
    if let Some(h) = cli.host {
        app.config.host = h;
    }
    if let Some(p) = cli.port {
        app.config.port = p;
    }
    if cli.no_ssl {
        app.config.ssl = false;
    }
    if let Some(path) = cli.screenshot {
        app.tab = Tab::Hosts;
        return write_screenshot(&app, &path);
    }
    app.start_rpc();

    let mut terminal = ratatui::init();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::execute!(std::io::stdout(), crossterm::event::DisableMouseCapture);
        previous(info);
    }));

    if !cli.no_mouse {
        crossterm::execute!(std::io::stdout(), crossterm::event::EnableMouseCapture)?;
    }
    let result = run(&mut terminal, &mut app).await;
    let _ = crossterm::execute!(std::io::stdout(), crossterm::event::DisableMouseCapture);
    ratatui::restore();
    app.shutdown_rpc().await;
    result
}

async fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> anyhow::Result<()> {
    let mut events = EventStream::new();
    let mut ticks = tokio::time::interval(Duration::from_millis(200));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let rendered = terminal.draw(|f| ui::draw(f, app))?;
        aurora::paint_wordmark(rendered.buffer)?;
        if app.should_quit {
            break;
        }
        tokio::select! {
            _ = ticks.tick() => {
                app.on_tick().await;
            }
            maybe = events.next() => {
                match maybe {
                    Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                        app.handle_key(key);
                    }
                    Some(Ok(Event::Mouse(mouse)))=>app.navigation_mouse(mouse),
                    Some(Ok(Event::Resize(_, _))) => {}
                    Some(Err(e)) => anyhow::bail!(e),
                    None => break,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn write_screenshot(app: &App, path: &std::path::Path) -> anyhow::Result<()> {
    let backend = ratatui::backend::TestBackend::new(120, 36);
    let mut terminal = ratatui::Terminal::new(backend)?;
    terminal.draw(|f| ui::draw(f, app))?;
    let buf = terminal.backend().buffer();
    let (cw, ch) = (10u32, 20u32);
    let w = buf.area.width as u32 * cw;
    let h = buf.area.height as u32 * ch;
    let mut mvg = format!(
        "push graphic-context\nviewbox 0 0 {w} {h}\nfill '#282a36'\nrectangle 0,0 {w},{h}\nfont 'DejaVu-Sans-Mono'\nfont-size 15\n"
    );
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            let cell = &buf[(x, y)];
            let (br, bg, bb) = rgb(cell.bg, false);
            let px = x as u32 * cw;
            let py = y as u32 * ch;
            if (br, bg, bb) != (0x28, 0x2a, 0x36) {
                mvg.push_str(&format!(
                    "fill '#{br:02x}{bg:02x}{bb:02x}'\nrectangle {px},{py} {},{} \n",
                    px + cw,
                    py + ch
                ));
            }
            let sym = cell.symbol();
            if sym.trim().is_empty()
                && sym != "█"
                && !matches!(
                    sym,
                    "▸" | "▌"
                        | "—"
                        | "│"
                        | "─"
                        | "┌"
                        | "┐"
                        | "└"
                        | "┘"
                        | "├"
                        | "┤"
                        | "┬"
                        | "┴"
                        | "┼"
                        | "║"
                        | "═"
                )
            {
                if sym.chars().all(|c| c == ' ' || c == '\0') {
                    continue;
                }
            }
            if sym.chars().all(|c| c == ' ' || c == '\0') {
                continue;
            }
            let (fr, fg, fb) = rgb(cell.fg, true);
            let escaped = sym.replace('\\', "\\\\").replace('\'', "\\'");
            let ty = py + 15;
            let weight = if cell.modifier.contains(Modifier::BOLD) {
                "bold"
            } else {
                "normal"
            };
            mvg.push_str(&format!(
                "fill '#{fr:02x}{fg:02x}{fb:02x}'\nfont-weight {weight}\ntext {px},{ty} '{escaped}'\n"
            ));
        }
    }
    mvg.push_str("pop graphic-context\n");
    let mvg_path = path.with_extension("mvg");
    std::fs::write(&mvg_path, mvg)?;
    let status = std::process::Command::new("convert")
        .args([
            &format!("mvg:{}", mvg_path.display()),
            path.to_str().unwrap(),
        ])
        .status()?;
    let _ = std::fs::remove_file(&mvg_path);
    anyhow::ensure!(status.success(), "convert failed");
    Ok(())
}

fn rgb(c: Color, fg: bool) -> (u8, u8, u8) {
    match c {
        Color::Reset => {
            if fg {
                (0xf8, 0xf8, 0xf2)
            } else {
                (0x28, 0x2a, 0x36)
            }
        }
        Color::Rgb(r, g, b) => (r, g, b),
        Color::Black => (0x21, 0x22, 0x2c),
        Color::Red => (0xff, 0x55, 0x55),
        Color::Green => (0x50, 0xfa, 0x7b),
        Color::Yellow => (0xf1, 0xfa, 0x8c),
        Color::Blue => (0xbd, 0x93, 0xf9),
        Color::Magenta => (0xff, 0x79, 0xc6),
        Color::Cyan => (0x8b, 0xe9, 0xfd),
        Color::Gray => (0x62, 0x72, 0xa4),
        Color::DarkGray => (0x44, 0x47, 0x5a),
        Color::White => (0xf8, 0xf8, 0xf2),
        Color::LightRed => (0xff, 0x6e, 0x6e),
        Color::LightGreen => (0x69, 0xff, 0x94),
        Color::LightYellow => (0xff, 0xff, 0xa5),
        Color::LightBlue => (0xd6, 0xac, 0xff),
        Color::LightMagenta => (0xff, 0x92, 0xd0),
        Color::LightCyan => (0xa4, 0xff, 0xff),
        Color::Indexed(i) if i == 7 => (0xe6, 0xe6, 0xe6),
        Color::Indexed(i) => match i {
            0 => (0x21, 0x22, 0x2c),
            1 => (0xff, 0x55, 0x55),
            2 => (0x50, 0xfa, 0x7b),
            3 => (0xf1, 0xfa, 0x8c),
            4 => (0xbd, 0x93, 0xf9),
            5 => (0xff, 0x79, 0xc6),
            6 => (0x8b, 0xe9, 0xfd),
            7 => (0xf8, 0xf8, 0xf2),
            _ => {
                if fg {
                    (0xf8, 0xf8, 0xf2)
                } else {
                    (0x28, 0x2a, 0x36)
                }
            }
        },
    }
}
