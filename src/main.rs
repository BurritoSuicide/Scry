use anyhow::Context;
use clap::Parser;
use scry::app::App;
use scry::cli::{Cli, Commands};
use scry::config::Config;
use scry::tui::{self, event::EventSource};
use crossterm::event::{
    DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::stdout;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load().context("failed to load Scry config")?;

    if let Some(Commands::Run(args)) = cli.command {
        return scry::cli::run_headless(config, args).await;
    }

    let mut app = App::new(config);

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // ~30 fps keeps tachyonfx fades / pulses smooth without burning CPU.
    let events = EventSource::new(Duration::from_millis(33));
    let run_result = tui::run(&mut terminal, &mut app, &events).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
        DisableBracketedPaste
    )?;
    terminal.show_cursor()?;

    if let Err(err) = run_result {
        eprintln!("Scry exited with error: {err:#}");
        return Err(err);
    }

    // Persist any config changes made during the session.
    app.config.save().context("failed to save Scry config")?;
    Ok(())
}
