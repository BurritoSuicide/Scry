//! Headless CLI: `scry run` without the TUI.

use crate::config::{Config, OutputFormat, Verbosity};
use crate::investigation::{run_investigation, InvestigationRequest, LiveEvent};
use crate::vendors::all_vendors;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;

#[derive(Debug, Parser)]
#[command(
    name = "scry",
    about = "Scry — modular OSINT investigation TUI (and headless runner)",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run an investigation without the TUI
    Run(RunArgs),
}

#[derive(Debug, Clone, ValueEnum)]
pub enum CliFormat {
    Csv,
    Raw,
    Both,
}

impl From<CliFormat> for OutputFormat {
    fn from(value: CliFormat) -> Self {
        match value {
            CliFormat::Csv => OutputFormat::Csv,
            CliFormat::Raw => OutputFormat::RawTxt,
            CliFormat::Both => OutputFormat::Both,
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
pub enum CliVerbosity {
    Quiet,
    Normal,
    Verbose,
}

impl From<CliVerbosity> for Verbosity {
    fn from(value: CliVerbosity) -> Self {
        match value {
            CliVerbosity::Quiet => Verbosity::Quiet,
            CliVerbosity::Normal => Verbosity::Normal,
            CliVerbosity::Verbose => Verbosity::Verbose,
        }
    }
}

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Input indicator file (newline-separated)
    #[arg(short, long, value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// Use ~/.config/scry/watchlist.txt as input
    #[arg(long)]
    pub watchlist: bool,

    /// Output directory (default: ~/scry-output)
    #[arg(short, long, value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = CliFormat::Both)]
    pub format: CliFormat,

    /// Result verbosity
    #[arg(long, value_enum, default_value_t = CliVerbosity::Normal)]
    pub verbosity: CliVerbosity,

    /// Comma-separated vendor ids (overrides config selection for this run)
    #[arg(long, value_name = "IDS")]
    pub vendors: Option<String>,

    /// Enable normalize & dedup for this run
    #[arg(long, default_value_t = false)]
    pub normalize: bool,

    /// Disable normalize & dedup for this run
    #[arg(long, default_value_t = false)]
    pub no_normalize: bool,

    /// Re-run when the input file changes (poll mtime)
    #[arg(long, default_value_t = false)]
    pub watch: bool,

    /// Watch poll interval in seconds (with --watch)
    #[arg(long, default_value_t = 2)]
    pub watch_interval: u64,
}

pub async fn run_headless(mut config: Config, args: RunArgs) -> Result<()> {
    if args.normalize && args.no_normalize {
        bail!("cannot combine --normalize and --no-normalize");
    }
    if args.normalize {
        config.normalize_inputs = true;
    } else if args.no_normalize {
        config.normalize_inputs = false;
    }

    if let Some(list) = &args.vendors {
        config.selected_vendors.clear();
        for id in list.split(',') {
            let id = id.trim();
            if id.is_empty() {
                continue;
            }
            if !all_vendors().iter().any(|v| v.id() == id) {
                let known: Vec<_> = all_vendors().iter().map(|v| v.id()).collect();
                bail!("unknown vendor `{id}` (known: {})", known.join(", "));
            }
            config.selected_vendors.insert(id.to_string());
        }
        if config.selected_vendors.is_empty() {
            bail!("--vendors produced an empty selection");
        }
    }

    let input = resolve_input(&args)?;
    let output_dir = args.output.clone().unwrap_or_else(default_output_dir);

    if args.watch {
        eprintln!(
            "scry: watching {} (interval {}s) · Ctrl+C to stop",
            input.display(),
            args.watch_interval
        );
        let mut last_mtime = file_mtime(&input).ok();
        // Run once immediately.
        run_once(&config, &input, &output_dir, &args).await?;
        loop {
            tokio::time::sleep(Duration::from_secs(args.watch_interval.max(1))).await;
            let mtime = match file_mtime(&input) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("scry: watch read error: {e}");
                    continue;
                }
            };
            if last_mtime.map(|t| mtime > t).unwrap_or(true) {
                last_mtime = Some(mtime);
                eprintln!("scry: change detected — re-running");
                if let Err(e) = run_once(&config, &input, &output_dir, &args).await {
                    eprintln!("scry: run failed: {e:#}");
                }
            }
        }
    } else {
        run_once(&config, &input, &output_dir, &args).await
    }
}

fn resolve_input(args: &RunArgs) -> Result<PathBuf> {
    if args.watchlist {
        if args.input.is_some() {
            bail!("use either --input or --watchlist, not both");
        }
        return Config::ensure_watchlist().context("watch list");
    }
    let path = args
        .input
        .clone()
        .context("provide --input FILE or --watchlist")?;
    if !path.is_file() {
        bail!("input file not found: {}", path.display());
    }
    Ok(path)
}

fn default_output_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join("scry-output"))
        .unwrap_or_else(|| PathBuf::from("./scry-output"))
}

fn file_mtime(path: &PathBuf) -> Result<SystemTime> {
    Ok(std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .modified()?)
}

async fn run_once(
    config: &Config,
    input: &PathBuf,
    output_dir: &PathBuf,
    args: &RunArgs,
) -> Result<()> {
    let request = InvestigationRequest {
        input_path: input.clone(),
        output_dir: output_dir.clone(),
        format: args.format.clone().into(),
        verbosity: args.verbosity.clone().into(),
    };

    eprintln!(
        "scry: investigating {} → {} ({:?}, {:?}, normalize={})",
        input.display(),
        output_dir.display(),
        request.format,
        request.verbosity,
        config.normalize_inputs
    );

    let (tx, mut rx) = mpsc::unbounded_channel();
    let cfg = config.clone();
    let handle = tokio::spawn(async move {
        run_investigation(cfg, request, tx).await;
    });

    let mut finished_ok = false;
    while let Some(event) = rx.recv().await {
        match event {
            LiveEvent::Warning(w) => eprintln!("warn: {w}"),
            LiveEvent::Progress(p) => {
                eprint!(
                    "\rprogress: {}/{}        ",
                    p.completed_queries, p.total_queries
                );
            }
            LiveEvent::ResultHit { line, .. } => {
                eprintln!();
                println!("{line}");
            }
            LiveEvent::Finished {
                output_paths,
                results,
            } => {
                eprintln!();
                eprintln!("scry: complete — {results} result(s)");
                for path in output_paths {
                    eprintln!("  wrote {}", path.display());
                }
                finished_ok = true;
            }
            LiveEvent::Failed(err) => {
                eprintln!();
                bail!("investigation failed: {err}");
            }
        }
    }
    handle.await.context("investigation task join")?;
    if !finished_ok {
        bail!("investigation ended without a Finished event");
    }
    Ok(())
}
