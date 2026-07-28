# Scry

A modular terminal UI for OSINT investigations. Scry takes newline-separated indicators (emails (coming soon), IPs, domains, JA4 fingerprints (TBD), hashes), routes them to selected vendors with personal or enterprise rate-limit profiles, and exports results as CSV and/or raw JSON dumps.

<video src="https://github.com/user-attachments/assets/b62d78df-a322-47dc-a3ee-b68a43d076fb" controls playsinline width="100%">
  Your browser does not support the video tag.
  <a href="demo/demonstration.mp4">Download the demo</a>
</video>

## Installation

**Requirements:** a recent [Rust](https://rustup.rs/) toolchain (`rustc` / `cargo`).

```bash
git clone https://github.com/BurritoSuicide/Scry.git
cd Scry
cargo run --release
```

If you're on Github Codespaces:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
cargo run --release
```

> **Note:** rustc 1.97.1 can SIGSEGV during aggressive release codegen. Scry's release profile uses `opt-level = 1` and disables LTO; `.cargo/config.toml` raises `RUST_MIN_STACK` so `cargo build --release` succeeds on that toolchain.

To install the binary onto your `PATH`:

```bash
cargo install --path .
scry
```

Config and cached API keys live at `~/.config/scry/config.toml`. The watch list is `~/.config/scry/watchlist.txt`. Investigation output defaults to `~/scry-output`. Legacy `~/.config/imbas/` or `~/.config/charon/` configs are migrated automatically on first launch.

## Headless mode

Run investigations without the TUI (uses the same config, keys, and rate profiles):

```bash
scry run -i indicators.txt
scry run -i indicators.txt -o ~/scry-output --format both --verbosity normal
scry run --watchlist
scry run -i indicators.txt --vendors virustotal,abuseipdb --no-normalize
scry run -i indicators.txt --watch --watch-interval 5
```

| Flag | Meaning |
|------|---------|
| `-i` / `--input` | Indicator file |
| `--watchlist` | Use `~/.config/scry/watchlist.txt` |
| `-o` / `--output` | Output directory |
| `--format` | `csv`, `raw`, or `both` (default) |
| `--verbosity` | `quiet`, `normal`, or `verbose` |
| `--vendors` | Comma-separated vendor ids for this run |
| `--normalize` / `--no-normalize` | Override config normalize & dedup |
| `--watch` | Re-run when the input file’s mtime changes |

`scry` with no subcommand still launches the TUI.

## Tools utilized in tandem

| Tool | Role |
|------|------|
| [Ratatui](https://github.com/ratatui/ratatui) | Terminal UI layout, widgets, and rendering |
| [TachyonFX](https://github.com/ratatui/tachyonfx) | Panel fade-ins, gradient borders, progress shimmer |
| [Crossterm](https://github.com/crossterm-rs/crossterm) | Terminal backend, input, and alternate screen |
| [Tokio](https://tokio.rs/) | Async runtime for concurrent vendor lookups |
| [Reqwest](https://github.com/seanmonstar/reqwest) | HTTPS client for vendor APIs (rustls) |
| [Clap](https://github.com/clap-rs/clap) | Headless CLI (`scry run`) |
| Serde / TOML / CSV | Config persistence and result export |
| [Arboard](https://github.com/1Password/arboard) | Clipboard copy from the output viewer |
| [SecKC-MHN-Globe](https://github.com/n0xa/SecKC-MHN-Globe) | Earth bitmap + orthographic globe projection (BSD-2-Clause); geocode via SecKC MHN API |

## Vendors supported

| Vendor | Indicator types | Notes |
|--------|-----------------|-------|
| **VirusTotal** | hash, IP, domain, email | Multi-engine reputation and malware analysis |
| **abuse.ch** | hash, domain, IP | MalwareBazaar · URLhaus · ThreatFox · Feodo (one Auth-Key) |
| **Hybrid Analysis** | hash, domain, IP | Falcon Sandbox reports and host/domain search |
| **AbuseIPDB** | IP | Abuse confidence, ISP, and country |
| **GreyNoise** | IP | Scanner noise vs RIOT / community context |
| **AlienVault OTX** | IP, domain, hash | Pulses and community threat intel |

Additional vendors plug in via the `OsintVendor` trait under `src/vendors/`.

## Main menu

| Option | What it does |
|--------|----------------|
| **Investigate** | Pick an input file (or `w` for the watch list), review detected types and vendor fit, choose output format/verbosity, then watch live progress with a threat-mix chart and intel tags |
| **View Output** | Browse `~/scry-output`; open CSV as a table or raw text; copy CSV/text (`c`), markdown (`m`), or the current row (`y` / `Y`) |
| **Edit Input** | Create or edit newline-separated indicator files (Ctrl+V paste, Ctrl+N normalize/dedup, Ctrl+D delete line, Ctrl+S save) |
| **API Keys** | Manage cached keys per vendor |
| **Vendors** | Checkbox select; press `b` to bulk-enable every vendor that supports a given indicator type |
| **Watch List** | Edit the persistent watch list; Ctrl+I runs an investigation against it |
| **World Map** | Plot IPs on a rotating 3D ASCII globe or static 2D map; load from last investigation, an input file, or an output file (`Tab` / `m` toggles views) |
| **Options** | Usage profile, color scheme, normalize & dedup toggle, and per-vendor rate-limit overrides |
| **Quit** | Exit Scry |

Normalize & dedup (on by default) refangs common defanging (`hxxp`, `[.]`), strips URL schemes/paths to hosts, and drops duplicate indicators when loading files for investigation.

## License

MIT
