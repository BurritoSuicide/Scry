# Scry

A modular terminal UI for OSINT investigations. Scry takes newline-separated indicators (emails (coming soon), IPs, domains, JA4 fingerprints (TBD), hashes), routes them to selected vendors with personal or enterprise rate-limit profiles, and exports results as CSV and/or raw JSON dumps.

<video src="demo/demonstration.mp4" width="320" height="240" controls></video>

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

Config and cached API keys live at `~/.config/scry/config.toml`. Investigation output defaults to `~/scry-output`. Legacy `~/.config/imbas/` or `~/.config/charon/` configs are migrated automatically on first launch.

## Tools utilized in tandem

| Tool | Role |
|------|------|
| [Ratatui](https://github.com/ratatui/ratatui) | Terminal UI layout, widgets, and rendering |
| [TachyonFX](https://github.com/ratatui/tachyonfx) | Panel fade-ins, gradient borders, progress shimmer |
| [Crossterm](https://github.com/crossterm-rs/crossterm) | Terminal backend, input, and alternate screen |
| [Tokio](https://tokio.rs/) | Async runtime for concurrent vendor lookups |
| [Reqwest](https://github.com/seanmonstar/reqwest) | HTTPS client for vendor APIs (rustls) |
| Serde / TOML / CSV | Config persistence and result export |
| [Arboard](https://github.com/1Password/arboard) | Clipboard copy from the output viewer |

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
| **Run OSINT Investigation** | Pick an input file, review detected indicator types and vendor fit, choose output format/verbosity, then watch live progress with a threat-mix chart and intel tags |
| **View Output** | Browse `~/scry-output`; open CSV as a table or raw text; copy CSV/text (`c`), markdown (`m`), or the current row (`y` / `Y`) |
| **Add / Edit Input** | Create or edit newline-separated indicator files (Ctrl+V paste, Ctrl+D delete line, Ctrl+S save) |
| **Add / Remove / Change API Key** | Manage cached keys per vendor |
| **List / Select Vendors** | Checkbox select; press `b` to bulk-enable every vendor that supports a given indicator type |
| **Usage Profile** | Personal (free/community, default) or Enterprise (paid/premium pacing) |
| **Options** | Manually override per-vendor rate limits (with warnings) |
| **Color Scheme** | Pick a TUI theme |
| **Quit** | Exit Scry |

## License

MIT
