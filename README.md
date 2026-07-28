# Scry

A modular terminal UI for OSINT investigations — ferry indicators across vendors and see what washes ashore.

Scry ingests newline-separated indicators (emails, IPs, domains, JA4 fingerprints, hashes), routes them to selected vendors, respects per-vendor rate limits (personal vs enterprise profiles), and exports results as CSV or raw JSON dumps.

## Status

Foundation release with **VirusTotal**, **abuse.ch**, **Hybrid Analysis**, **AbuseIPDB**, **GreyNoise**, and **AlienVault OTX**. Additional vendors drop in via the `OsintVendor` trait under `src/vendors/`.

The TUI uses [tachyonfx](https://github.com/ratatui/tachyonfx) for staggered panel fade-ins, a highlighted active panel with an animated gradient border, and a theme-aware progress-bar shimmer.

## Quick start

```bash
cargo run --release
```

Config and cached API keys live at:

```
~/.config/scry/config.toml
```

(Legacy `~/.config/imbas/config.toml` or `~/.config/charon/config.toml` is migrated automatically on first launch.)

## Main menu

- **Run OSINT Investigation** — pick an input file, review auto-detected indicator types + vendor fit, choose output format/verbosity, then watch live progress. A threat-mix bar chart (malicious / suspicious / benign) sits under the main menu; malware families, actors, and pulse tags stream into the **tags / intel** panel.
- **View Output** — browse `~/scry-output`, open CSV as a table (csvlens-style) or raw text; `c` copies CSV/text, `m` copies a markdown table, `y` / `Y` copy the current row (CSV / markdown).
- **Add / Edit Input** — create or edit newline-separated indicator files; paste with Ctrl+V, delete lines with Ctrl+D, save with Ctrl+S.
- **Add / Remove / Change API Key** — manage cached keys per vendor.
- **List / Select Vendors** — checkbox select; press `b` to bulk-select every vendor that supports a given indicator type (IP / domain / hash / …).
- **Usage Profile** — Personal (free/community, default) or Enterprise (paid/premium pacing).
- **Options** — manually override per-vendor rate limits (with warnings).
- **Color Scheme** — TUI themes (each preview fades in via [tachyonfx](https://github.com/ratatui/tachyonfx)).

## Usage profiles & rate limits

| Vendor | Personal (default) | Enterprise |
|--------|--------------------|------------|
| VirusTotal | 4/min · 500/day (public) | unthrottled client (premium SLA) |
| abuse.ch | 30/min fair-use | 120/min |
| Hybrid Analysis | 5/min · 200/hour (restricted key) | 60/min · 2,000/hour |
| AbuseIPDB | 45/min · 1,000/day (standard) | 120/min · 50,000/day (premium) |
| GreyNoise | 10/min · ~7/day (50/week community) | unthrottled client (paid) |
| AlienVault OTX | 30/min · 10,000/hour | 300/min |

Manual overrides in **Options** can raise or lower these, or mark a vendor **unthrottled** (skips Scry client pacing only — vendors may still return HTTP 429).

## Adding a vendor

1. Create `src/vendors/<name>/` implementing `OsintVendor`.
2. Register it in `src/vendors/mod.rs` (`all_vendors()`).
3. Add personal/enterprise presets in `RateLimitSpec::for_vendor`.

## License

MIT
