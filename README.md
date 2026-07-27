# Charon

A modular terminal UI for OSINT investigations — ferry indicators across the Styx and see what washes ashore.

Charon ingests newline-separated indicators (emails, IPs, JA4 fingerprints, hashes), routes them to selected vendors, respects per-vendor rate limits, and exports results as CSV or raw JSON dumps.

## Status

Foundation release. **VirusTotal** is the first plugged-in vendor. Additional vendors drop in via the `OsintVendor` trait under `src/vendors/`.

## Quick start

```bash
cargo run --release
```

Config and cached API keys live at:

```
~/.config/charon/config.toml
```

## Main menu

- **Run OSINT Investigation** — pick an input file, review auto-detected indicator types + vendor fit, choose output format/verbosity, then watch live progress.
- **Add / Remove / Change API Key** — manage cached keys per vendor.
- **List / Select Vendors** — checkbox select; missing keys are prompted when enabling a vendor.

## Adding a vendor

1. Create `src/vendors/<name>/` implementing `OsintVendor`.
2. Register it in `src/vendors/mod.rs` (`all_vendors()`).
3. Declare supported `IndicatorType`s and a `RateLimitSpec`.

No UI rewrite required — menus and the investigation runner discover vendors from the registry.

## VirusTotal (public API)

| Limit | Value |
|-------|-------|
| Requests / minute | 4 |
| Requests / day | 500 |
| On exceed | HTTP 429 |

Premium keys use higher quotas; Charon still paces at the configured `RateLimitSpec` (override later per-key tier if needed).

## License

MIT
