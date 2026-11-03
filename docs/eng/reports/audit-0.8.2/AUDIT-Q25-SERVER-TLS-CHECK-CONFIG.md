# Q25-F148: TLS file validation in check-config

1 October 2026. Base: `b6e9fcf4`. D07 remains **IN_PROGRESS**.

`qeli check-config` validated the active panel schema but did not open its PEM files. A broken certificate or key produced `OK`, then disabled the HTTPS panel at startup.

The CLI now shares the startup TLS loader for an enabled HTTPS panel: it checks pair presence, bounded PEM reads, certificate and key parsing, and construction of `rustls::ServerConfig`. Dormant fields remain unread when the panel or TLS is disabled. A wholly absent auto-generated pair remains valid for first startup; `check-config` creates no files. An incomplete auto pair or missing explicit file is rejected.

On isolated lab .11, eight focused TLS tests, `cargo fmt`, and strict library/CLI Clippy passed. The built CLI rejected a private INI with an invalid PEM using a nonzero exit and `panel TLS: no certificates`; no service was started or restarted. Logs: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/tlscheck1.log` and `tlscli1.log`.

Limit: before first startup, `check-config` cannot prove that `/etc/qeli` is writable for auto-pair creation. Explicit TLS path trust, the complete file-field matrix, and races with manual editors remain. Register: **5/15 DONE**.
