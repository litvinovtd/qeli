# Q25-F147: panel TLS PEM input and incomplete auto pair

1 October 2026. Base: `ba06e7db`. D07 remains **IN_PROGRESS**.

The panel opened `web.tls_cert` and `web.tls_key` with ordinary `File::open` and handed the stream to the PEM parser without a type or size bound. A FIFO at either path could wait for a writer and delay panel startup; a large regular file had no explicit read limit. Separately, losing either file of the auto-generated pair caused generation of **both** files, replacing the surviving key or certificate.

PEM loading now opens with `O_NONBLOCK` on Unix, checks the opened inode is a regular file, and limits reads to 4 MiB plus one byte. Symlinks to regular PEM files remain supported for certificate rotation. Auto-pair presence uses `symlink_metadata`: generate when both are absent, load when both exist, and refuse without replacing anything when only one remains. The existing TLS error path leaves the HTTPS panel off without changing the VPN config.

Verification on isolated .11: five tests for a new readable pair and `0600` key, preservation of a surviving key, rejection at 4 MiB + 1 byte, nonblocking FIFO refusal, and a symlinked regular PEM; `cargo fmt` and strict library/CLI Clippy. Log: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/tlsinput2.log`. Lab services were not restarted.

D07 remains open: `check-config` does not yet read PEM content and can say OK for a broken TLS asset; explicit TLS path trust and the full file-field matrix need separate review. Register: **5/15 DONE**.
