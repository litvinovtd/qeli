# Q25-F149: TLS path trust and Let's Encrypt panel saves

1 October 2026. Base: `d3e623c8`. D07 remains **IN_PROGRESS**.

Explicit `web.tls_cert`/`tls_key` paths were not bound to the trusted server INI snapshot: `check-config` could open them from an untrusted config, and the supervisor admitted them before starting the panel. Both panel editors rejected the documented `/etc/letsencrypt/live/...` paths because they reused the allowlist for Qeli-managed writable files. Backup also required TLS files for a disabled panel with dormant `web.tls = true`.

For an enabled HTTPS panel with an explicit pair, `check-config`, supervisor, and worker now require trust from the same opened INI snapshot that supplied the paths: a regular file owned by root or the effective UID, without group/world write or a symlink. CLI checks trust before reading PEM. Auto-generated pairs and inactive TLS are unaffected. Both panel editors accept TLS files below `/etc/qeli` and `/etc/letsencrypt`; users, identity, and log path policies remain narrow. Backup treats TLS as critical only for an enabled HTTPS panel.

On isolated lab .11, tests for original-snapshot trust across `chmod 0666` → `0600`, the panel TLS path policy, and three backup cases passed; `cargo fmt` and strict library/CLI Clippy passed. The built CLI rejected the untrusted INI before PEM parsing, then after `0600` reached the expected invalid-PEM error. Logs: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/tlstrust1.log` and `tlsbackup2.log`. Lab services were untouched.

An explicit pair under `/etc/letsencrypt` is accepted for panel startup and saves, but portable Backup covers only `/etc/qeli` and returns HTTP 409; back up the external pair separately. The full file-field matrix and races with manual editors remain D07. Register: **5/15 DONE**.
