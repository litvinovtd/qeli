# Q25-F150: INI trust in panel identity, Share, and users

1 October 2026. Base: `553815c9`. D07 remains **IN_PROGRESS**.

Startup CLI and worker already required a trusted INI snapshot for an explicit `identity_key` and custom `auth.users_file`, but `GET /api/identity` and key rotation independently reread the current config with unbounded `read_to_string` before key creation or replacement. Share used the common panel loader, which bounded INI size but returned paths without checking snapshot trust. That loader also serves users-file operations. A manual edit to a running server's config could therefore bypass startup admission.

The common panel loader now reads one bounded `read_config_source` snapshot, parses it strictly, and checks custom users-file, explicit identity, and active explicit TLS paths against permissions of that same opened inode. Identity listing and rotation use this loader; Share and users inherit its gate. Restart preflight also checks TLS paths. Trust requires a regular INI owned by root or the effective UID, with no group/world write or symlink.

On isolated lab .11, four focused tests passed: list/rotate refuse before key creation and listing succeeds after `chmod 600`; Share refuses before key/password work; the shared loader refuses a custom users-file path; and the existing Share failure still leaves the password unchanged. `cargo fmt` and strict library/CLI Clippy passed. Log: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/panelpaths1.log`. No services were started or changed.

An external manual editor can still change the pathname or file after snapshot validation; that race and the complete file-field matrix remain D07. Register: **5/15 DONE**.
