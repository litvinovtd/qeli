# Q25-F154: Quick Start and lockout-policy saves

1 October 2026. Base: `f2770b79`. D07 remains **IN_PROGRESS**.

After Q25-F153, a review of all five server-INI write paths found two missing guards. Quick Start and `POST /api/blocked/settings` could rewrite a manually edited config with an enabled panel and either an empty admin hash without explicit `insecure_no_auth` or a nonempty malformed Argon2 hash. The lockout-policy API checked only INI syntax, not the conditions under which SIGHUP accepts new VPN-auth state. For example, a changed `auth.users_file` path made the worker refuse SIGHUP while the API still said the settings were saved and applied. `GET /api/blocked/settings` hid INI read/parse failures by returning default policies with a success response.

Quick Start now validates the resulting web authentication before writing. Before saving, the lockout-policy API checks the complete candidate: strict INI parsing, the presence and Argon2 format of the enabled panel's admin hash, startup profile validation, and, for VPN policy, the unchanged startup users-file path and effective users union. The Blocked IPs page shows a read failure. Save responses distinguish a requested worker reload from deferred application when the worker is unavailable; the UI displays the corresponding status.

On isolated lab .11, one focused test covered five candidates; the status and config-editor test groups, `cargo fmt --check`, and strict Clippy also passed. Node parsed the changed JavaScript. Log: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/bfwriters6.log`. Running services were unchanged.

The remaining server-field runtime matrix and the external manual-editor race without the advisory lock remain under D07. Register: **5/15 DONE**.
