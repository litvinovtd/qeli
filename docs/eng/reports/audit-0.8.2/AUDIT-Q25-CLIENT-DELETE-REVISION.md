# Q25-F166: stale Delete and applying client INI changes

1 October 2026. Base: 5ea46043. D08 remains **IN_PROGRESS**.

Panel Delete stopped a tunnel and removed its file without a revision. A tab opened before another edit could stop and delete the newer profile. Saving a running client's INI only reported Saved, although the Linux client reads the file at process start and keeps the old configuration even through internal reconnect loops.

The profile list now includes a revision of the exact INI bytes. The panel sends it as X-Qeli-Revision on Delete. Under the shared mutex and sidecar lock, the API requires a matching token before Disconnect: missing or stale tokens neither stop the tunnel nor delete the file. It reads again after graceful Disconnect; an intervening manual edit survives and returns a conflict. Such a late conflict may leave the tunnel stopped, so the user must reload the profile and reconnect if needed. Direct API clients must take X-Qeli-Revision from the profile list.

A successful Save of a running profile returns requires_reconnect; the panel explicitly asks for Disconnect and Connect to apply the new INI. No automatic restart was added, since route or kill-switch changes merit an administrator's decision. Files over 256 KiB or with invalid encoding receive no revision and cannot be deleted from the panel; inspect and repair them on the host.

On isolated lab .11, formatting, eight client API tests and strict Clippy for normal and client-only builds passed. Log: clientdelete1.log in C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase. Local JS header/reconnect/i18n checks and git diff --check passed. Three missing Russian configuration-form translations were added. No active-tunnel HTTP E2E was run; .10 was unchanged.

D08 still covers other adapters, URI/QR/store and real reconnect. An external editor ignoring the lock can write between the final check and unlink; D07 records this boundary.
