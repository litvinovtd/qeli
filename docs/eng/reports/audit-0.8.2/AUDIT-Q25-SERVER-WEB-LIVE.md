# Q25-F139: panel live state after saving INI

25 September 2026. Base: `a410ae9c`. D07 remains **IN_PROGRESS**.

A live `[web]` reload replaced all of `live_web`, although the listener,
TLS transport and panel router kept their startup settings. After saving a
new `web.port`, CSRF expected the new port while the panel still listened on
the old one. Also, changing `[web] brute_force` in the general form updated
INI and `live_web` but not `FailedAuthTracker`; the old thresholds still
controlled logins. The dedicated settings endpoint did apply the tracker, so
the two save paths disagreed.

Live reload now retains startup `enabled`, `bind`, `port`, `tls`, certificate
paths, `base_path` and session-key source in its live view. The candidate is
validated against the panel that is still running before state changes;
invalid dormant values in a config that disables the panel cannot enter the
still-running panel. New login thresholds reach the tracker only after
validation; unchanged thresholds preserve existing IP lockouts.

A direct async test on isolated Linux lab host `.11` checks startup-only
fields, hot `public_host`, retention of accumulated IP state under unchanged
thresholds, application of changed thresholds, and complete refusal of an
invalid candidate. `cargo fmt --check` and strict
`cargo clippy --lib --bins -- -D warnings` passed. Log:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/webreloadchecksv2.log`.

Remaining D07 criteria: the full field → runtime trace, the combined
check-config/startup/SIGHUP/HTTP/Quick Start matrix and atomic conflict
handling between the last file read and publication.
