# Q25-F137: SIGHUP refusal without partial VPN-auth changes

25 September 2026. Base: `5e2f565f`. D07 moves to **IN_PROGRESS**.

On SIGHUP the worker parsed the new INI and rejected parser findings, but
did not run the `validate_profiles` check used by `check-config` and normal
startup. If external `users.conf` failed to load, it kept the old users but
still replaced `FailedAuthTracker` with the candidate thresholds. A rejected
configuration could thus reset active lockouts and apply a different
brute-force policy without its corresponding users database.

The worker now validates the whole candidate and loads the effective users
database before changing any live auth component. A failure at either step
retains both users and thresholds. On success, users and derived dummy
hashes are updated, while the tracker is rebuilt only if thresholds changed.
Profile changes still require restart and are reported separately by SIGHUP.

A direct async SIGHUP test on isolated Linux lab `.11` covered three
successive cases: invalid `tun.mtu`, malformed `users.conf`, and valid INI
with an inline user. The first two retained an empty live database and the
old 5-attempt threshold; the third applied `alice` and 2 attempts.
Rustfmt, the **1/1** focused test and strict Clippy passed. `server/mod.rs`
SHA256: `2dbd9b151beb24c71b030256042556a17ee48d5817f17c8f38dd0e3c1e388caa`.
Test artifact: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/sighupchecks.log`.

D07 remains open: the complete field → parse/validate/runtime/serialize
matrix, size bounds on server INI and panel reads, concurrent file
replacement, and the combined check-config/startup/HTTP/Quick Start matrix
are beyond this scoped fix.
