# Q01 — server INI: first audit pass

<!-- normative-sync: audit-q01-server-ini-v1 -->

Date: **2026-09-22**. Base: `fc6f4a5dc8df7f119f2d99a6b72b08916ae7a268`, branch `dev`.
Results apply to the working tree with the fixes below.
Plan: [FULL-SYSTEM-AUDIT](../../plans/FULL-SYSTEM-AUDIT.md).

Fixed **6 configuration-processing defects** and **1 coverage-evidence gap**.
Overall status remains **IN_PROGRESS**: portable checks pass and Linux targets compile;
Linux server/CLI/reload execution and per-field runtime tracing remain open.
This report does not certify completion of the full Qeli audit.

## Scope

- Shared INI grammar, typed readers, read tracking and diagnostics.
- Server section structure, scalar/list/map semantics, profile and user routes.
- Rejection through `parse_server_config`, `parse_server_config_reporting` and
  `UsersDb::parse_strict`; startup, SIGHUP, Quick Start and panel save call sites were
  inspected in source. No HTTP requests or signals were sent to a live server.
- Missing versus empty lists, defaults and roundtrip, metric boundaries, IPv4/IPv6
  gateways, diagnostic isolation across 32 concurrent parses.
- Four shipped server examples through the actual portable parser. Their Linux profile
  validation compiled but did not execute here.

No dead executable modules were established within this scope. Obsolete TOML field-order
and startup-warning comments were removed. AWG normalization, scoped retired keys and
empty-value defaults in `parse_or` remain separate existing contracts, not new findings.

## Findings and fixes

### Q01-F001 — P2: malformed routes disappeared or changed meaning

**Before:** `route = nonsense` disappeared; `route = 10.0.0.0/8 metric=no` lost its
metric. Misspellings such as `metirc=7`, repeated `metric`/`gateway`/`cidr`, and extra
tokens were accepted. A substring search for `desc=` could conceal `notdesc=`.
Errors never reached `doc.bad_values()`, leaving strict callers unable to reject them.
User routes also silently lost malformed metrics.

**After:** syntax, CIDR, gateway family, unknown/duplicate options and metric
`0..=4294967295` are checked. Errors are recorded in their section. A final `desc=`
is matched at an option boundary and retained on profile routes. Unsupported `desc`
on user routes is rejected, including an explicitly empty option.

**Tests:** `invalid_profile_routes_produce_findings`,
`route_option_typos_and_duplicates_are_rejected`, `user_routes_share_strict_option_validation`,
`route_options_and_profile_descriptions_round_trip`.

### Q01-F002 — P2: duplicate or empty map keys were silently transformed

**Before:** two `pool.reservation.alice` entries selected the last value without an
error; `pool.reservation. = 10.9.0.2` disappeared with a warning. IPv6 reservations
behaved the same way. Repeated `metadata.note` overwrote the first value.

**After:** each full dynamic key must be unique and have a nonempty suffix; invalid
entries produce findings. Reservation usernames also pass `is_valid_ident`.
Distinct usernames and metadata keys remain supported.

**Test:** `dynamic_map_keys_must_be_unique_and_nonempty`, plus the general roundtrip.

### Q01-F003 — P2: supported repeated lists were rejected as duplicate scalars

**Before:** a presence check using `get()` recorded a scalar-duplicate finding,
although the following `list()` correctly merged values. Two `pool.exclude` lines
reproduced this. IPv6 exclusions, DNS lists, REALITY short_ids, round_sizes, web lists
and group allowed_networks were also affected.

**After:** presence checks do not impose scalar semantics. Lists merge in source
order; missing keys remain distinct from explicitly empty lists.

**Tests:** `repeated_profile_lists_merge_in_source_order`,
`repeated_web_and_group_lists_are_accepted`, `missing_and_explicit_empty_lists_remain_distinct`.

### Q01-F004 — P2: malformed global section shapes passed schema validation

**Before:** `[web:main]` acted as global `[web]` because section lookup ignored the
instance. A repeated empty singleton or empty unknown section could evade unread-key
validation because it contained no keys to report.

**After:** `[auth]`, `[web]` and `[logging]` are unique and have no instance.
Unknown sections are rejected regardless of their contents.

**Test:** `malformed_and_duplicate_singleton_sections_are_rejected`.

### Q01-F005 — P2: invalid round_sizes members were silently dropped

**Before:** `obf.traffic_normalization.round_sizes = 512,no,1500` became `[512,1500]`
through `filter_map(parse().ok())`, with no configuration error.

**After:** malformed integers, negative values and type overflow produce findings.
Allowed runtime sizes remain the profile validator's responsibility; parsing does
not replace that validation.

**Test:** `malformed_numeric_list_members_produce_findings`.

### Q01-F006 — P2: the ordinary parse API bypassed accumulated findings

**Before:** `parse_server_config` ignored findings, unlike strict startup/panel paths.
Quick Start reads the current file through this function before rewriting it. A bad
line could disappear on serialization, so later validation no longer saw the original
error. CLI code also uses this entry point.

**After:** the ordinary API calls the reporting parser and rejects nonempty findings.
Low-level `ServerConfig::from_ini` remains a builder for diagnostic workflows; its
callers must inspect bad values and unread keys.

**Test:** `ordinary_server_parser_does_not_discard_findings` failed independently before
this fix and passes afterwards. This verifies the API contract; full HTTP/CLI execution
still requires Linux.

### Q01-F007 — P3: the exhaustive roundtrip claim was not supported by coverage

**Before:** the primary Rust fixture omitted ten read keys: `listen`,
`perf.udp.recv_buffer_size`, `perf.udp.send_buffer_size`, four `roaming.*` keys,
`routing.ipv6.ndp_proxy`, `routing.ipv6.ndp_proxy_interface`, and `users_file`.
The generator and embedded fixture had drifted. The regex missed multiline accessors;
broad exemptions hid missing values. Some fields already had dedicated tests, so this
finding does not mean they had never been tested at all.

**After:** fixtures are synchronized, including IPv6 reservations and metadata.
`python scripts/gen_roundtrip_fixture.py --check` verifies reader names, three dynamic
families, and parity with the actual Rust fixture. CI runs this command. The sole
exception is the read-only retired `tun.netmask`, which must not be serialized again.

**Evidence limit:** 163 unique key names and 3 families are covered by this check.
It does not prove every field is non-default, every combination is valid, or every
field is applied at runtime. Test and generator descriptions now state this limit.

## Reproduction and results

Environment: Windows x64, stable Rust, offline commands. Linux checking used target
`x86_64-unknown-linux-gnu` and existing Zig CC/AR wrappers.

| Check | Result |
|---|---|
| Original `--lib config::` on fc6f4a5d | 129 PASS |
| First 11 new regression tests before fixes | 2 PASS, 9 FAIL |
| Ordinary parse API test before its fix | 1 FAIL |
| Final portable `--tests` | 632 unit + 7 examples + 12 audit = **651 PASS** |
| Fixture coverage | 163 names, 3 families; PASS |
| Linux `cargo check --all-targets` | PASS; tests did not execute |
| Panel static checks | 11 templates, 1142 RU strings; PASS |
| Panel editor regressions | 25 PASS |

Commands from the repository root:

```sh
cargo test --offline --manifest-path qeli/Cargo.toml --no-default-features --features transport-core-ffi --tests
cargo check --offline --manifest-path qeli/Cargo.toml --target x86_64-unknown-linux-gnu --all-targets
python scripts/gen_roundtrip_fixture.py --check
python scripts/check_panel.py
node scripts/test_panel_editors.cjs
python scripts/check_docs.py
git diff --check
```

Local evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-q01-20260922/`.
`regressions-before.log` and `ordinary-parser-before.log` capture reproductions;
`portable-all-tests.log`, `linux-check.log`, `coverage.log`, and `panel-*.log` capture
results. `source-manifest.txt` records tested file SHA-256 hashes;
`key-inventory.md` lists reader keys. Tests used synthetic strings, not live secrets.

## Remaining work

1. **BLOCKED, Linux runtime:** isolated `check-config`, startup, SIGHUP, HTTP save and
   Quick Start checks; verify rejection before writes and preservation of running state.
   Requires an available Linux environment; local WSL/Docker is not configured here.
2. **TODO, complete field tracing:** verify each field's runtime consumer, ranges and
   combinations. Parser isolation does not exercise NAT, NDP, DNS, obfuscation or filesystem
   operations. Follow-up connects to sections 05, 06 and 13–20.
3. **TODO, broader failure scenarios:** large/corrupt files, budget/DoS and prolonged load.
   Per-section diagnostic limits are not a total input-document size limit.
4. **Stage 00 release blockers remain:** stale native cores and missing 0.8.2 certification.
   Hashes and attestations were not rewritten merely to make checks pass.

The next independent plan section is **02: client parsers and qeli://**.

## Open-item reconciliation — 3 October 2026

The list above describes the first pass on 22 September. Linux runtime, full
field tracing and broader failures were subsequently covered by D07/Q25-F209;
native provenance and certification were refreshed by D15. The [current plan](../../plans/FULL-SYSTEM-AUDIT.md#01-server-ini-and-schema)
and [machine reconciliation](../../../../release/certification/evidence/q01-reconciliation-20261003.json)
verify applicability: all 288 Rust hashes match; 201 unit / 4 privileged /
44 runtime retain their original artifact/environment limits. No repeated
executions are claimed. Targeted dead-code review remains before overall PASS.

## Review completion — 3 October 2026

**Section 01: PASS.** Reviewed builders/codec, strict loading, diagnostic CLI,
form admission, users loading and locked update; traced references through serde
attributes, function pointers and OS/feature gates. Strict paths examine document
findings after conversion and before publication. The client editor remains in
section 02 and networking implementations in sections 13–25.

No new confirmed defects or safely removable dead runtime code were found.
`set_bandwidth` and `notify::save_path` serve test fixtures; a helper name does not
establish a runtime API. `logging.format`, read-only `tun.netmask`, fields inactive
on another transport and AWG normalization have documented contracts and are not
removed as forgotten implementations. The serde baseline is an internal DTO,
not a JSON configuration loader.

Fresh `python scripts/gen_roundtrip_fixture.py --check`: PASS, 163 key names,
three dynamic families, embedded fixture matches. All 288 Rust hashes were checked
again against Q25-F209. Its 201 unit / 4 privileged / 44 runtime checks and fresh D15
validation cover the other criteria; runtime was not repeated here. [Machine reconciliation](../../../../release/certification/evidence/q01-reconciliation-20261003.json)
records the original commit, reviewed file hashes and suspect-branch decisions.
This section PASS does not complete the full audit or alter the accepted D06
limitation for WAN replacement.
