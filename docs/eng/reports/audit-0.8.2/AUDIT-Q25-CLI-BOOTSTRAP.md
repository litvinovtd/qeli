# Q25-F216/F217: shared Linux CLI INI bootstrap

4 October 2026. Startup boundary verified; final section status is [DONE/PASS](AUDIT-Q25-LINUX-CLI-FINAL.md).

<!-- normative-sync: audit-q25-cli-bootstrap-v3 -->

The standalone `qeli-client` read INI using unbounded `read_to_string` before the shared loader: a FIFO without a writer blocked startup, and an untrusted config could select a log file. `check-config --client` also bypassed bounded reading. The full `qeli client` used the server bootstrap's 16 MiB bound and a separate partial logging parser: oversized/invalid client profiles could open a file, and the case of valid keys changed behavior.

Both Linux entry points now use `client::logging_bootstrap`: the shared regular-file snapshot bounded at **262144 bytes**, strict client INI parsing, and immutable trust for the same opened inode. Invalid profiles use stderr; untrusted profiles preserve valid level/time_format but cannot select a file sink. Validation receives zeroizing text from the same loader. The standalone partial parser was removed. Server bootstrap, INI keys, wire and ABI are unchanged. The new module is gated by `target_os = linux`.

Private sources had SHA-verified 348 compilation inputs, Rust 1.97.0, one Cargo job and offline/locked commands. Linux library tests: **2412 PASS, 60 ignored**; five new regressions cover FIFO, the exact limit, invalid profiles, case and permissions/symlinks. Strict Clippy `--all-targets --features transport-core-ffi,client-bin -- -D warnings` and both actual Linux CLI builds PASS.

`scripts/audit_linux_cli_bootstrap.py` runs real processes only in fresh NET/mount/PID namespaces. Baseline reproduced **10 failing scenarios**. Fixed: **24 scenarios / 46 checks PASS**, including exactly 256 KiB and one byte over, trusted/untrusted log sinks, mixed-case INI, FIFO, a directory and a missing file. Exact private network before/after matched; the longest fixed CLI scenario took 0.057 seconds. These are pre-connect checks and do not prove a successful VPN connection.

The first build and CLI wrappers exited nonzero because three ambient legacy firewall rules changed. Those FAIL results remain intact. Passive observation without tests also showed the rules appearing/disappearing about every five seconds; the current journal identified the actor: external `vpn-nat` adds/removes the rules while its required `vpn-obfuscated` cycles through restarts. Final `runtime-fixed-r2` passed its checks and **strict complete host snapshot comparison**, without excluding rules. PID 745/901 and the running server SHA were preserved; the installed service was not replaced.

Raw logs/manifests: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q25-cli-20261004/`. `fixed-build/result.json` records passing individual Cargo commands but `host_restored=false`, so it is not an overall wrapper PASS. Final CLI wrapper: `runtime-fixed-r2/wrapper.json`, `qualification_status=PASS`. Executables: standalone `a2cf8daa6dbb4da484a3306c86e11f2eb5ab9bef33e62e0cb0ca683c7de4cbce`, daemon `fba890ab7af1698780d35e4e5e64cd0b60119d21c2ed330a14a13405412f4240`.

Next Q25 boundary: reconcile Linux lifecycle/recovery against closed D01–D05/D09/D10/D13 and align native provenance after source changes. No new router runtime is implied: the user excluded that lab.

## F217: FIFO in logging.file

The same startup boundary exposed another blocking open: a valid trusted INI with `logging.file = <FIFO>` stopped both CLI processes before signal handlers were installed. Shared `open_log_file` opens without blocking and checks the obtained fd for a regular file before handing it to the logger; rejection uses stderr. The full daemon's server/worker logger uses the same helper. Ordinary append and parent-directory creation remain intact; no JSON config was added. Linux-only wiring is appended after shared client code: the shared Q24 source remains an exact prefix, preserving other platforms' source locations.

Extended baseline: **12 failures reproduced**, including both FIFO log sinks; this complete outer wrapper preserved host state and exited 0 because it expected those defects. Fixed final: **26 scenarios / 68 checks PASS**, including nonzero startup exit on failure and append behavior. All final CLI processes completed within 0.036 seconds; namespace network and complete host snapshots matched. `fixed-build-r2`: **2414 library tests PASS, 60 ignored**, strict Clippy and both CLI builds PASS; library tests ran in a separate NET/mount/PID namespace with private /run, /var/lib, /var/log and /tmp. Both final wrappers have `qualification_status=PASS`, `host_restored=true`. Two unit regressions cover FIFO with/without a reader and preserved append.

Final manifests: `fixed-build-r2/result.json`, `runtime-baseline-log-fifo/`, `runtime-fixed-log-fifo/`. Standalone SHA: `5b5951ef921ab76aec6d8fb8a7c705f2f7788cadc357cfe2de7467f4e88f541b`; daemon SHA: `5f5838b24cf667d26bd8a27a6d0e6717f20c7680c3d14474b425773d5124c6c4`. Initial records and executables remain separate.
