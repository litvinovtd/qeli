# Q25-F133: Linux client-only build and exit WAN monitor

25 September 2026. Base: `25488dbd`. D11 remains **IN_PROGRESS**.

`cargo check --offline --lib --no-default-features --features client`
failed on Linux with two E0425 errors: `tun_name` was undefined in the TCP
and UDP `spawn_exit_wan_monitor` paths. The monitor is enabled under
`target_os = linux` regardless of `experimental-roaming`, but both TUN-name
declarations were gated on that feature. The default build and `client-bin`
include roaming, which hid the defect.

Both `tun_name` declarations now use the same Linux scope as the monitor.
The ordinary binary's algorithm and runtime behavior are unchanged;
INI/API/ABI formats are unchanged.

On isolated `.11`, the original client-only check exited **101** with two
E0425 errors. The fixed client-only check, separate server-only check,
`cargo build --offline --bin qeli-client --no-default-features --features client-bin`,
and running the new binary with `--help` all exited **0**. Rustfmt passed.
This check did not establish a real router-client VPN connection.
The client-only warning for unused `terminal_sender` remains a separate
dead-code cleanup candidate, not a build failure.

Client binary SHA256:
`ca6f5d7b5e940a814c9a43737b053ab4835b48bcd70ff26c73f8e7bfb83b54d2`.
Verified `client/mod.rs` SHA256:
`9bbf372803ea3cb20c9737b0f0786316fd70c8f559985f88677a94ce7c6eddb2`.
Baseline and fixed logs/exit codes:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/client-feature-phase/`.
Installed lab services were untouched. D11 provenance/package and D12
platform runtime remain open.
