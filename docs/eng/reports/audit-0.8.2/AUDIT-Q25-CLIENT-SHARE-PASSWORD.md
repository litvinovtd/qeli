# Q25-F194 — portable password in share links and editor build

Status: fixed on 1 October 2026; the shared Rust contract was verified on Windows. Android and iOS UI/runtime remain within D12 limitations.

The shared editor exported a profile using `password_file` or `password_command`, but no inline `pass`, as a plausible `qeli://` link with no password. The local client could resolve the secret; the recipient could not, so failure surfaced only at connect time. The `uri` operation now requires a nonempty inline `pass` and explains why sharing is refused. Validation and saving of local INI remain unchanged. When inline `pass` coexists with an external source, the inline value has the same precedence as at connect time and enters the link.

The integration test exposed a separate Windows build defect: `config::notify` always uses the bounded INI loader `config_source`, but the module was gated to Linux or `cfg(test)`. The outer platform gate is removed. Shell-command trust checks still deny authorization on Windows, while notification INI loading can compile. The integration suite runs with `--no-default-features` because the `qeli` binary is intentionally Linux-only.

A targeted regression covers no password, `password_file`, `password_command`, and inline `pass` alongside an external source. Full `config_editor`: 52/52 PASS on Windows. Portable `cargo test --lib`: 1551 PASS, 1 ignored; rustfmt PASS. Documentation checking retains its pre-existing baseline of 61 findings (32 index, 3 links, 26 parity), with none added. Live Linux servers and mobile apps were not replaced.
