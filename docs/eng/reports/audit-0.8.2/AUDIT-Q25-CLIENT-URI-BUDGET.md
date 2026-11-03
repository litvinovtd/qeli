# Q25-F198 — direct qeli:// import budget

Status: 1 October 2026. Public `ClientLink::from_uri` was called both through the shared editor, which already limited documents to 256 KiB, and directly by the panel's `POST /api/client/import-link`. A long URI therefore reached query parsing and percent decoding without that limit before profile persistence.

The parser now rejects input longer than 256 KiB before allocating decoded values. A boundary test accepts the exact limit and rejects one additional byte. Windows results: 1552/1552 portable Rust tests PASS (1 ignored), 54/54 `config_editor` integration tests PASS. This bounds a single input; it does not replace a global HTTP body limit or panel load testing.

D11: `provenance.py --check` still reports STALE, as committed release native cores belong to an older source digest; A/B release rebuilding has not been performed. D12: after the VM reset, `.11` answers SSH but rejects the `root` password; Android instrumentation remains unverified on the current SHA.

The local D11 check found a stale source assertion in `test_native_recipes.py`: it looked for the former `load_users_db` call, while `check-config` and runtime now use the shared `load_users_db_for_runtime`. The assertion follows the current path; 69/69 native-recipe Python tests PASS. This does not replace release-core A/B rebuilding.
