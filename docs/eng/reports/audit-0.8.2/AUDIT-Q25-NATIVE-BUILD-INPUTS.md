# Q25-F199 — reproducible native build inputs

Status: 1 October 2026; local recipe checks PASS, release A/B was not run.

The A/B build synchronized `qeli/src` and Cargo manifests but left a previous `qeli/.cargo/config.toml` on the VM. Such a config could change compilation while both passes still matched. The `source-digest` also omitted the local Cargo config and executable Python recipes: changing a build command or Mach-O normalization did not invalidate recorded evidence.

Source synchronization now removes only managed `src` and `.cargo` under the dedicated remote source directory, then uploads the local `config.toml`. Shared `BUILD_INPUTS` participates in the digest and clean-tree gates before A/B and provenance updates: manifests, Cargo config, both platform recipes, and their shared helpers/normalizer. A test changes the Cargo config and Mach-O recipe and verifies a changed digest and rejection of old evidence; another verifies remote `.cargo` reset and exact file transfer.

`python -m unittest discover -s scripts -p 'test_native_*.py' -q`: 70/70 PASS. `py_compile`: PASS. `provenance.py --check`: expected STALE with exit code 1. This package does not verify actual binaries, A/B hashes, ABI or Android instrumentation. D11 still needs a clean commit, `.10`/`.11` access, A/B builds and consumed-copy checks.
