# qeli fuzz targets

Coverage-guided fuzzing (via [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
/ libFuzzer) for the parsers that face fully attacker-controlled bytes from a
hostile network. These are the highest-value place to fuzz: a panic or over-read
in any of them is reachable by a single crafted packet.

This crate is **standalone** — it is an independent Cargo package, so the
normal `cargo build` / `cargo test` do not touch it. It pulls in
only the cross-platform parser core (`default-features = false`: no
server/client/tun/web).

CI runs **`fuzz-smoke` as a blocking merge gate** on every push/PR (a 30 s
smoke per target, starting with an empty corpus), and **`fuzz-nightly`** on a schedule
(10 min per target with a corpus persisted across runs via
`actions/cache`, so coverage accumulates; a crash uploads its reproducer as an
artifact). See `.github/workflows/ci.yml`.

## Targets

| Target | Exercises |
|--------|-----------|
| `client_config` | Strict/permissive flat-INI parsers and the `qeli://` share-link parser. |
| `websocket_head` | Pre-authentication WebSocket HTTP Upgrade request parser. |
| `clienthello` | `FakeTlsHandshake::parse_client_hello` / `parse_client_hello_full` / `extract_client_mlkem_ek` — the fake-TLS / REALITY / PQ ClientHello parsing the server runs on first contact. |
| `packet_decrypt` | `PacketCodec::decrypt_packet` (TLS and raw framing) — data-plane record framing, length/nonce/tag slicing, padding length, replay accounting. |
| `realtls_record` | `realtls::record::RecordCrypto::decrypt` — TLS 1.3 record framing and authenticated decryption. |
| `obfs_datagram` | Datagram obfuscation framing and length checks. |
| `udp_frag` | UDP handshake fragments: arbitrary input plus valid round trips, historic 1200-byte receive chunks, conflict and over-limit refusal. |
| `data_frag` | Authenticated UDP data-record fragments: exact reassembly under reorder/duplicates, authenticated conflict and MAC refusal, and 32-record/512-KiB limit recovery. |
| `roaming_wire` | UDP CID headers, TCP resume JOIN/proofs, and authenticated PATH control framing/round trips. |
| `quic` | QUIC-like header and packet-number parsing. |
| `ip_packet` | IPv4/IPv6 lengths, fragments, extension chains and guarded transport-port lookup. |
| `control_v2` | Control/management frames, bounded reassembly, expiry, conflicting fragments and duplicate handling. |
| `realtls_client` | Complete and malformed ServerHello through the shipping sans-IO client state machine. |
| `websocket_frame` | Raw and structured binary/control WebSocket frames through the shipping parser. |
| `quic_envelope` | Shared QUIC camouflage envelopes: round trips, malformed input and structured mutations. |

## Running

CI pins `nightly-2026-06-10` and `cargo-fuzz 0.13.2`. The independent
`fuzz/Cargo.lock` freezes this package's graph; the parent lockfile alone does
not control it. Update the pins and lockfile together, review the dependency
changes, then build and smoke all registered targets.

```sh
# one-time
rustup toolchain install nightly-2026-06-10 --profile minimal
cargo +nightly-2026-06-10 install cargo-fuzz --version 0.13.2 --locked --jobs 1

cd qeli
export RUSTUP_TOOLCHAIN=nightly-2026-06-10 CARGO_BUILD_JOBS=1
test -f fuzz/Cargo.lock
cargo +nightly-2026-06-10 fetch --locked --manifest-path fuzz/Cargo.toml
sha256sum fuzz/Cargo.lock > fuzz-lock.sha256
export CARGO_NET_OFFLINE=true
cargo +nightly-2026-06-10 fuzz build
sha256sum --check fuzz-lock.sha256
cargo +nightly-2026-06-10 fuzz run clienthello -- -max_total_time=60
sha256sum --check fuzz-lock.sha256
rm fuzz-lock.sha256
```

`cargo-fuzz 0.13.2` has no `--locked` build/run option. CI first requires the
committed lockfile and fetches with Cargo's `--locked`, then builds/runs offline
and checks that the lockfile stayed byte-identical. `RUSTUP_TOOLCHAIN` also pins
the Cargo and rustc processes launched internally by cargo-fuzz.

The target inventory comes from `Cargo.toml` via `scripts/fuzz_targets.py` for
both CI smoke and the nightly matrix. A 30-second smoke checks build/API drift
and reachable crashes within that budget; it does not prove parser safety.

A crash is written to `fuzz/artifacts/<target>/`; reproduce with
`cargo +nightly-2026-06-10 fuzz run <target> fuzz/artifacts/<target>/crash-…`.

## Seed corpus & crash triage

libFuzzer maintains an evolving corpus under `fuzz/corpus/<target>/` and writes
any crash/timeout reproducer to `fuzz/artifacts/<target>/`. Both are
**gitignored** (generated data, not source) — see the repo `.gitignore`.

**Seeding** (optional but speeds coverage): drop representative inputs into the
corpus dir before the first run. Good seeds:

- `clienthello` — a captured real `ClientHello` (e.g. `tshark`/`tcpdump` of a
  browser TLS 1.3 handshake), or bytes produced by
  `FakeTlsHandshake::build_client_hello(...)` (see `crypto::reality::tests`).
- `packet_decrypt` — a record emitted by `PacketCodec::encrypt_packet` (see
  `protocol::packet::tests`), then mutate.
- `realtls_record` — a record from `RecordCrypto::encrypt`.

```sh
mkdir -p fuzz/corpus/clienthello
# e.g. extract a ClientHello payload and drop it in:
# cp /tmp/chrome_clienthello.bin fuzz/corpus/clienthello/seed1
cargo +nightly-2026-06-10 fuzz run clienthello                    # uses the corpus
```

**Triage a crash:**

```sh
# reproduce
cargo +nightly-2026-06-10 fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
# minimize the reproducer
cargo +nightly-2026-06-10 fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>
# the panic backtrace points at the parser; fix, then add the (minimized)
# reproducer to fuzz/corpus/<target>/ as a permanent regression seed.
```

A crash here is a panic/over-read on attacker-controlled input — treat it as a
security issue and follow [`SECURITY.md`](../../SECURITY.md).

## Adding a target

1. Add `fuzz_targets/<name>.rs` (see the existing ones — `#![no_main]` +
   `fuzz_target!`).
2. Register a `[[bin]]` in `Cargo.toml`.
3. Keep targets to **pure parsing of untrusted input** — fix any keys, since the
   point is the framing/bounds logic, not the cipher.
