# qeli fuzz targets

Coverage-guided fuzzing (via [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
/ libFuzzer) for the parsers that face fully attacker-controlled bytes from a
hostile network. These are the highest-value place to fuzz: a panic or over-read
in any of them is reachable by a single crafted packet.

This crate is **standalone** — it is not a member of the `qeli` workspace, so the
normal `cargo build` / `cargo test` / CI merge gate never touches it. It pulls in
only the cross-platform parser core (`default-features = false`: no
server/client/tun/web).

## Targets

| Target | Exercises |
|--------|-----------|
| `clienthello` | `FakeTlsHandshake::parse_client_hello` / `parse_client_hello_full` / `extract_client_mlkem_ek` — the fake-TLS / REALITY / PQ ClientHello parsing the server runs on first contact. |
| `packet_decrypt` | `PacketCodec::decrypt_packet` (TLS and raw framing) — data-plane record framing, length/nonce/tag slicing, padding length, replay accounting. |
| `realtls_record` | `realtls::record::RecordCrypto::decrypt` — the hand-rolled TLS 1.3 record-layer framing (largest unaudited surface). |

## Running

```sh
# one-time
rustup toolchain install nightly
cargo install cargo-fuzz

cd qeli
cargo +nightly fuzz run clienthello          # runs until a crash / Ctrl-C
cargo +nightly fuzz run packet_decrypt -- -max_total_time=60   # 60s smoke
cargo +nightly fuzz run realtls_record
```

A crash is written to `fuzz/artifacts/<target>/`; reproduce with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-…`.

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
cargo +nightly fuzz run clienthello                    # uses the corpus
```

**Triage a crash:**

```sh
# reproduce
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
# minimize the reproducer
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>
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
