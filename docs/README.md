# Qeli

VPN с современной криптографией (эфемерный X25519 + post-quantum ML-KEM-768,
ChaCha20-Poly1305) и настраиваемой обфускацией транспорта для работы в сложных
сетевых условиях. Один Rust-движок протокола и клиенты под Android, Windows и
macOS на общем нативном ядре через FFI.

A VPN with modern cryptography (ephemeral X25519 + post-quantum ML-KEM-768,
ChaCha20-Poly1305) and configurable transport obfuscation for hostile networks.
One Rust protocol engine plus Android / Windows / macOS clients sharing a native
core via FFI.

## Документация · Documentation

- 🇷🇺 **Русский** — [`docs/ru/README.md`](ru/README.md)
- 🇬🇧 **English** — [`docs/eng/README.md`](eng/README.md)

(Полная документация — конфигурация, дизайн, аудиты, бенчмарки — в соответствующей
локали. The full docs — configuration, design, audits, benchmarks — live under each locale.)

## License

Монорепозиторий с **несколькими лицензиями по каталогам** · monorepo with
**per-directory licences**:

- ядро + сервер (`qeli/`) · core + server → **AGPL-3.0-only** ([LICENSE](../LICENSE))
- клиенты (`qeli-android/`, `qeli-win/`, `qeli-mac/`) · clients → **MPL-2.0**

Полная карта и нюансы (`libqeli`/AGPL) · full map and the `libqeli`/AGPL note —
[LICENSING.md](../LICENSING.md). Вклады · contributing (DCO, без CLA) —
[CONTRIBUTING.md](../CONTRIBUTING.md).
