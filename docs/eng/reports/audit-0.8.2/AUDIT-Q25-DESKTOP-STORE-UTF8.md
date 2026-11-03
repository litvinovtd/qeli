# Q25-F171: desktop profile-store encoding

1 October 2026. Base: a1b64ece. D08 remains **IN_PROGRESS**.

Windows DPAPI and macOS AES-GCM stores decoded their decrypted JSON containers with Encoding.UTF8.GetString, which replaces malformed UTF-8 with U+FFFD. New serialized containers use valid UTF-8, but a legacy plaintext store or restored record could contain damaged bytes. Replacement before JSON parsing could silently alter a password or other string field. JSON is only an internal store container here; client configuration documents remain INI.

Both stores now use a UTF-8 decoder that throws on malformed input. Windows falls back to legacy plaintext only when DPAPI fails, not when already decrypted text fails decoding. The error follows the existing path that preserves damaged files separately. macOS then attempts the intended .bak recovery using the same strict check. Valid encrypted containers and the write format are unchanged.

QeliWin and QeliMac dotnet builds with --no-restore passed without warnings or errors; git diff --check passed. Loading a real damaged store and UI rollback on failed write were not tested; the latter remained a separate D08 criterion. Mac runtime and a Windows VM were unavailable under the agreed lab scope.
