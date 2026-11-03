# Q25-F188: mobile store and backup bounds

1 October 2026. Base: aa0397d6. D08 remains **IN_PROGRESS**.

Android Activity checked profile JSON after decryption, but SecureStore first decoded unbounded base64 and AES-GCM envelopes from SharedPreferences. Direct SecureStore or migration calls could also write more than 8 MiB. BackupCrypto accepted encrypted archives without its own direct-call limit and decoded authenticated plaintext with replacement UTF-8, possibly changing damaged INI or credential bytes to U+FFFD. Open JSON backup in Activity had the same decoding issue.

SecureStore now checks base64 length before decoding, binary envelope length afterwards and the 8 MiB plaintext bound before writing and after decryption. A small pure Kotlin ProfileLimits defines 8 MiB for a JSON archive, 12 MiB for a portable encrypted file and 256 profiles. BackupCrypto checks sizes before PBKDF2/AES, strictly decodes envelope and plaintext UTF-8 and clears temporary plaintext. Open backup in Activity checks 8 MiB before decoding and uses the same strict decoder. Malformed encrypted archives are no longer misreported as passphrase errors; only GCM authentication failure receives that message. Invalid archives leave existing profiles intact.

Size contract: individual INI 256 KiB; portable Android/iOS JSON backup 8 MiB; encrypted backup 12 MiB. Internal Android SecureStore permits 8 MiB plaintext plus a 29-byte AES-GCM envelope encoded in base64; iOS bounds its internal plaintext to 8 MiB. Desktop profiles.json is a separate encrypted internal format with a 16 MiB file cap. That difference is intentional and does not affect mobile backup compatibility; blind numerical unification of all containers is no longer required.

164/164 Android JVM tests passed, including new boundary cases and an authenticated archive with malformed UTF-8. assembleDebug, assembleDebugAndroidTest and git diff --check passed. Two new instrumentation scenarios for real Android Keystore were built but not run because .11 emulator access was rejected. Device testing is not claimed.
