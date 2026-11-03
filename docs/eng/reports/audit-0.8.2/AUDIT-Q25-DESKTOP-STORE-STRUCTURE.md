# Q25-F185: desktop profile-store structure

1 October 2026. Base: 38462475. D08 remains **IN_PROGRESS**.

After decryption, deserializing a root JSON null returned null, which Windows/macOS code replaced with an empty profile list. A later save could persist that emptiness over the original encrypted file. An array with a null element reached the UI as a list with a missing row and could fail later. JSON here is only an internal encrypted-list container; user config remains INI.

Shared ProfileStorePayload.Decode now requires an array root and forbids null entries. Both Load paths validate before admitting the list to UI; macOS .bak recovery uses the same check. Failure follows the existing fail-closed path that preserves an unreadable store for manual recovery. A genuine empty array remains valid because desktop UI permits deleting every profile.

Shared conformance selftest passed for an empty array, null root and null element. QeliWin/QeliMac --no-restore builds had zero warnings or errors; git diff --check passed. Platform UI runtime was not verified without Windows/macOS labs.
