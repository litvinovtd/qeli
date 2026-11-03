# Q25-F183: bounded desktop profile-store reads

1 October 2026. Base: 220aed55. D08 remains **IN_PROGRESS**.

Windows/macOS ProfileStoreFile read all of profiles.json before decryption and structural checks. Revision verification after external replacement also hashed the whole file, while macOS .bak recovery read unbounded bytes. A damaged or substituted huge file could consume memory and delay startup or saving.

The encrypted desktop store now has a 16 MiB file limit. Read checks the opened file length before allocation and reads in chunks, rechecking the limit if it grows during I/O. The same budget covers revision checks, writes and macOS .bak. Oversize input throws IOException before decryption and is not quarantined, preserving original bytes for manual recovery. This limit exceeds the mobile 8 MiB plaintext budget to allow for desktop format overhead and existing profiles; numerical alignment of every container remained a D08 question at this stage. Both client READMEs state the bound.

Shared conformance selftest passed, including oversized load, external replacement with an oversized file and refusal of oversized writes without changing the file. QeliWin/QeliMac --no-restore builds had zero warnings and errors; git diff --check passed. Real Mac runtime and a Windows VM were unavailable by user decision.
