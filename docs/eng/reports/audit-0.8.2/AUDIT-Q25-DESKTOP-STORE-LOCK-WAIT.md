# Q25-F184: bounded desktop profile-store lock wait

1 October 2026. Base: 99edf3a7. D08 remains **IN_PROGRESS**.

Q25-F178 added a shared sidecar lock, but AcquireLock immediately returned IOException under short contention. A second instance could fail to load profiles on simultaneous startup or reject a save even though the first would release the lock milliseconds later. GUI load ran in the window constructor, turning a transient lock into a startup error.

AcquireLock now retries only IOException with a monotonic one-second budget and short 25 ms steps. After the deadline the error propagates, so a stuck owner cannot block the UI indefinitely. Directory-creation errors and other exception types are not retried. File-version checking after lock acquisition remains unchanged: waiting never authorizes a stale write.

Conformance selftest checks refusal under a continuously held lock, a second reader waiting, and successful read after release. The full suite passed; QeliWin/QeliMac --no-restore builds had no warnings or errors; git diff --check passed. Cross-process UI testing on Windows VM and Mac is unavailable under the agreed exclusion.
