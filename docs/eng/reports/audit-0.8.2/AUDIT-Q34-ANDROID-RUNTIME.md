# Q34 — Android build recipe and runtime evidence

<!-- normative-sync: audit-q34-android-runtime-v1 -->

Date: 24 September 2026. Base: `ff2720ba8b8c444de8bbe2e94e7901614c301713`
plus the working changes in this phase. Partial D08/D11/D12 closure in the
[debt register](../../plans/AUDIT-DEBT.md) for already started sections 02/22/34.
This run neither starts nor completes the full Android audit (29).

## Q34-F002, P2 — the standard Android JNI build failed to start

`build_client_core.py --android` used the repository root as cwd, although the
Cargo workspace lives in `qeli/`. cargo-ndk 4.1.2 reads metadata before forwarding
`--manifest-path`; the original helper failed because Cargo.toml was missing.
Fixing cwd exposed a second reproducible failure: `-p 28` does not select the
Android API level. The helper now uses `--platform 28`.

Cargo runs from `qeli/`; dev/CI and release A/B remain separate recipes.
The corrected standard helper built x86_64 JNI using Rust 1.97.0, NDK 26.3.11579264
and cargo-ndk 4.1.2, `--debug --offline --locked`, no default features and
`transport-core-ffi`. The Linux-only strict sysctl lock method is now gated on
Linux instead of every Unix, removing an unused Android method without changing Linux.

## Q34-F003, P3 — the obsolete Android harness exercised a removed format

Removed `e2e_android.py` (under `scripts/`): it generated JSON configs and injected old
plaintext preferences, so it could not validate the current INI and encrypted
storage contract. No active CI consumers were found. The separate
`e2e_android_udpquic.py` remains and was not executed in this phase.
Internal JSON APIs, test fixtures and storage containers remain supported.

Two packaged ConfigCore JNI instrumentation regressions were added: INI
parse/serialize/parse with `mtu_probe=off`, and rejection of a JSON config and a
link with an injected newline. Existing `connectedDebugAndroidTest` CI runs them.

## Validation and artifact provenance

- **154 JVM tests PASS**, no failures/errors/skips, using the current host DLL through JNI.
- **6 Android instrumentation tests PASS** on Android 14 / API 34 / x86_64:
  two ConfigCore, two Android Keystore (encrypted round-trip, tamper/AAD refusal),
  one private diagnostic journal, and one production `VpnService.Builder.establish`
  exercising split IPv4, full IPv4 and dual-stack plans.
- **1458 host unit + 71 config integration PASS**, all 9 Rust feature/cross/lint commands PASS.
  Host Rust 1.98; cross-Clippy retains the single pre-existing
  `clippy::chunks_exact_to_as_chunks` allowance, with no new allowances.
- The last full Linux run on base `ff2720ba`: **1922 + 28 privileged + 8 worker
  lifecycle E2E PASS**. The full Linux suite was not rerun after the cfg-only edit;
  cross-checks passed and the Linux code branch is unchanged.

Gradle 9.7.1 built the APK using `QELI_NATIVE_JNI_DIR`, replacing committed jniLibs.
ZIP contents were checked: only the fresh x86_64 libqeli.so, with a hash matching
the Linux build output. Dev x86_64 does not certify arm64 or release A/B.

| Artifact | SHA256 |
|---|---|
| Host DLL | `0810991935ef02423c2e0d2be0454ac6bfd1de0d3991dc472512ee3a1a78126f` |
| Android libqeli.so | `4927d240f5f0264ae226e43c948d0538fb1187d3bc517ca695af02013fadb542` |
| app-debug.apk | `e7720d27062687c11a3c4689190fa7027de59b1aafea42d52a955c9947ab3eae` |
| app-debug-androidTest.apk | `9e01ed8cfcd00a54ed31c1243d25660a0fd71cdf40a0a92b6c4bcd5fb36a4aa7` |

The environment was a dedicated read-only `test` AVD session on the client Linux
VM, emulator 36.6.11.0, with snapshot loading/saving disabled. The missing
libxkbfile1 dependency was installed. Retained signing records for old main/test
APKs were removed only inside the disposable session. Diagnostic `ip link` used
`su 0` because Android denies netlink to the ordinary ADB shell. Instrumentation
itself used the normal Android test runner. Failed setup attempts are retained separately.

No TUN remained after force-stopping the app. Original userdata image sizes,
mtimes and SHA256 hashes matched after emulator shutdown. The running Qeli server
and its configs were not changed.

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`:
`android-runtime-phase/` (build/JVM/matrix/source manifests),
`android-runtime-evidence-4/` and `android-instrumented-netdiag.log` (final PASS).
`android-runtime-evidence`, `-2`, `-3` contain setup failures, not successful tests.

## Remaining scope

Remote VPN handshake/traffic, roaming/soak, other Android APIs/ABIs, Windows network
runtime, Mac/iOS/router runtime and release A/B/provenance are unverified.
D08 and D11 remain IN_PROGRESS; D12 retains unconfirmed external environments.
The full configuration matrix and a current benchmark remain open. Existing
Gradle/Java warnings and a deprecated Android API are not fixed by this validation.

[Reproduction](../../../../qeli-android/README.md) · [Shared core](../../plans/CLIENT-CONFIG-CORE.md)
