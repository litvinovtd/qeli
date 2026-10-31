# Android / iOS functional parity audit, 28 October 2026

[Русский](../../ru/reports/IOS-ANDROID-PARITY-2026-10-28.md) · English

Source audit of `dev` for 0.8.4, based on `416db5ce`; the fixes below were in the
working tree at the time of this audit. It checks feature availability and specific
defects, not the absence of all bugs or certification of an iOS build. Parallel
server-identity, transport and website changes are outside this snapshot.

## Functional matrix

| Android area | iOS state after changes | Implementation / limits |
|---|---|---|
| Connect, disconnect, status, speeds and counters | Available | `AppModel`, `TunnelManager`, `ConnectionView`; Apple lifecycle needs runtime testing |
| TCP/UDP, plain/fake-TLS/obfs/REALITY, QUIC, AWG, PQ, padding, heartbeat, shaping, bonding, PMTU | Shared implementation | Rust whole-client core through `QeliFFI`; Swift does not duplicate the wire protocol |
| IPv4/IPv6, DNS, routes, pushed values, local exclusions | Available with platform applicability checks | `NativeNetworkPlan`, `QeliNativeTunnelEngine`; unsupported plans rejected before ACK |
| Reconnect, roaming, Wi-Fi/cellular, wake | Available; initial DNS failure and pending-update cancellation fixed | `InitialCarrierResolution`, `IOSRoamingController`; actual device transitions not tested |
| Route enforcement / bypass prevention | Apple mechanism, not Android lockdown equivalence | `TunnelManager.makeTunnelProtocol`: `enforceRoutes` also for split; full-tunnel capture retained |
| Profile create/edit/delete/copy/select/reorder | Available | `ProfilesView`, `ProfileEditorView`, `AppModel`; active-profile and stale-editor protections retained |
| INI, URI, clipboard, deep link, file, QR; link/QR sharing | Available; two differences fixed | `ProfileImportPolicy` preserves INI; `QRCode` uses AVFoundation without an A12 threshold |
| Manual availability probe | Available | Shared UDP probe / TCP connect; active VPN probes the authenticated gateway |
| Automatic profile probes and interval | Added | `ProfileAutoProbePolicy`, `AppModel`, `SettingsView`; foreground only, with system VPN disconnected |
| Encrypted storage and Android/iOS backup transfer | Available | `ProfileStore`, `BackupCrypto`, `SettingsView`; shared QELI-ENC-1; Keychain runtime not established by this run |
| Logs, time format, level, clearing after disconnect | Available | `SharedTunnelStore`, `LogsView`, `AppSettings`; ordinary automatic clearing retains errors |
| Current diagnostics and opt-in last-error report | Added | `DiagnosticJournalStore`, `DiagnosticReport`; at most one retained error report |
| Queue/carrier metrics in diagnostics | Added | C ABI 1.17 → `CarrierDiagnosticsSnapshot` → sampler/export; unavailable metrics are not replaced with zeros |
| Automatic scrolling of a full journal | Fixed | `LogsView` observes the last line ID rather than the unchanged buffer size |
| Theme, RU/EN, clearing and diagnostics settings | Available; translations extended | `AppSettings`, `SettingsView`, string catalogs, widget locale; system dialogs remain native |
| Connect on launch, trusted Wi-Fi rules | Available | `autoConnectOnLaunch`, VPN On Demand / `TrustedWiFiPolicy`; OS restart behavior is controlled by iOS |
| Widget / system tile | Apple equivalent available | WidgetKit, App Intent; Control Center/Lock Screen control on iOS 18 |
| Update check | Available, opt-in | Bounded public metadata request through protected full tunnel; installation follows iOS distribution rules |
| Arbitrary application selection, include/exclude apps | iOS restriction | Consumer apps cannot enumerate all installed apps or apply Android rules; Per-App VPN requires MDM |
| Android Always-on + system kill switch | No direct equivalent for custom Packet Tunnel | VPN On Demand is not Always-On; enforced Apple Always On is supervised IKEv2 |
| Android foreground notification, battery exemption, boot receiver | Android-specific | iOS uses NetworkExtension/On Demand and system lifecycle |
| Managed configuration | Available | `ManagedConfiguration`, MDM templates; managed policy takes precedence |

Platform restrictions were checked against Apple documentation:
[Per-App / On Demand / Always On VPN](https://support.apple.com/guide/deployment/vpn-overview-depae3d361d0/1/web/1.0)
and [enforceRoutes](https://developer.apple.com/documentation/networkextension/nevpnprotocol/enforceroutes).

Configurations remain INI. JSON is used for internal ABI messages, backup containers
and reports; it does not restore a JSON configuration editor. Recognized fields for
another platform survive editing without claiming iOS applies them. Windows IP-copy
buttons and charts are not presented as missing Android features.

## How the added features work

**Automatic probes:** Settings → Profile availability → Automatically check profiles.
Off by default; interval 30 seconds, range 10–3600. At most four unfinished probes
run concurrently, with at least 10 seconds between sweeps. Backgrounding, Connect
or a VPN state change cancels scheduling; a busy native worker retains its slot
until actual completion. An already started UDP probe cannot stop instantly: DNS
and two attempts have their own deadlines, usually up to 6 seconds in total.
Cancelled results are not published. Corrupt storage does not probe a demo profile.
Probing contacts the profile endpoint over the network.

**Reports:** Log → Report. The current report contains timestamps, session ID,
event category and available numeric metrics. Free-form log text, profile names,
network addresses and keys are excluded. Settings → Diagnostic reports → Keep
the last error report is off by default. Clear removes current data and the retained
error report; disabling retention removes the saved error report. Prepared exports
check the privacy revision before being handed to the system. A file already copied
to another application cannot be revoked.

The journal is bounded to 500 events/1 MiB; exported reports to 256 KiB. Native
carrier JSON is limited to 64 KiB and 32 rows; the intermediate metrics file to
128 KiB. Metrics are stored separately, so a sample does not rewrite the entire
event archive. Sampling is every 20 seconds plus a final sample at attempt end.
Local completion counts submission to the local transport writer, not a remote
client ACK. An unavailable final sample retains the last known value marked as
unavailable; a new VPN session clears old metrics.

**DNS and routes:** an initial transient DNS failure uses normal reconnect limits.
When the address is not yet known, resolution uses the physical interface so
tunnel protection does not block its own DNS. Disabled reconnect, retry limits
and cancellation remain enforced. A duplicate NWPath callback does not cancel
a pending debounce; losing and regaining the same network counts as an event.

## Verification and remaining boundaries

| Check | Result |
|---|---|
| Swift: portable policies, journal, metrics, DNS recovery, QR gate | 46 tests PASS, no warnings |
| Swift + actual Rust C API: reader, import, reconnect | 13 tests PASS, no warnings |
| Rust C ABI, including buffer bounds, invalid handles and panic containment | 22 tests PASS |
| Native build recipes and iOS package verifiers | 41 + 20 tests PASS |
| Swift syntax in Swift 5 mode | 116 files PASS; not an Apple SDK typecheck |
| RU/EN, placeholders, duplicates | 265 keys per language; PASS |
| Documentation and versions | 9 documentation checks and sync_version PASS |

Total: 59 executed Swift XCTest, Linux Swift 6.4.1, language mode 5, Rust 1.97.0,
single-job builds. Production logic was not replaced with stubs. Test native builds
on both servers produced the same SHA256:
`d31d1e7e86eb35f8bbbf209d216c79ed024aab289863085a7b07d0ba09874a0f`.

The initial native Swift run retained 4 FAIL: the Linux library intentionally does
not advertise the iOS packet data-plane capability, so creating the full Apple
transport adapter correctly failed. Tests were corrected to use an actual C
lifecycle handle and the same production reader; unsupported full-adapter refusal
is checked separately. Capability checks were not weakened. This is not an iOS
VPN running successfully on Linux.

Compact logs, source hashes and the initial FAIL are retained in the working
directory `mobile-parity-20261028`; temporary builds/compiler were removed,
freeing 4.42 GB on `.10`; the separate `.11` build was also removed. Original audit
archives were untouched. Platform route/UI/camera XCTest and two app-owned native
wrapper tests require Apple CI and remain NOT_RUN. The raw C fixture is Linux-only:
Apple bundles use the app library without linking another Rust registry copy.
After this split, the executed Linux test bodies were retained unchanged.
Tests use actual portable Swift sources and the new Rust C API without production
stubs. The isolated Rust snapshot excludes parallel changes. Linux Swift does not
replace Apple SDK/Xcode or qualify camera, Keychain, WidgetKit, NetworkExtension
or device OS callbacks.

An installable iOS build still needs an ABI 1.17 XCFramework rebuild and Apple CI
for app + Packet Tunnel + widget + XCTest; physical smoke/interop is separate.
Old libraries were not relabelled, and their provenance was not rewritten.
This audit does not publish a release.

Historical 37/37 audit decisions remain unchanged: accepted Android API34 ENONET
is unfixed, the original FAIL is retained, and user-excluded physical platforms
are not converted into PASS.
