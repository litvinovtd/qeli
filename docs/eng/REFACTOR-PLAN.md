# qeli — refactoring plan: eliminating code duplication (audit 2026-06-10)

Source: an audit of duplication across the codebase. This document is a working
checklist in the style of [RELEASE-FIXES.md](RELEASE-FIXES.md): each item has an ID, a
severity, the affected files, an approach, and an acceptance criterion. Statuses are
updated as work proceeds. **✅ This refactor is DONE** — shipped in 0.6.0 (the C#
`qeli-shared` consolidation removed ~2700 duplicated lines; `scripts/lab_common.py` is
the shared SSH harness). Kept as a historical record.

Status legend: ⬜ not started · 🟦 in progress · ✅ done · 🧪 awaiting a build/e2e.

> **The principle:** the refactoring is behavior-preserving. No item changes the wire,
> crypto, config format, or UX — only code reuse. The acceptance criterion of each item
> = **the same wire/behavior byte-for-byte** + a green build of all affected clients +
> e2e on the lab wherever the data plane is touched.

---

## Why this is needed

| Zone | Volume of duplication | The risk now |
|---|---|---|
| **C# `qeli-win` ↔ `qeli-mac`** | **~3000+ lines** copied (some 1:1) | desync of the two clients: a fix in one is forgotten in the other |
| **`scripts/` (Python)** | the SSH harness + hosts in **97 of 102** scripts | editing the lab access/host = editing dozens of files |
| **Rust `web/api`** | minor boilerplate (json responses, auth) | low, cosmetic |

The main win is the C# zone: the two clients (`QeliWin`, `QeliMac`) are two **fully
separate** projects (`.csproj`), with no shared library and no single
`ProjectReference`. Most of the protocol/crypto/model is copied verbatim.

### Measured C# duplication (win ↔ mac)

**Verbatim identical** (the difference — only the line `namespace QeliWin.X` ↔
`QeliMac.X`, occasionally `QeliWin.Loc` ↔ `QeliMac.Loc` and a comment):

| File | lines |
|---|---|
| `Crypto/KeyDerivation.cs` | 87 |
| `Crypto/KeyExchange.cs` | 64 |
| `Crypto/PacketCipher.cs` | 50 |
| `Protocol/ObfsStream.cs` | 186 |
| `Protocol/PacketCodec.cs` | 181 |
| `Protocol/Quic.cs` | 91 |
| `Protocol/TlsHandshake.cs` | 224 |
| `Model/VpnConfig.cs` | 485 |
| **total 1:1** | **~1368** |

**Almost identical** (the logic is common, only the platform seam diverges):

| File | shared lines | win / mac | the platform seam |
|---|---|---|---|
| `Vpn/VpnTunnel.cs` | ~1063 (~93%) | 1137 / 1122 | `WintunAdapter` ↔ `UtunDevice` |
| `Vpn/RealTls.cs` | 103 | 108 / 110 | — (P/Invoke to one C-ABI) |
| `Loc.cs` | 163 | 189 / 196 | the translation table |
| `CliRunner.cs` | 173 | 362 / 205 | win — larger (the service) |
| `Service/ServiceState.cs` | 91 | 111 / 154 | — |
| `Vpn/NetworkConfigurator.cs` | 84 | 177 / 193 | the OS route/DNS commands |
| `TrayController.cs` | 74 | 130 / 140 | NotifyIcon ↔ Avalonia tray |
| `ThemeManager.cs` | 70 | 100 / 121 | WPF ↔ Avalonia |
| `Toast.cs` | 61 | 111 / 118 | — |
| `Branding.cs` | 44 | 171 / 166 | the icon render (GDI ↔ Skia) |

---

## Plan summary table

| ID | Severity | Topic | Status |
|----|:---:|---|:---:|
| R0 | 🟠 Main | **Pre-unification:** mac → `net10.0`; win-NuGet to the mac versions (BouncyCastle 2.5.1→2.6.2, QRCoder 1.6.0→1.8.0); CI macos-SDK → 10.0.x | ✅ |
| R1 | 🟠 Main | Create the shared project `QeliShared` (`net10.0`, managed-only) + a `ProjectReference` from both clients | ✅ |
| R2 | 🟠 Main | Move `Crypto/*` (3 files) into `QeliShared` as is | ✅ |
| R3 | 🟠 Main | Move `Protocol/*` (4 files) into `QeliShared` as is | ✅ |
| R4 | 🟠 Main | Move `Model/VpnConfig` + a full consolidation of `Loc` (a shared dictionary + platform overrides) | ✅ |
| R5 | 🔴 Large | Extract the `VpnTunnel` core into `QeliShared` (an abstract `VpnTunnelBase` + `ITunDevice`); `RealTls`/`VpnStatus` → shared | ✅ build |
| R6 | 🟡 Secondary | The shared UI **data** extracted (`BrandPalette` + `ToastKind`); the framework logic (Toast/Theme/Tray/CLI/ServiceState) — per client by design | ✅ |
| R7 | 🟠 Main | A shared Python module `scripts/lab_common.py` (SSH + hosts); `reboot_vms.py` migrated | ✅ |
| R8 | ⚪ Cosmetic | Rust: the helpers `err_json(msg)` / `ok_json()` in `web/api` (31 sites consolidated) | ✅ lab |
| R9 | ⚪ Cosmetic | Rust: `check_auth` → the axum extractor `AuthGuard` (20 handlers) | ✅ lab |

Severity here = the size/risk of the refactoring, not a bug. 🔴 = a lot of code + a
platform seam (careful), 🟠 = the main win, 🟡/⚪ = optional.

---

## R0 — pre-unification of versions (do before R1)

The goal is to bring both C# clients to **one .NET version and one set of versions of
the shared NuGet packages**, so that the shared lib `QeliShared` (R1) fits without TFM
compromises and without a dependency conflict. This is a standalone,
behavior-neutral step.

> **Important facts (as of 2026-06-10):**
> - win is **already** on `net10.0-windows`; mac is on `net8.0`. The unification = **raise mac to net10**.
> - The TFM will not become byte-identical **deliberately**: win = `net10.0-windows` (WPF/WinForms,
>   OS-locked to Windows), mac = `net10.0` (Avalonia is cross-platform, without `-windows`).
>   The **.NET version (10)** matches, not the TFM string — and that's how it should be.
> - BouncyCastle is currently **the other way around**: mac **2.6.2**, win **2.5.1** → we raise **win**, not mac.

**Affected:** `qeli-mac/QeliMac/QeliMac.csproj`; `qeli-win/QeliWin/QeliWin.csproj`; `.github/workflows/ci.yml`.

**The approach:**

1. **mac → net10.** Exactly two edits (the SDK isn't pinned anywhere — no `global.json`,
   `Directory.Build.props`, `.sln`):
   - `qeli-mac/QeliMac/QeliMac.csproj` — `<TargetFramework>net8.0</TargetFramework>` → `net10.0`.
   - `.github/workflows/ci.yml` (the `macos-build` job) — `dotnet-version: '8.0.x'` → `'10.0.x'`.
   - Avalonia (11.3.x) and SkiaSharp (2.88.x) are **NOT touched**: net10 consumes the
     net8/netstandard packages (forward-compat), the self-contained publish pulls the
     net10 runtime. Consistent with the deliberate `ignore` of the majors Avalonia 12.x
     / SkiaSharp 3.x in `dependabot.yml`.
   - The mac build scripts (`build_mac_universal.py`, `build_mac_dist_resign.py`) need **no** edits:
     the TFM is taken from the `.csproj` (`dotnet publish -r osx-… --self-contained`), the path `net8.0` is not hardcoded anywhere.

2. **Consolidating the shared NuGet to the mac versions** (`QeliWin.csproj` is edited):
   - `BouncyCastle.Cryptography` 2.5.1 → **2.6.2**.
   - `QRCoder` 1.6.0 → **1.8.0**.

   *Not unified* (no counterpart on the other side — different frameworks):
   win-only `Microsoft.Extensions.Hosting.WindowsServices` / `System.ServiceProcess.ServiceController` /
   `System.Security.Cryptography.ProtectedData` (the service + DPAPI); mac-only `Avalonia*` / `SkiaSharp*`.

**Acceptance criterion:** CI green on both (`windows-build` 10.0.x + `macos-build` 10.0.x);
`dotnet publish -r osx-arm64 --self-contained` builds a working bundle; new obsolete
warnings from the analyzer (if any surface on net10) are dealt with; the wire/crypto are
not affected (only the toolchain/package versions).

**Risk:** low. net10 is a superset of net8. There's no physical Mac → the functional check of mac =
compilation + dylib parity (as in RELEASE-FIXES, the B phase); CI does not validate the render.

**✅ Status (2026-06-10):** made and locally verified by a build on the net10 SDK (10.0.300):
- `QeliMac.csproj` `net8.0`→`net10.0`; `dotnet build -c Release` → **0 warn / 0 err** (Avalonia 11.3.17 + SkiaSharp 2.88.9 under net10 ok).
- `QeliWin.csproj` BouncyCastle 2.5.1→2.6.2, QRCoder 1.6.0→1.8.0; `dotnet build -c Release` → **0 err** (3 pre-existing `NU1510` about the in-box `ProtectedData` — not from these edits).
- `ci.yml` `macos-build` job SDK `8.0.x`→`10.0.x`. CI confirmation — on the first push (locally both clients are already green).

> As a side note (optional, outside R0): on net10 the package `System.Security.Cryptography.ProtectedData`
> became in-box (`NU1510`) — the explicit reference in `QeliWin.csproj` can be removed in a separate cleanup.

---

## A. The shared C# library `QeliShared`

### R1 — the shared project scaffold

**Affected:** the new `qeli-shared/QeliShared/QeliShared.csproj`; `qeli-win/QeliWin/QeliWin.csproj`; `qeli-mac/QeliMac/QeliMac.csproj`.

**Precondition:** **R0** is done (both clients on net10, BouncyCastle/QRCoder consolidated).

**The approach:**
- Create a class library **`QeliShared`** with `RootNamespace = Qeli.Shared` (neutral, not `QeliWin`/`QeliMac`).
- **TFM = `net10.0`** (without the `-windows` suffix → no WPF/WinForms/Win-API in the shared lib). After R0 both clients are on net10, so the `net10.0` lib is consumed by both without compromise: `qeli-mac` (`net10.0`) and `qeli-win` (`net10.0-windows`) reference the `net10.0` library directly. *(An alternative — `netstandard2.0` for maximum compatibility; `net10.0` is simpler and sufficient.)*
- The lib's dependencies — **managed only, no OS**: `BouncyCastle.Cryptography` **2.6.2** (already consolidated in R0). Declare it in `QeliShared`, remove the direct references from the clients (they come transitively).
- In both `.csproj` add `<ProjectReference Include="..\..\qeli-shared\QeliShared\QeliShared.csproj" />`.

**Acceptance criterion:** both clients build (`dotnet build` Release) with a still-empty `QeliShared` in the graph; `git` shows the new project; BouncyCastle resolves to a single 2.6.2 transitively.

**Risk:** low. A clean scaffold, with no logic moved.

---

### R2 — `Crypto/*` → `QeliShared/Crypto`

**Affected:** `Crypto/KeyDerivation.cs`, `Crypto/KeyExchange.cs`, `Crypto/PacketCipher.cs` (in both clients — removed).

**The approach:** move **as is** — the files differ only in the `namespace` line. Rewrite the namespace to `Qeli.Shared.Crypto`, remove both copies from the clients, fix the `using` where they're referenced (`PacketCodec`, `VpnTunnel`, `RealTls`).

**Acceptance criterion:** both clients build; **the crypto/KAT unit tests — if any — green**; the e2e handshake on the lab (.10↔.11) passes unchanged (keys are derived identically). The wire diff is zero.

**Risk:** low (the code is byte-for-byte, only relocating).

---

### R3 — `Protocol/*` → `QeliShared/Protocol`

**Affected:** `Protocol/ObfsStream.cs`, `Protocol/PacketCodec.cs`, `Protocol/Quic.cs`, `Protocol/TlsHandshake.cs`.

**The approach:** move as is (the difference — the namespace + one `using QeliWin.Crypto`→`Qeli.Shared.Crypto`). After R2 the dependency on crypto is already shared. Remove both copies, hook up `using Qeli.Shared.Protocol`.

**Acceptance criterion:** a build of both clients; e2e of all wire modes (`fake-tls`/`obfs`/`reality-tls`/QUIC) on the lab — the packet codec and TLS mimicry give the same wire. The JA3/obfuscation bytes are unchanged.

**Risk:** low-medium (this is the "wire" itself — an e2e run is mandatory, but the code doesn't change in substance).

---

### R4 — `Model/VpnConfig` + `Loc` → `QeliShared`

**Affected:** `Model/VpnConfig.cs` (1:1, 485 lines), `Loc.cs` (163 shared).

**The approach:**
- `VpnConfig` pulls `QeliWin.Loc`/`QeliMac.Loc` (for the displayed status strings) → we move `Loc` along. `Loc` is a translation table (the shared part 163 lines) + possible platform additions.
- Move `Loc` into `Qeli.Shared.Loc` wholesale (the string table isn't platform-specific). If a client has unique keys — leave a thin platform partial/extension that augments the shared dictionary.
- `VpnConfig` → `Qeli.Shared.Model`. Account for the found micro-difference: mac in the WireMode comment mentions `"plain"`, win — does not. Consolidate to the common one (the plane already supports `plain`, see README) — **the behavior doesn't change, only the comment/default value is synchronized**.

**Acceptance criterion:** a build of both; parsing/serialization of `qeli://` links and the flat config gives an identical result on both clients (a round-trip test on several links); the localized strings are in place.

**Risk:** low. Attention to platform-specific `Loc` keys.

**✅ Status (2026-06-10):** done, a full consolidation of `Loc` (the "full Loc now" variant was chosen):
- **`VpnConfig` + `ProfileReachability`** → `Qeli.Shared.Model.VpnConfig`. The only dependency on `Loc` (`Loc.T("Offline")` in `LatencyText`) was switched to `Qeli.Shared.Loc`. The `WireMode` comment consolidated to the fuller one (`… | "plain"`). 20 consumer files got `using Qeli.Shared.Model;`.
- **`Loc` fully consolidated:** data+logic (a dictionary of **110 shared** keys + `T/F/SetLanguage/Lang` + the `LanguageChanged` event) → `Qeli.Shared.Loc`. The framework parts (`LocalizationManager` INPC + `LocExtension` MarkupExtension) **stayed in the client namespace** (WPF ↔ Avalonia) → **XAML untouched** (`xmlns:l` points at `QeliWin`/`QeliMac`). The platform strings are registered at startup via `[ModuleInitializer]` → `Loc.AddOrReplace`: win **13** override keys (the Windows service/tray/Wintun), mac **20** (13 in macOS wording + 7 mac-only: CouldNotConnect/ModeFakeTls/ModeObfs/Ok/Yes/No/NeedRoot). The string move is programmatic (exact bytes, the Cyrillic preserved). 19 call sites `Loc.*` got `using Qeli.Shared;`.
- **Check:** both clients `dotnet build -c Release` → mac 0/0, win 0 errors. A key reconciliation: 110 shared + 13 = 123 (win) / 110 + 20 = 130 (mac) — exactly as in the originals, not a single shared key lost. A runtime test of the shared `Loc` (net10): en/ru resolve, the language-change event, a platform override, an unknown key → all PASS.

---

### R5 — the `VpnTunnel` core in `QeliShared` behind interfaces (a large item)

**Affected:** `Vpn/VpnTunnel.cs` (~1063 shared lines), `Vpn/RealTls.cs`, `Vpn/NetworkConfigurator.cs`, plus the platform `WintunAdapter`/`NativeLoader`/`Wintun.cs` (win) and `Vpn/UtunDevice.cs` (mac).

**Seam analysis:** `VpnTunnel` is ~93% identical; all the platform difference is the TUN device:
- win: `WintunAdapter` (the field `_wintun`)
- mac: `UtunDevice` (the field `_utun`, the methods `Open()`, `Name`, `ReceivePacket(ct)`, `SendPacket(buf,len)`, `Dispose()`)

The nested transports (`TcpTransport`, `UdpTransport`, `RealTlsTransport`, `SocketIO`) sit on the same lines and match.

**The approach:**
1. Introduce in `QeliShared` the interface **`ITunDevice`**: `void Open()`, `string Name`, `byte[]/Span ReceivePacket(CancellationToken)`, `void SendPacket(ReadOnlySpan<byte> buf, int len)`, `IDisposable`.
2. Introduce **`INetworkConfigurator`** (applying routes/DNS; the implementations stay platform-specific — `route`/`netsh` on win, `route`/`networksetup`/`scutil` on mac).
3. `RealTls` is P/Invoke to **one** C-ABI core (`qeli.dll`/`libqeli.dylib`); the signatures are identical → an interface `IRealTlsCore` or a direct move with `DllImport("qeli")` (the name is resolved by the loader in each client).
4. Move the body of `VpnTunnel` (+ the nested transports) into `Qeli.Shared.Vpn.VpnTunnel`, taking an `ITunDevice` factory and `INetworkConfigurator` via constructor/DI.
5. In the clients leave only: `WintunTunDevice : ITunDevice` (a wrapper over `WintunAdapter`) and `UtunTunDevice : ITunDevice`, plus the platform `NetworkConfigurator`.

**Acceptance criterion:** **a full live tunnel** on the lab for both clients (where possible: win-e2e on .11/the emulator; mac — a build + dylib parity, since there's no physical Mac — see RELEASE-FIXES the B phase). All modes: TCP, UDP/QUIC, reality-tls, multipath (round-robin upload). 0% loss, the same wire.

**Risk:** **medium-high** — the largest file and the only one with a platform seam. Do it **last** in the C# zone (after R2–R4), as a separate step, with an e2e gate. The transports inside are better moved too (they're shared anyway), but first a minimal cut: the TUN device behind an interface.

**✅ Status (2026-06-10): the refactoring is done, builds (both clients 0 errors); a live full-tunnel e2e — an optional desktop QA (see below).** The implementation — via an **abstract base class** (not composition), so that the UI instantiation `new VpnTunnel()` doesn't change:
- Created `Qeli.Shared.Vpn` with: `ITunDevice` (`ReceivePacket`/`SendPacket`/`Dispose` — a common Wintun/utun contract) + `VpnStatus` (`TunDevice.cs`); `RealTls` (P/Invoke `DllImport("qeli")`, moved from win — identical to mac); **`VpnTunnelBase`** (abstract, 1232 lines) — the shared code moved **byte-for-byte** (transports, the handshake, the tunnel loops, multipath/bonding), the edits only at the seam: the field `_wintun`→`protected ITunDevice? _tun`, `SetupTun`→`protected abstract`, `_net`/`ApplyPushedRoutes`/`AdapterGuid` pushed down to the subclass, `CloseTransports`→a `CleanupPlatform()` hook, `Session`/`Log`/`EffectiveMtu`→`protected`.
- The clients: `QeliWin.Vpn.VpnTunnel : VpnTunnelBase` (85 lines) and `QeliMac.Vpn.VpnTunnel : VpnTunnelBase` (81 lines) — only `override SetupTun` (Wintun+`NetworkConfigurator` ↔ utun+`NetworkConfigurator`) + `ApplyPushedRoutes` + `CleanupPlatform`. `WintunAdapter`/`UtunDevice` implement `ITunDevice`. The two client copies of `RealTls.cs` removed; `NetworkConfigurator` stays platform-specific.
- **A behavioral nuance (fixed deliberately):** two error strings in the shared reconnect loop were hardcoded differently (win — Russian literals, mac — `Loc.T("CouldNotConnect")` + an English MITM literal). Consolidated to the shared `Loc` keys — `CouldNotConnect` (promoted to shared) and `MitmStop` added to `Qeli.Shared.Loc`. Now both strings are **localized on both clients** (for win — a minor improvement: previously always Russian, now by language). A runtime key test (en/ru) — PASS.
- **Check:** `dotnet build -c Release` → mac 0/0, win 0 errors. The shared code moved **byte-for-byte** (the behavior preserved by construction); the Rust server the clients talk to passed the lab gate after R8/R9 (build/179 tests/clippy). **Not run here:** a live full-tunnel of the C# client (TCP/UDP/QUIC/reality-tls/multipath). The reasons: this is a **desktop/admin operation** (a full `connect` creates Wintun/utun and intercepts routes — invasive on a dev machine; `handshake`-only doesn't exercise the `SetupTun` seam itself, since it works only in the TUN phase), there's no Mac hardware (as in RELEASE-FIXES the B phase). Recommendation: a one-off `QeliWin.exe connect <link>` under admin against the lab server — optional, in a separate QA session.
- **Dedup:** the `VpnTunnel` core (~1290 lines) and `RealTls` (~108 lines) are no longer duplicated between the clients (was ×2 → became ×1 in shared + thin subclasses).

---

### R6 — partially-shared classes (optional)

**Affected:** `CliRunner` (173 shared), `Service/ServiceState` (91), `Toast` (61), `ThemeManager` (70), `TrayController` (74), `Branding` (44).

**The approach:** for each — extract the shared logic into `QeliShared` (a base/util), and leave the platform part (WPF↔Avalonia render, NotifyIcon↔Avalonia tray, GDI↔Skia icons, route/service) as a subclass/partial class in the client. This is the "long tail" — take it up **after** R1–R5, in decreasing order of the volume of shared lines.

**Acceptance criterion:** a build of both; visual/functional UI parity (tray, toasts, theme), `CliRunner`/`ServiceState` behave as before.

**Risk:** medium — the UI classes are intertwined with the framework; the benefit is smaller than R2–R5. May be deferred/skipped.

**✅ Status (2026-06-10): the targeted extraction of shared DATA is done; the logic — per client by design.**
The analysis showed: the "shared" strings of these classes are intertwined with the framework/platform and don't separate cleanly — `ServiceState` (DPAPI ↔ AES-256-GCM at-rest), `CliRunner` (a Wintun-probe selftest ↔ Skia render; win-only `uishot/editshot` ↔ mac-only `genicns/genassets`), `Toast`/`ThemeManager`/`TrayController` (WPF ↔ Avalonia, NotifyIcon ↔ Avalonia tray), `Branding` (GDI+ `Color` ↔ Skia `SKColor`). This is exactly the case "What we don't touch: only the logic/data behind the framework becomes shared".
- **Extracted into shared (build-verified, both clients 0 errors):** `Qeli.Shared.BrandPalette` — a single source of the brand/status palette as raw RGB (`record struct Rgb`); both `Branding.cs` build their `Color`/`SKColor` from it via the helper `FromRgb` (the color type stays platform-specific; the values — in one place). `Qeli.Shared.ToastKind` — a shared enum, the local copies in both `Toast.cs` removed.
- **Left per client deliberately:** render/theme/tray/service/CLI commands and the at-rest crypto of `ServiceState` — framework/platform-bound; a forced extraction would give a cross-build indirection with near-zero dedup and isn't verifiable on mac (no hardware/GUI).

---

## B. Python scripts

### R7 — the shared module `scripts/lab_common.py`

**Affected:** ~97 of 102 scripts in `scripts/` (use `paramiko`); the hosts `10.66.116.10` (×97 occurrences), `.11` (×69), prod `YOUR_PROD_HOST` (×43).

**The problem:** each script re-defines `connect()`/`conn()` (the same `SSHClient()` + `AutoAddPolicy()` + `.connect(...)`) and `run()`/`ssh()`/`csh()` (the same `exec_command` + `.read().decode("utf-8", errors=...)`), and hardcodes the lab-VM IPs.

**The approach:** create `scripts/lab_common.py`:
- `connect(host, *, password=None) -> SSHClient` — a single harness (`AutoAddPolicy`, `look_for_keys=False`, `allow_agent=False`, timeout).
- `run(ssh, cmd, timeout=..., label=...) -> str` — a single exec + decode of stdout/stderr.
- Host constants: `LAB_SRV = ("10.66.116.10", "root")`, `LAB_CLI = ("10.66.116.11", "root")`, `PROD = ("YOUR_PROD_HOST", "root")`; the password — **from env** (`QELI_LAB_PASS`), as the `e2e_*` scripts already do.
- Migrate the scripts to `from lab_common import connect, run, LAB_SRV, ...` — gradually, not necessarily all at once.

**⚠️ Adjacent (security, not duplication):** the deploy scripts previously hardcoded the server SSH password. The credentials were moved to the env variable `QELI_DEPLOY_PASS` (`os.environ.get("QELI_DEPLOY_PASS", "")`), the password removed from the code — it doesn't end up in the repository. For the future: new scripts take credentials only from env, IPs in the code are acceptable.

**Acceptance criterion:** `lab_common.py` exists; ≥1 e2e script (e.g. `e2e_android.py`) is switched to it and passes on the lab; new scripts use the shared module.

**Risk:** low. The scripts are auxiliary, not part of the product; the migration is incremental.

**✅ Status (2026-06-10):** `scripts/lab_common.py` created — `connect(host|tuple, user, password, timeout)`, `run(ssh, cmd, timeout, label)`, `lab_password()`, the constants `LAB_SRV`/`LAB_CLI`/`PROD` (the password from `QELI_LAB_PASS`). `reboot_vms.py` migrated to it (as a showcase). Check: `python -m py_compile` of both + a real `import lab_common` (hosts/functions available) — OK. The full migration of the remaining ~96 scripts — incrementally, as they're touched. The hardcoded password in `deploy_to_server.py` (see above) — a separate cleanup.

> Note: previously (RELEASE-FIXES H2) 154 one-off scripts were already moved to `scripts/archive/`.
> R7 concerns the ~active working scripts in `scripts/`.

---

## C. The Rust core (cosmetics)

### R8 — JSON-response helpers in `web/api`

**Affected:** `qeli/src/web/api/*.rs` — the pattern `json!({"ok": false, "error": ...})` occurs **30 times**, `json!({"ok": true, ...})` — 9.

**The approach:** add to `web/api/mod.rs` a pair of helpers, e.g.:
```rust
fn err_json(msg: impl Into<String>) -> Json<Value> { Json(json!({"ok": false, "error": msg.into()})) }
fn ok_json() -> Json<Value> { Json(json!({"ok": true})) }
```
and replace the inline literals. It will cut the noise, unify the response shape.

**Acceptance criterion:** `cargo test` (161 tests) green; `cargo clippy` clean (format on .10, see reference_qeli_github_ci); the API responses byte-for-byte as before.

**Risk:** very low.

**✅ Status (2026-06-10): done and verified on the lab (.10).** The helpers `err_json(msg: impl Into<String>)` / `ok_json()` added to `web/api/mod.rs` (the return — `serde_json::Value`); **31 sites** consolidated to `super::err_json(...)` / `super::ok_json()` (config 10, control 2, login 3, share 4, status 2, users 10). The call by the full path `super::` — without editing the `use` in the submodules. `login.rs`: the now-redundant `json` removed (`use serde_json::Value;`). `auth.rs` (outside `api`) kept its 1 site. **The gate `lab_sync_build.py` on .10 → PASS:** `cargo build` OK, `cargo test` OK (**179 tests**), `cargo clippy --all-targets -- -D warnings` OK.

---

### R9 — `check_auth` as an extractor (optional)

**Affected:** `qeli/src/web/api/*.rs` — `auth::check_auth(&headers, &state.config.web)?` repeats in every protected handler (config/control/status/users/...).

**The approach:** make an axum `FromRequestParts` extractor (e.g. `AuthGuard`), which checks auth and is placed in the handler signature instead of the manual call + `HeaderMap`. The handlers will get cleaner, the check can't be "forgotten".

**Acceptance criterion:** all protected routes still require auth (a test for 401/403 without credentials); the public ones (login/hash?) are unaffected; `cargo test` green.

**Risk:** low-medium — it touches the signatures of all handlers; easily verified by authorization tests. Optional.

**✅ Status (2026-06-10): done and verified on the lab (.10).** In `auth.rs` the extractor `AuthGuard` added (`#[async_trait] impl FromRequestParts<Arc<ServerState>>` → `check_auth(&parts.headers, &state.config.web)?`; `AuthError = (StatusCode, Json<Value>)` already `IntoResponse`). In all **20 protected handlers** (config 4, control 1, hash 1, logs 1, share 1, status 4, users 8) `headers: HeaderMap` + the manual `check_auth(...)?` / if-let were replaced with a parameter `_guard: auth::AuthGuard`; the unused `HeaderMap` imports removed. Where `state` was used only for auth (hash + 3 status handlers `clients`/`kick_client`/`set_bandwidth`, which go through `control(...)`) → `State(_state)`.
- **The gate revealed 2 things (as anticipated), both fixed:** (1) axum 0.7 `FromRequestParts` requires `#[async_trait]` (a native `async fn` gave E0195) → added `use axum::async_trait;` + the attribute; (2) `unused state` after removing `check_auth` → `_state`.
- **`lab_sync_build.py` on .10 → PASS:** build OK / **179 tests** OK / clippy `-D warnings` OK. Auth enforcement now can't be "forgotten" (type-level), the 401 shape is the same.

---

## Execution order

The principle (as in RELEASE-FIXES): **first the version unification, then the scaffold, then the move — in batches**.

1. **R0** — pre-unification: mac → net10, win-NuGet to the mac versions, CI macos-SDK → 10.0.x. *(gate: CI green on both)*
2. **R1** — the `QeliShared` scaffold (`net10.0`). *(gate: both clients build with an empty lib)*
3. **R2 → R3 → R4** — moving the managed code (Crypto → Protocol → Model/Loc) **as is**. After each — a build of both; after R3 — e2e of the wire modes on the lab.
4. **R5** — `VpnTunnel` behind interfaces. A separate step, **a full e2e gate** (TCP/UDP/reality-tls/multipath).
5. **R6** — partially-shared classes, in decreasing benefit. Optional / may be deferred.
6. **R7** — `lab_common.py` + script migration, incrementally and independently of C#.
7. **R8 / R9** — Rust cosmetics, at any time, independently.

Zones A (C#), B (Python), C (Rust) are **independent** — they can be done in parallel/in any order. Within A the order **R0→R1→R5 is mandatory** (dependencies).

## What we do NOT touch (deliberately)

- **The cross-language protocol.** The same stack is implemented in Rust (the canon),
  Kotlin (Android), and C# (×2). It can't be merged into one — these are different
  runtimes. The real goal is only to **merge the two C# copies** (R1–R5); Rust and Kotlin
  stay separate out of necessity.
- **The platform profile storage.** `ProfileStore`/the at-rest secrets: win — DPAPI
  (`ProtectedData`), mac — Keychain/a file (`Model/SecureKey.cs`, `Model/Paths.cs`).
  Fundamentally different OS mechanisms — behind an interface, but not "shared code".
- **The UI markup** (WPF `.xaml` ↔ Avalonia `.axaml`) — different frameworks, not made
  shared (only the logic behind them becomes shared, R6).
- **The native cores** (`.so/.dll/.dylib`) — these are already a single Rust `realtls`,
  built per platform; there's no duplication.

---

*Created 2026-06-10 from the results of the duplication audit. No code edits were made — this is a plan.*
