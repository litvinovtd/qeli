# Qeli Windows CLI

[Русский](../../ru/manuals/WINDOWS-CLI.md) · English

`qeli-cli.exe` is a Windows x64 console client for CMD, `.bat`/`.cmd` files,
Windows PowerShell 5.1 and PowerShell 7. It shares the Windows runtime, Rust core,
Wintun/WinDivert and INI parser with the GUI. This is development for 0.8.4;
the presence of source code does not mean a finished release has been published.

## Running and configuration

The `net-required` package needs .NET 10 Runtime; `standalone` includes the runtime.
Release files: `qeli-cli-windows-x64-net-required.zip` and
`qeli-cli-windows-x64-standalone.zip`. Extract the selected archive in full.
WPF/Desktop Runtime is not required for the CLI. Copy the **entire folder** of
the chosen variant, rather than just the EXE. Install the Windows service from
a protected directory, such as `C:\Program Files\QeliCli`: permissions on its
files and parent directories are checked.

```cmd
qeli-cli.exe --help
qeli-cli.exe version --json
qeli-cli.exe config validate --config "C:\VPN\office.ini"
qeli-cli.exe run --config "C:\VPN\office.ini"
```

`run` stays in the current process until Ctrl+C/Ctrl+Break. There is no implicit
30-second limit. `--timeout 60` bounds the initial connection; `--duration 300`
bounds runtime after the first confirmed connection. Terminal errors return
a nonzero exit code. Ordinary exit invokes route/DNS/firewall cleanup; cleanup
failure returns the separate exit code 10. Forced termination and console closure
have Windows limitations: cleanup cannot be guaranteed, and recovery journals
are retained.

Configuration files must be UTF-8 INI, at most 256 KiB; a BOM is accepted.
JSON is not a configuration format. Passwords and links containing passwords
are not accepted as process arguments. Set a verified `key` for unattended
connections; key verification and TOFU follow the same rules as the Windows GUI.
Trust/device identity can differ between the user process and the SYSTEM service;
their stores are not copied automatically.

```cmd
qeli-cli.exe config validate --config - --json < "C:\VPN\office.ini"
```

For a text pipeline into stdin in PowerShell 5.1, first set
`$OutputEncoding = [System.Text.UTF8Encoding]::new($false)`, or pass a file path
using `--config`. PowerShell 7 uses UTF-8 by default. Quote paths containing
spaces. For CMD batch files containing Cyrillic characters, account for the
batch file encoding and the shell's active code page.

File-based CLI profile identity is stable by absolute path, without hashing
the password. Persistent adapters with stdin require an explicit `dev_node`/`dev`;
this prevents creating a new persistent interface on every invocation.

GUI preferences do not change the CLI profile. `windows_persistent_adapter=true`
selects Per-profile mode; the GUI's Global adapter is not selected implicitly.
One machine-wide owner covers the current GUI, CLI and service through reconnect
and incomplete cleanup.

## Commands

| Command | Purpose |
|---|---|
| `--help` | Display command help |
| `version` | Display the client version |
| `config validate --config FILE` | Validate an INI file; `-` reads redirected stdin |
| `run --config FILE` | Run the VPN in the foreground |
| `probe --config FILE` | Perform an authenticated handshake without configuring routes |
| `connect --config FILE` | Connect using the installed service |
| `disconnect` | Stop the service connection and check cleanup |
| `status` | Read service connection status |
| `wait --state connected` | Wait for the service connection |
| `wait --state disconnected` | Wait for the service to disconnect |
| `logs` | Read the service log; `--follow` streams updates |
| `service install` | Install the service; a new installation is idle |
| `service start` | Start the worker with its saved connection intent |
| `service stop` | Stop the service and disarm boot connection intent |
| `service uninstall` | Stop and uninstall the service, retaining the saved profile |
| `licenses` | List embedded license texts |
| `licenses --export NEW_DIR` | Export license texts to a new directory |

## Windows service and automation

```cmd
qeli-cli.exe service install
qeli-cli.exe connect --config "C:\VPN\office.ini" --timeout 60
qeli-cli.exe status --json
qeli-cli.exe wait --state connected --timeout 60
qeli-cli.exe logs --follow
qeli-cli.exe disconnect --timeout 30
```

The existing `QeliWinSvc` uses SCM and protected DPAPI storage. Installing a new
service saves intent=disconnected. `service start` launches the worker with its
saved intent; `service stop`/`disconnect` disarm boot connection intent. A service
connection runs independently of the terminal and user login.

`connect` returns 0 after a fresh Connected status for the requested profile,
rather than merely after SCM startup. Repeating an unchanged profile does not
create a second tunnel. Switching profiles uses stop/publish/start. `disconnect`
waits for SCM and checks cleanup confirmation; an unknown/stale Connected status
does not count as success. `status`, `wait`, `logs`, `connect` and `disconnect`
target the service backend. A foreground `run` is stopped from its own terminal,
rather than through a service control command.

A timeout or Ctrl+C during `connect` stops CLI waiting, but already published
service intent can remain active: cancel it explicitly using `disconnect`.
An initial `run` timeout performs cleanup. An old service host without the new
control metadata produces `service_incompatible`: stop/uninstall its registration
and install the current CLI. Uninstall does not delete the saved profile.
Legacy/untrusted storage is migrated only explicitly through the existing GUI;
the CLI does not quarantine it silently.

Service control and `run` require administrator rights. Help, version, licenses,
configuration validation and handshake probe do not require elevation. The EXE
uses asInvoker; insufficient rights return an error without a UAC dialog.

CMD/batch:

```bat
@echo off
qeli-cli.exe connect --config "C:\VPN\office.ini" --timeout 60 --json
if errorlevel 1 exit /b %errorlevel%
qeli-cli.exe status --json
rem Perform the required work through the VPN.
qeli-cli.exe disconnect --timeout 30 --json
exit /b %errorlevel%
```

PowerShell:

```powershell
& .\qeli-cli.exe connect --config 'C:\VPN\office.ini' --timeout 60 --json
if ($LASTEXITCODE -ne 0) { throw 'VPN connection failed' }
$status = & .\qeli-cli.exe status --json | ConvertFrom-Json
$status.data.state
```

## Output and errors

`--json` emits one schema_version=1 object on stdout, without banners or log
messages mixed in. Ordinary `run` logs go to stderr. `--json-lines` is supported
by `run`/`logs`; use `--json-lines` instead of `logs --follow --json`. The log queue
is bounded so a slow reader does not block the transport; `logs_dropped` reports
dropped messages in the foreground result. Service log rotation can replay
a retained bounded snapshot.

```json
{"schema_version":1,"ok":true,"command":"config validate","data":{"valid":true},"error":null}
```

| Code | Meaning |
|---|---|
| 0 | Command completed successfully |
| 2 | Invalid arguments |
| 3 | INI read/validation error |
| 4 | Insufficient rights or untrusted storage |
| 5 | Owner/operation conflict |
| 6 | Deadline expired |
| 7 | Authentication failure |
| 8 | Server key mismatch |
| 9 | Transport/operation failure |
| 10 | Network cleanup is not confirmed |
| 11 | Service/native core unavailable or incompatible |
| 12 | Waiting cancelled |

`probe --config FILE` performs an authenticated handshake without installing
routes. It does not confirm DNS/routing/data transfer through a full VPN.
`licenses` lists embedded original texts; `licenses --export NEW_DIR` writes
them to a new directory, without overwriting an existing directory.

## Building and verification

Use the SDK pinned by the root `global.json` and a matching native core.

```powershell
dotnet build .\qeli-win\QeliCliTests\QeliCliTests.csproj -c Release
dotnet exec .\qeli-win\QeliCliTests\bin\Release\net10.0-windows\QeliCliTests.dll
$env:QELI_CLI_REQUIRED = '1'
python -B -m unittest discover -s scripts -p test_windows_cli.py -v
.\qeli-win\build-cli.ps1 -OutputDirectory C:\Build\qeli-cli-candidate
```

`build-cli.ps1` creates net-required/standalone directories and two release ZIPs,
including every DLL/runtime file (except debug PDBs) and a short README. It verifies original
licenses, exact native core bytes and actual INI parser compatibility. An explicit
`-NativeCorePath` can be supplied for a development build; this does not qualify
the DLL as a release artifact. Public distribution requires the normal
provenance/release checks.

After assembling the complete 0.8.4 distribution and generating `SHA256SUMS`, run
`python scripts/release_assets.py --directory release/dist/v0.8.4 --version 0.8.4`.
This requires both Linux ELF/DEB pairs, both CLI ZIPs and the other release files;
an incomplete set or an extra stale file is not admitted as a complete distribution.

Unit/fault-injection and shell smoke tests do not replace real Windows VPN
testing: elevated full-tunnel, dual-stack/DNS, reboot/service lifecycle,
reconnect, kill switch, network loss and forced termination require a separate
isolated Windows test environment.
