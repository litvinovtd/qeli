# Qeli Linux Desktop

Linux desktop client: Avalonia / .NET 10 with the existing Rust `qeli-client`
data plane. The GUI runs as the logged-in user, never as root. VPN start and stop
use polkit authentication and a transient systemd service.

## Features

- Import a `qeli://` link or flat INI by pasting it into the editor.
- Name, save, select, edit and delete profiles.
- Start and stop the VPN using the current Rust core.
- System-tray icon with Open Qeli, Start VPN, Stop VPN and Exit Qeli actions,
  plus a process-status tooltip.
- Optional close-to-tray: enable **Keep running in tray when closing** after
  confirming that the icon appears near your clock. This session-only option
  leaves the VPN running when the window is hidden. **Exit Qeli** always stops
  the VPN first; cancelling polkit authorization keeps the application open.
- Bounded live process journal; errors and authentication cancellation are shown.
- Profiles use the shared desktop parser and serializer.

This is an initial desktop implementation, not Windows/macOS feature parity.
There is no autostart, QR scanner or per-app routing. The status reports
process lifecycle, not authenticated tunnel readiness. Linux integration must
be tested on a Linux desktop before distributing this as a production release.

## Requirements

Linux with systemd, polkit (`pkexec`) and a graphical polkit authentication agent,
TUN support, and the native libraries required by Avalonia (X11/fontconfig).
Non-systemd distributions are not supported by this launcher.
The tray uses StatusNotifierItem/AppIndicator. KDE Plasma normally supports it
out of the box; GNOME requires the AppIndicator/KStatusNotifierItem extension.
Close-to-tray is off by default so a missing tray host cannot hide the application
unexpectedly. Without it, closing the window stops the VPN and exits.
The VPN executable must be installed by the administrator at
`/usr/libexec/qeli-linux/qeli-client` when installed from a package, or
`/usr/local/bin/qeli-client` for manual installations; do not make these files or their parents writable by
unprivileged users. No custom polkit policy grants unattended root access.

Profiles contain credentials in plain text in the user's local application-data
directory (`~/.local/share/qeli-linux` by default). Directory mode is 0700 and
profile mode is 0600. Configuration travels to the privileged launcher via stdin,
never command-line arguments. The launcher writes a root-owned 0600 regular file
inside a systemd-managed 0700 runtime directory under `/run`. The current core
requires a regular file and may read it repeatedly. systemd removes the runtime
directory when the service stops. INI profiles
are privileged VPN configuration: import only profiles you trust.

## Build And Install

Run from the repository root on Linux with Rust and the .NET 10 SDK:

```sh
cargo build --manifest-path qeli/Cargo.toml --release --bin qeli-client --no-default-features --features client-bin
CARGO_PROFILE_RELEASE_PANIC=unwind cargo build --locked --manifest-path qeli/Cargo.toml --release --lib --no-default-features --features transport-core-ffi
sudo install -o root -g root -m 0755 qeli/target/release/qeli-client /usr/local/bin/qeli-client
sudo install -D -o root -g root -m 0755 qeli-linux/launch-client.sh /usr/libexec/qeli-linux/launch-client
dotnet publish qeli-linux/QeliLinux/QeliLinux.csproj -c Release -r linux-x64 --self-contained true -o qeli-linux/dist
install -m 0755 qeli/target/release/libqeli_core.so qeli-linux/dist/libqeli.so
sudo mkdir -p /opt/qeli-linux
sudo cp -a qeli-linux/dist/. /opt/qeli-linux/
sudo install -m 0644 qeli-linux/qeli-linux.desktop /usr/share/applications/qeli-linux.desktop
sudo install -Dm 0644 assets/branding/qeli-logo.png /usr/share/icons/hicolor/256x256/apps/qeli.png
/opt/qeli-linux/QeliLinux
```

For ARM64 use `-r linux-arm64` and build the Rust client on the target machine.
The self-contained publish includes the .NET runtime, not Linux system libraries.

## DEB And RPM Packages

The packaging script builds the self-contained GUI, the Rust client, and the
native `libqeli.so` configuration adapter required by the shared profile model,
then creates DEB and RPM packages for the host architecture (x86_64 or ARM64).
Run on Linux, not directly in Windows PowerShell. It requires .NET 10 SDK,
Rust and its native build prerequisites, `dpkg-deb`, and `rpmbuild`.
On Debian/Ubuntu the packaging tools are provided by `dpkg` and `rpm`.
Build as an ordinary user:

```sh
bash qeli-linux/build-packages.sh
```

Artifacts are placed in `qeli-linux/packages`. Install the appropriate format:

```sh
sudo apt install ./qeli-linux/packages/qeli-linux_0.8.3_amd64.deb
# Fedora/RHEL-family systems:
sudo dnf install ./qeli-linux/packages/qeli-linux-0.8.3-1.x86_64.rpm
```

The package installs the GUI and matching native configuration library in
`/opt/qeli-linux`, the VPN executable and privileged launcher in
`/usr/libexec/qeli-linux`, and a desktop menu entry and icon. It does not start
the VPN during installation or install an unattended-root polkit policy.
Use the package manager to uninstall; user profiles are preserved.

Build on the oldest supported target distribution: Rust and native .NET assets
can require newer system libraries than the declared glibc 2.34 baseline.
The dependencies target modern Debian/Ubuntu and Fedora-family systems; this
is not a claim of compatibility with every DEB/RPM distribution. A graphical
polkit agent must be running in the user's desktop session.
Release compilation, self-contained x64/ARM64 GUI publishing, headless window
lifecycle checks, launcher regression tests and transient systemd user-service
cleanup were checked under Ubuntu 26.04 in WSL. A short WSLg startup smoke test
also passed after providing the declared X11 session libraries. These automated
checks do not replace testing actual tray visibility, polkit dialogs, VPN traffic,
installation/removal and route/DNS restoration on the target Linux desktop.

## Linux Smoke Test

1. Import a valid link, save it, restart the GUI and select the saved profile.
2. Start VPN, authorize polkit, verify routes, DNS and access through the VPN.
3. Stop VPN, authorize polkit, verify that routes and DNS are restored.
4. Verify the tray icon and its Open/Start/Stop/Exit actions and status tooltip.
   Enable close-to-tray, close the window while VPN is running, verify the VPN
   stays up, then reopen from the tray. Repeat after minimizing the window.
5. Exit while VPN is running; verify route/DNS restoration and removal of the
   service runtime directory. Cancel stop authentication: the application must
   remain open and allow another stop/exit attempt.
6. Disable close-to-tray and close the window; verify the VPN stops before exit.
   Also test a desktop without a tray host (leave close-to-tray disabled).
7. Cancel start authentication and try an unreachable server; check journal and cleanup.

Unprivileged launcher regression tests (Linux, Python 3):

```sh
python3 -m unittest discover -s qeli-linux/tests -v
dotnet run --project qeli-linux/QeliLinux.Tests/QeliLinux.Tests.csproj -c Release
```

Set `QELI_TEST_SYSTEMD=1` for the Python tests to additionally exercise a real
transient user service and verify automatic runtime-directory cleanup. This does
not start a VPN or request root access. Pass the absolute path to a built
`libqeli.so` after `--` to the headless test runner to also verify native profile
import and round-trip serialization.

The launcher passes SIGINT when stopping the service so the existing Rust client
can restore network state. If shutdown hangs, systemd applies its 30-second stop
timeout; inspect system logs and network configuration before reconnecting.
