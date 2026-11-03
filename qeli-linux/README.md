# Qeli Linux Desktop

Linux desktop client: Avalonia / .NET 10 with the existing Rust `qeli-client`
data plane. The GUI runs as the logged-in user, never as root. VPN start and stop
use polkit authentication and a transient systemd service.

## Features

- Import a `qeli://` link or flat INI by pasting it into the editor.
- Name, save, select, edit and delete profiles.
- Start and stop the VPN, including stopping it when closing the window.
- Bounded live process journal; errors and authentication cancellation are shown.
- Profiles use the shared desktop parser and serializer.

This is an initial desktop implementation, not Windows/macOS feature parity.
There is no tray, autostart, QR scanner or per-app routing. The status reports
process lifecycle, not authenticated tunnel readiness. Linux integration must
be tested on a Linux desktop before distributing this as a production release.

## Requirements

Linux with systemd, polkit (`pkexec`) and a graphical polkit authentication agent,
TUN support, and the native libraries required by Avalonia (X11/fontconfig).
Non-systemd distributions are not supported by this launcher.
The VPN executable must be installed by the administrator at
`/usr/libexec/qeli-linux/qeli-client` when installed from a package, or
`/usr/local/bin/qeli-client` for manual installations; do not make these files or their parents writable by
unprivileged users. No custom polkit policy grants unattended root access.

Profiles contain credentials in plain text in the user's local application-data
directory (`~/.local/share/qeli-linux` by default). Directory mode is 0700 and
profile mode is 0600. Configuration travels to the service via stdin rather
than command-line arguments or a temporary world-readable file. INI profiles
are privileged VPN configuration: import only profiles you trust.

## Build And Install

Run from the repository root on Linux with Rust and the .NET 10 SDK:

```sh
cargo build --manifest-path qeli/Cargo.toml --release --bin qeli-client --no-default-features --features client-bin
sudo install -o root -g root -m 0755 qeli/target/release/qeli-client /usr/local/bin/qeli-client
dotnet publish qeli-linux/QeliLinux/QeliLinux.csproj -c Release -r linux-x64 --self-contained true -o qeli-linux/dist
sudo mkdir -p /opt/qeli-linux
sudo cp -a qeli-linux/dist/. /opt/qeli-linux/
sudo install -m 0644 qeli-linux/qeli-linux.desktop /usr/share/applications/qeli-linux.desktop
sudo install -Dm 0644 assets/branding/qeli-logo.png /usr/share/icons/hicolor/256x256/apps/qeli.png
/opt/qeli-linux/QeliLinux
```

For ARM64 use `-r linux-arm64` and build the Rust client on the target machine.
The self-contained publish includes the .NET runtime, not Linux system libraries.

## DEB And RPM Packages

The packaging script builds both the self-contained GUI and the Rust client,
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
sudo apt install ./qeli-linux/packages/qeli-linux_0.8.1_amd64.deb
# Fedora/RHEL-family systems:
sudo dnf install ./qeli-linux/packages/qeli-linux-0.8.1-1.x86_64.rpm
```

The package installs the GUI in `/opt/qeli-linux`, the VPN executable in
`/usr/libexec/qeli-linux`, and a desktop menu entry and icon. It does not start
the VPN during installation or install an unattended-root polkit policy.
Use the package manager to uninstall; user profiles are preserved.

Build on the oldest supported target distribution: Rust and native .NET assets
can require newer system libraries than the declared glibc 2.34 baseline.
The dependencies target modern Debian/Ubuntu and Fedora-family systems; this
is not a claim of compatibility with every DEB/RPM distribution. A graphical
polkit agent must be running in the user's desktop session.
Package construction, dependency resolution, installation and removal still
require Linux validation; only the managed application build was checked on
Windows during implementation.

## Linux Smoke Test

1. Import a valid link, save it, restart the GUI and select the saved profile.
2. Start VPN, authorize polkit, verify routes, DNS and access through the VPN.
3. Stop VPN, authorize polkit, verify that routes and DNS are restored.
4. Repeat with closing the window while VPN is running.
5. Cancel authentication and try an unreachable server; check journal and cleanup.

The launcher passes SIGINT when stopping the service so the existing Rust client
can restore network state. If shutdown hangs, systemd applies its 30-second stop
timeout; inspect system logs and network configuration before reconnecting.