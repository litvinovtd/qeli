#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/qeli/Cargo.toml" | head -n 1)"
case "$(uname -m)" in
    x86_64) rid=linux-x64; deb_arch=amd64; rpm_arch=x86_64 ;;
    aarch64) rid=linux-arm64; deb_arch=arm64; rpm_arch=aarch64 ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
for tool in cargo dotnet dpkg-deb rpmbuild install tar; do
    command -v "$tool" >/dev/null || { echo "Missing build tool: $tool" >&2; exit 1; }
done

output="$root/qeli-linux/packages"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$output"
dotnet publish "$root/qeli-linux/QeliLinux/QeliLinux.csproj" -c Release \
    -r "$rid" --self-contained true -o "$work/publish"
cargo build --manifest-path "$root/qeli/Cargo.toml" --release \
    --bin qeli-client --no-default-features --features client-bin \
    --target-dir "$work/cargo"

stage="$work/stage"
mkdir -p "$stage/opt/qeli-linux" "$stage/usr/share/doc/qeli-linux"
cp -a "$work/publish/." "$stage/opt/qeli-linux/"
chmod 0755 "$stage/opt/qeli-linux/QeliLinux"
install -Dm0755 "$work/cargo/release/qeli-client" "$stage/usr/libexec/qeli-linux/qeli-client"
install -Dm0644 "$root/qeli-linux/qeli-linux.desktop" "$stage/usr/share/applications/qeli-linux.desktop"
install -Dm0644 "$root/assets/branding/qeli-logo.png" "$stage/usr/share/icons/hicolor/256x256/apps/qeli.png"
install -m0644 "$root/qeli-linux/README.md" "$root/LICENSING.md" "$stage/usr/share/doc/qeli-linux/"
install -m0644 "$root/qeli/LICENSE" "$stage/usr/share/doc/qeli-linux/LICENSE-core"

mkdir -p "$stage/DEBIAN"
cat > "$stage/DEBIAN/control" <<EOF
Package: qeli-linux
Version: $version
Section: net
Priority: optional
Architecture: $deb_arch
Maintainer: Qeli contributors
Depends: libc6 (>= 2.34), libgcc-s1, libstdc++6, libssl3, libicu-dev, libfontconfig1, libx11-6, libice6, libsm6, systemd, pkexec, iproute2
Recommends: policykit-1-gnome | polkit-kde-agent-1
Description: Qeli Linux desktop VPN client
 Avalonia desktop interface and the Rust Qeli VPN client.
 Uses polkit authentication and systemd to manage the VPN process.
EOF
chmod 0755 "$stage/DEBIAN"
chmod 0644 "$stage/DEBIAN/control"
dpkg-deb --build --root-owner-group "$stage" "$output/qeli-linux_${version}_${deb_arch}.deb"
dpkg-deb --info "$output/qeli-linux_${version}_${deb_arch}.deb"
rm -rf "$stage/DEBIAN"

rpmroot="$work/rpm"
mkdir -p "$rpmroot"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
tar -C "$stage" -czf "$rpmroot/SOURCES/qeli-linux.tar.gz" .
cat > "$rpmroot/SPECS/qeli-linux.spec" <<EOF
Name: qeli-linux
Version: $version
Release: 1
Summary: Qeli Linux desktop VPN client
License: AGPL-3.0-only AND MPL-2.0
Source0: qeli-linux.tar.gz
BuildArch: $rpm_arch
AutoReqProv: no
Requires: glibc >= 2.34, libgcc, libstdc++, openssl-libs, libicu, fontconfig, libX11, libICE, libSM, systemd, polkit, iproute

%description
Avalonia desktop interface and the Rust Qeli VPN client.
Uses polkit authentication and systemd to manage the VPN process.

%prep

%build

%install
mkdir -p %{buildroot}
tar -xzf %{SOURCE0} -C %{buildroot}

%files
%defattr(-,root,root,-)
/opt/qeli-linux
/usr/libexec/qeli-linux
/usr/share/applications/qeli-linux.desktop
/usr/share/icons/hicolor/256x256/apps/qeli.png
%doc /usr/share/doc/qeli-linux
EOF
rpmbuild -bb --define "_topdir $rpmroot" --define "__os_install_post %{nil}" "$rpmroot/SPECS/qeli-linux.spec"
find "$rpmroot/RPMS" -name '*.rpm' -exec cp '{}' "$output/" \;
printf 'Packages created in %s\n' "$output"