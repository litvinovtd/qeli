# Build a binary .deb for qeli (Debian/Ubuntu). Run from qeli/debian/ on a
# Debian/Ubuntu host (needs dpkg-deb; the `deb` target also needs cargo).
#
#   make deb           - alias for deb-portable; never use the build host's glibc.
#   make binary-portable - build and admit the standalone Linux binary.
#   make deb-portable ARCH=arm64 - native or cross build for Linux ARM64.
#   make deb-portable  - RELEASE target: cargo-zigbuild against a pinned old glibc ABI,
#                        then package. Use this for anything published.
#   make deb-prebuilt  - package an ALREADY-built binary (no cargo). Override path:
#                        make deb-prebuilt BINARY=/opt/qeli-src/target/release/qeli
#   make check-abi     - print the highest glibc version the binary demands
#   make clean
#
# Version comes from control; architecture defaults to the host, or explicit ARCH.

PACKAGE_NAME := qeli
VERSION := $(shell sed -n 's/^Version: //p' control)
ARCH    ?= $(shell dpkg --print-architecture)
ifeq ($(ARCH),amd64)
override RUST_TARGET := x86_64-unknown-linux-gnu
else ifeq ($(ARCH),arm64)
override RUST_TARGET := aarch64-unknown-linux-gnu
else
$(error unsupported ARCH '$(ARCH)'; use amd64 or arm64)
endif
BINARY  ?= $(ZIG_BINARY)
# The server .deb ships the jemalloc allocator (bounded RSS under handshake churn).
# Keep the feature literal in both build recipes: a command-line Make variable must not
# be able to turn a release package back into a glibc-allocator server.

BUILD_DIR := build
DEB_DIR   := $(BUILD_DIR)/$(PACKAGE_NAME)_$(VERSION)_$(ARCH)

# Published artifacts MUST pin the glibc ABI. A plain `cargo build --release` links against
# whatever glibc the BUILD host has, and Rust's std references pidfd_spawnp/pidfd_getpid — on a
# host with glibc >= 2.39 the linker stamps them GLIBC_2.39, so the binary dies on older distros
# with "version 'GLIBC_2.39' not found". That is how 0.7.8-0.7.11 shipped broken for Ubuntu 22.04
# (glibc 2.35) while `Depends: libc6 (>= 2.34)` let apt install them without a word.
# cargo-zigbuild targets an explicit ABI instead; the pidfd symbols then stay weak+unversioned
# and std falls back at runtime. Keep GLIBC_ABI in sync with `Depends:` in `control`.
override GLIBC_ABI := 2.28
override ZIG_TARGET := $(RUST_TARGET).2.28
ZIG_BINARY := ../target/$(RUST_TARGET)/release/$(PACKAGE_NAME)

.PHONY: all deb binary-portable deb-portable deb-prebuilt check-abi stage clean

all: deb

deb: deb-portable

# Release build: pinned glibc ABI. Needs cargo-zigbuild + zig on PATH.
binary-portable:
	cargo zigbuild --locked --release --features jemalloc --bin $(PACKAGE_NAME) --target $(ZIG_TARGET)
	$(MAKE) check-abi BINARY=$(ZIG_BINARY)

deb-portable: binary-portable
	$(MAKE) deb-prebuilt BINARY=$(ZIG_BINARY)

# Fails when the binary demands more of the target machine than the package promises:
#   1. a newer glibc than the declared floor, and
#   2. a CPU baseline `Depends:` cannot express (Audit 2026-07-27, G3).
#
# On (2): `-C target-feature=+aes` used to be set for one triple only, so the release
# could be built demanding AES-NI while nothing checked it - the binary then SIGILLs at
# startup on a VPS whose CPU flags are masked, and apt installs it happily because
# there is no way to write "requires AES-NI" in a Depends line. The check is by
# construction indirect: RustCrypto's `cpufeatures` compiles its CPUID probe away when
# the feature is enabled at compile time, so "AES instructions present AND no cpuid
# anywhere" means the runtime fallback is gone. It is a heuristic, and it is the only
# signal the ELF actually carries - a false PASS is possible, a false FAIL is not.
check-abi:
	python3 ../../scripts/linux_release.py --binary "$(BINARY)" --arch $(ARCH)
	python3 ../../scripts/linux_release_cpu.py --binary "$(BINARY)" --arch $(ARCH) $(if $(OBJDUMP),--objdump "$(OBJDUMP)")

# -Zxz is NOT cosmetic: dpkg >= 1.21.10 (Ubuntu 24.04, Debian 13 — i.e. every current build
# host) defaults to zstd, and dpkg on the oldest distro we promise to support (debian:10,
# glibc 2.28) cannot read it: `dpkg -x` dies with "unknown compression for member
# control.tar.zst" before the binary is ever unpacked. The package built fine and passed
# every objdump/Depends check while being undeployable on its own declared floor. xz is
# understood by dpkg since 1.15, so it covers everything from debian:10 upward.
deb-prebuilt: stage
	dpkg-deb --root-owner-group -Zxz --build $(DEB_DIR)
	python3 ../../scripts/linux_release.py --deb "$(DEB_DIR).deb" --arch $(ARCH)
	mv $(BUILD_DIR)/$(PACKAGE_NAME)_$(VERSION)_$(ARCH).deb .
	@echo "OK: $(PACKAGE_NAME)_$(VERSION)_$(ARCH).deb"

stage: check-abi
	python3 ../../scripts/native_licenses.py --repo ../..
	@test -f "$(BINARY)" || { echo "binary not found: $(BINARY) - run make deb or pass BINARY=<path>"; exit 1; }
	rm -rf $(DEB_DIR)
	install -d $(DEB_DIR)/usr/bin $(DEB_DIR)/etc/$(PACKAGE_NAME) $(DEB_DIR)/lib/systemd/system $(DEB_DIR)/DEBIAN
	install -m755 "$(BINARY)" $(DEB_DIR)/usr/bin/$(PACKAGE_NAME)
	install -d $(DEB_DIR)/usr/share/doc/$(PACKAGE_NAME)/licenses
	cp -R ../third-party-notices/rust $(DEB_DIR)/usr/share/doc/$(PACKAGE_NAME)/licenses/
	install -m644 ../config/server.conf $(DEB_DIR)/etc/$(PACKAGE_NAME)/server.conf.example
	install -m644 ../config/server-multiprofile.conf $(DEB_DIR)/etc/$(PACKAGE_NAME)/server-multiprofile.conf.example
	install -m644 ../config/server-ipv6.conf $(DEB_DIR)/etc/$(PACKAGE_NAME)/server-ipv6.conf.example
	install -m644 ../config/server-maxobf.conf $(DEB_DIR)/etc/$(PACKAGE_NAME)/server-maxobf.conf.example
	install -m644 ../config/users.conf  $(DEB_DIR)/etc/$(PACKAGE_NAME)/users.conf.example
	install -m644 ../config/client.conf $(DEB_DIR)/etc/$(PACKAGE_NAME)/client.conf.example
	install -m644 ../config/client-reality.conf $(DEB_DIR)/etc/$(PACKAGE_NAME)/client-reality.conf.example
	install -m644 ../config/client-maxobf.conf $(DEB_DIR)/etc/$(PACKAGE_NAME)/client-maxobf.conf.example
	install -m644 qeli.service $(DEB_DIR)/lib/systemd/system/qeli.service
	install -d $(DEB_DIR)/etc/polkit-1/rules.d
	install -m644 49-qeli.rules $(DEB_DIR)/etc/polkit-1/rules.d/49-qeli.rules
	install -m755 preinst $(DEB_DIR)/DEBIAN/preinst
	install -m755 postinst $(DEB_DIR)/DEBIAN/postinst
	install -m755 prerm    $(DEB_DIR)/DEBIAN/prerm
	install -m755 config    $(DEB_DIR)/DEBIAN/config
	install -m644 templates $(DEB_DIR)/DEBIAN/templates
	echo /etc/qeli/server.conf.example >  $(DEB_DIR)/DEBIAN/conffiles
	echo /etc/qeli/server-multiprofile.conf.example >> $(DEB_DIR)/DEBIAN/conffiles
	echo /etc/qeli/server-ipv6.conf.example >> $(DEB_DIR)/DEBIAN/conffiles
	echo /etc/qeli/server-maxobf.conf.example >> $(DEB_DIR)/DEBIAN/conffiles
	echo /etc/qeli/users.conf.example  >> $(DEB_DIR)/DEBIAN/conffiles
	echo /etc/qeli/client.conf.example >> $(DEB_DIR)/DEBIAN/conffiles
	echo /etc/qeli/client-reality.conf.example >> $(DEB_DIR)/DEBIAN/conffiles
	echo /etc/qeli/client-maxobf.conf.example >> $(DEB_DIR)/DEBIAN/conffiles
	sed 's/^Architecture: .*/Architecture: $(ARCH)/' control > $(DEB_DIR)/DEBIAN/control
	chmod 644 $(DEB_DIR)/DEBIAN/control
	echo "Installed-Size: $$(du -sk --exclude=DEBIAN $(DEB_DIR) | cut -f1)" >> $(DEB_DIR)/DEBIAN/control

clean:
	rm -rf $(BUILD_DIR) $(PACKAGE_NAME)_*.deb
