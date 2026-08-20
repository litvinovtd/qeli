# Build a binary .deb for qeli (Debian/Ubuntu). Run from qeli/debian/ on a
# Debian/Ubuntu host (needs dpkg-deb; the `deb` target also needs cargo).
#
#   make deb           - cargo build --release, then package the fresh binary.
#                        Links against the BUILD HOST's glibc -> for local use only.
#   make deb-portable  - RELEASE target: cargo-zigbuild against a pinned old glibc ABI,
#                        then package. Use this for anything published.
#   make deb-prebuilt  - package an ALREADY-built binary (no cargo). Override path:
#                        make deb-prebuilt BINARY=/opt/qeli-src/target/release/qeli
#   make check-abi     - print the highest glibc version the binary demands
#   make clean
#
# Version/Architecture are read from `control` (single source of truth).

PACKAGE_NAME := qeli
VERSION := $(shell sed -n 's/^Version: //p' control)
ARCH    := $(shell sed -n 's/^Architecture: //p' control)
BINARY  ?= ../target/release/$(PACKAGE_NAME)
# The server .deb ships the jemalloc allocator (bounded RSS under handshake churn).
# Override with `CARGO_FEATURES=` to build with the plain glibc allocator.
CARGO_FEATURES ?= --features jemalloc

BUILD_DIR := build
DEB_DIR   := $(BUILD_DIR)/$(PACKAGE_NAME)_$(VERSION)_$(ARCH)

# Published artifacts MUST pin the glibc ABI. A plain `cargo build --release` links against
# whatever glibc the BUILD host has, and Rust's std references pidfd_spawnp/pidfd_getpid — on a
# host with glibc >= 2.39 the linker stamps them GLIBC_2.39, so the binary dies on older distros
# with "version 'GLIBC_2.39' not found". That is how 0.7.8-0.7.11 shipped broken for Ubuntu 22.04
# (glibc 2.35) while `Depends: libc6 (>= 2.34)` let apt install them without a word.
# cargo-zigbuild targets an explicit ABI instead; the pidfd symbols then stay weak+unversioned
# and std falls back at runtime. Keep GLIBC_ABI in sync with `Depends:` in `control`.
GLIBC_ABI  ?= 2.28
ZIG_TARGET := x86_64-unknown-linux-gnu.$(GLIBC_ABI)
ZIG_BINARY := ../target/x86_64-unknown-linux-gnu/release/$(PACKAGE_NAME)

.PHONY: all deb deb-portable deb-prebuilt check-abi stage clean

all: deb

deb:
	cargo build --release $(CARGO_FEATURES)
	$(MAKE) deb-prebuilt BINARY=../target/release/$(PACKAGE_NAME)

# Release build: pinned glibc ABI. Needs cargo-zigbuild + zig on PATH.
deb-portable:
	cargo zigbuild --release $(CARGO_FEATURES) --target $(ZIG_TARGET)
	$(MAKE) check-abi BINARY=$(ZIG_BINARY)
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
	@test -f "$(BINARY)" || { echo "binary not found: $(BINARY)"; exit 1; }
	@max=`objdump -T "$(BINARY)" | grep -oE 'GLIBC_[0-9.]+' | sed 's/GLIBC_//' | sort -V | tail -1`; \
	 echo "highest glibc demanded: $$max (declared floor: $(GLIBC_ABI))"; \
	 if [ "`printf '%s\n%s\n' "$$max" "$(GLIBC_ABI)" | sort -V | tail -1`" != "$(GLIBC_ABI)" ]; then \
	   echo "ERROR: binary needs glibc $$max but the package promises $(GLIBC_ABI) - build with 'make deb-portable'"; exit 1; \
	 fi
	@objdump -d "$(BINARY)" | awk '/aesenc|aesdec|aeskeygenassist|aesimc/{a++} /cpuid/{c++} END{printf "AES-NI baseline: %d aes insn(s), %d cpuid probe(s)\n", a, c; if (a>0 && c==0) {print "ERROR: AES-NI is baked in with no runtime CPU detection left - the binary will SIGILL"; print "       on any CPU without AES-NI, and Depends: cannot express a CPU feature."; print "       Drop -C target-feature=+aes (see qeli/.cargo/config.toml)."; exit 1}}'

# -Zxz is NOT cosmetic: dpkg >= 1.21.10 (Ubuntu 24.04, Debian 13 — i.e. every current build
# host) defaults to zstd, and dpkg on the oldest distro we promise to support (debian:10,
# glibc 2.28) cannot read it: `dpkg -x` dies with "unknown compression for member
# control.tar.zst" before the binary is ever unpacked. The package built fine and passed
# every objdump/Depends check while being undeployable on its own declared floor. xz is
# understood by dpkg since 1.15, so it covers everything from debian:10 upward.
deb-prebuilt: stage
	dpkg-deb --root-owner-group -Zxz --build $(DEB_DIR)
	mv $(BUILD_DIR)/$(PACKAGE_NAME)_$(VERSION)_$(ARCH).deb .
	@echo "OK: $(PACKAGE_NAME)_$(VERSION)_$(ARCH).deb"

stage:
	@test -f "$(BINARY)" || { echo "binary not found: $(BINARY) - run make deb or pass BINARY=<path>"; exit 1; }
	rm -rf $(DEB_DIR)
	install -d $(DEB_DIR)/usr/bin $(DEB_DIR)/etc/$(PACKAGE_NAME) $(DEB_DIR)/lib/systemd/system $(DEB_DIR)/DEBIAN
	install -m755 "$(BINARY)" $(DEB_DIR)/usr/bin/$(PACKAGE_NAME)
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
	install -m644 control $(DEB_DIR)/DEBIAN/control
	echo "Installed-Size: $$(du -sk --exclude=DEBIAN $(DEB_DIR) | cut -f1)" >> $(DEB_DIR)/DEBIAN/control

clean:
	rm -rf $(BUILD_DIR) $(PACKAGE_NAME)_*.deb
