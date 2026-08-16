# OpenWrt feed package for the qeli VPN client.
# Build: clone into an OpenWrt feed (or `package/qeli`), enable the `rust` feed
# (lang/rust), then `make package/qeli/compile V=s`.

include $(TOPDIR)/rules.mk

PKG_NAME:=qeli
PKG_VERSION:=0.7.16
PKG_RELEASE:=1

# Built from the qeli Rust crate (client-only). Point PKG_SOURCE_URL at the repo,
# or drop the crate into a local source dir. The realtls FFI core is part of the
# same crate; client-bin pulls only the client path (no `ring` → builds on mips).
#
# PKG_SOURCE_VERSION is a full commit SHA, not `v$(PKG_VERSION)` (Audit 2026-07-27, G5).
# A tag is mutable — retagging silently changes what this package builds — and the tag
# for an unreleased version does not exist at all, so the package could not be built
# from a dev tree. A SHA pins one immutable tree. Re-pin it at the release commit when
# cutting a version.
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/litvinovtd/qeli.git
PKG_SOURCE_VERSION:=f2fcbc6ec3457772a313f3be0ba87540266dab55
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
# OpenWrt REQUIRES a hash for a git source: without PKG_MIRROR_HASH the generated
# tarball is accepted unverified, so the build trusts whatever github.com serves.
# The value is the sha256 of the tarball OpenWrt itself produces from the checkout
# above, so it cannot be computed without the SDK.
#
# AT TAG TIME, together with PKG_SOURCE_VERSION above: replace the placeholder with the
# real hash. Both are release-cut steps by nature — the SHA does not exist until the
# release commit is made, and the hash is of a tarball produced FROM that commit — so a
# development tree legitimately carries the placeholder and a stale SHA, and
# `release_preflight.py` failing on this line is the reminder working, not a defect.
# (This note used to be dated "TODO(release 0.7.13)" while PKG_VERSION already said
# 0.7.14, which read like a forgotten task rather than a standing procedure.)
#
# Produce the hash from the OpenWrt buildroot after adding this package:
#     make package/qeli/download V=s
#     sha256sum dl/$(PKG_NAME)-$(PKG_VERSION).tar.xz
# (or `make package/qeli/check FIXUP=1`, which rewrites the line in place). The
# placeholder is deliberately a value that CANNOT match, so the build fails loudly
# rather than proceeding unverified — do NOT replace it with `skip`.
PKG_MIRROR_HASH:=3b721d983b5fe088ffc964b3f063a6d0e5eec109ba38bfc98e500d22ff5660b9
PKG_MAINTAINER:=Alexandr
PKG_LICENSE:=AGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE

# The Cargo project (Cargo.toml) lives in the `qeli/` subdir of the repo; the git source
# above brings the WHOLE repo. Keep PKG_BUILD_DIR at the checkout ROOT so Build/Prepare
# unpacks correctly — overriding it to the `qeli/` subdir makes the unpack land in the
# wrong place and the SDK can't find the crate (Build/Compile cd's into qeli/ instead).
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

RUST_PKG_FEATURES:=client-bin
CARGO_PKG_CONFIG_DEPENDS:=

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/qeli
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=qeli VPN client (REALITY / anti-DPI, post-quantum)
  URL:=https://github.com/litvinovtd/qeli
  DEPENDS:=$(RUST_ARCH_DEPENDS) +kmod-tun +ip-full +iptables +ip6tables +ca-bundle
endef

define Package/qeli/description
  Headless client for the qeli VPN: REALITY / fake-tls / obfs / QUIC obfuscation,
  X25519 + ML-KEM-768 post-quantum handshake (UDP-fragmented for LTE/CGNAT),
  iptables kill-switch. Managed via UCI (/etc/config/qeli) and procd; install
  luci-app-qeli for a web UI.
endef

define Package/qeli/conffiles
/etc/config/qeli
endef

# Client-only build: no default features (drops the server, web panel and `ring`).
# The client-only bin is `qeli-client` (src/client_main.rs); the default `qeli`
# bin requires the server+client features and is not built here.
CARGO_INSTALL:=0
define Build/Compile
	+cd $(PKG_BUILD_DIR)/qeli && \
	$(CARGO_PKG_VARS) \
	cargo install -v \
		--profile release \
		--no-default-features --features client-bin \
		--bin qeli-client \
		--root $(PKG_INSTALL_DIR)/usr \
		--path .
endef

define Package/qeli/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/qeli-client $(1)/usr/bin/qeli-client

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/qeli.init $(1)/etc/init.d/qeli

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/qeli.config $(1)/etc/config/qeli

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/qeli.firewall.uci-defaults $(1)/etc/uci-defaults/99-qeli-firewall
endef

$(eval $(call BuildPackage,qeli))
