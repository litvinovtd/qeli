# OpenWrt feed package for the qeli VPN client.
# Build: clone into an OpenWrt feed (or `package/qeli`), enable the `rust` feed
# (lang/rust), then `make package/qeli/compile V=s`.

include $(TOPDIR)/rules.mk

PKG_NAME:=qeli
PKG_VERSION:=0.8.3
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
PKG_SOURCE_VERSION:=9667c1e46b700762efb74db43b229eb363ea8f5a
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
# Hash the SDK-generated source archive. Git fallback may only warn on a
# mismatch, so prepare AND compile verify it below before unpack/Cargo.
# At release-cut pin the immutable source commit, run SDK download, then
# make package/qeli/check FIXUP=1 and verify the actual Source archive filename.
# Source archive generated twice and hash-verified with SDK24.10.4 (2026-10-26).
# Publish the pinned commit to PKG_SOURCE_URL before using the public feed.
# Re-qualify the cut if qeli/ changes; see the OpenWrt README audit section.
PKG_MIRROR_HASH:=48e6a769d261f0440956a5b3f1db3aa72aaedb2a4f7205b5f9667aa480b4ddcc
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
  # ip6tables providers require IPv6; an unconditional virtual dependency
  # generates a recursive Kconfig expression in the 24.10 SDK.
  DEPENDS:=$(RUST_ARCH_DEPENDS) +kmod-tun +ip-full +iptables +IPV6:ip6tables +ca-bundle
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
# Project only this private SDK checkout to rlib, as the router helpers do;
# unused cdylib/staticlib outputs waste build resources and are never installed.
# Refuse an unknown declaration rather than silently building extra FFI targets.
# Source overlays are explicit developer SDK modes (USE_SOURCE_DIR/git-src),
# not mirror-qualified release builds. Default downloaded sources must have a
# nonempty regular, nonlinked archive matching the declared hash. Do not rely
# on download.mk warnings: check again even if prepare stamps already exist.
define Qeli/VerifySourceArchive
	$(SHELL) $(CURDIR)/verify-source.sh "$(DL_DIR)/$(PKG_SOURCE)" "$(PKG_MIRROR_HASH)" "$(MKHASH)" "$(PKG_SKIP_DOWNLOAD)"
endef
Hooks/Prepare/Pre += Qeli/VerifySourceArchive

CARGO_INSTALL:=0
define Build/Compile
	+$(Qeli/VerifySourceArchive) && \
	cd $(PKG_BUILD_DIR)/qeli && \
	test -f Cargo.lock && \
	grep -Eqx 'crate-type = (\["rlib"\]|\["rlib", "cdylib", "staticlib"\])' Cargo.toml && \
	sed -i 's/^crate-type = \["rlib", "cdylib", "staticlib"\]/crate-type = ["rlib"]/' Cargo.toml && \
	grep -qx 'crate-type = \["rlib"\]' Cargo.toml && \
	$(CARGO_PKG_VARS) cargo metadata --locked --format-version 1 \
		--no-default-features --features client-bin > /dev/null && \
	$(CARGO_PKG_VARS) \
	cargo install -v --locked --jobs 1 \
		--profile release \
		--no-default-features --features client-bin \
		--bin qeli-client \
		--root $(PKG_INSTALL_DIR)/usr \
		--path .
endef

define Package/qeli/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/qeli-client $(1)/usr/bin/qeli-client

	$(INSTALL_DIR) $(1)/usr/share/licenses/qeli
	$(CP) $(PKG_BUILD_DIR)/qeli/third-party-notices/rust $(1)/usr/share/licenses/qeli/
	find $(1)/usr/share/licenses/qeli/rust -type d -exec chmod 0755 {} +
	find $(1)/usr/share/licenses/qeli/rust -type f -exec chmod 0644 {} +

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/qeli.init $(1)/etc/init.d/qeli

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/qeli.config $(1)/etc/config/qeli

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/qeli.firewall.uci-defaults $(1)/etc/uci-defaults/99-qeli-firewall
endef

$(eval $(call BuildPackage,qeli))
