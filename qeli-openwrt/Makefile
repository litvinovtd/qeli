# OpenWrt feed package for the qeli VPN client.
# Build: clone into an OpenWrt feed (or `package/qeli`), enable the `rust` feed
# (lang/rust), then `make package/qeli/compile V=s`.

include $(TOPDIR)/rules.mk

PKG_NAME:=qeli
PKG_VERSION:=0.7.9
PKG_RELEASE:=1

# Built from the qeli Rust crate (client-only). Point PKG_SOURCE_URL at the repo,
# or drop the crate into a local source dir. The realtls FFI core is part of the
# same crate; client-bin pulls only the client path (no `ring` → builds on mips).
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/litvinovtd/qeli.git
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_MAINTAINER:=Alexandr
PKG_LICENSE:=AGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE

# The Cargo project lives in qeli/ inside the repo.
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/qeli

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
	+$(CARGO_PKG_VARS) \
	cargo install -v \
		--profile release \
		--no-default-features --features client-bin \
		--bin qeli-client \
		--root $(PKG_INSTALL_DIR)/usr \
		--path $(PKG_BUILD_DIR)
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
