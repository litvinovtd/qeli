# LuCI web UI for the qeli VPN client.
include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for the qeli VPN client
LUCI_DEPENDS:=+qeli
LUCI_PKGARCH:=all
PKG_VERSION:=0.7.5
PKG_RELEASE:=1
PKG_MAINTAINER:=Alexandr
PKG_LICENSE:=AGPL-3.0-only

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
