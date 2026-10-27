# LuCI web UI for the qeli VPN client.
include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for the qeli VPN client
# The UI framework and imported fs module are runtime requirements.
LUCI_DEPENDS:=+luci-base +qeli +rpcd-mod-ucode +ucode-mod-fs
LUCI_PKGARCH:=all
PKG_VERSION:=0.8.4
PKG_RELEASE:=1
LUCI_MAINTAINER:=Alexandr
LUCI_URL:=https://github.com/litvinovtd/qeli
PKG_LICENSE:=AGPL-3.0-only

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
