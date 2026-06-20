# Build a binary .deb for qeli (Debian/Ubuntu). Run from qeli/debian/ on a
# Debian/Ubuntu host (needs dpkg-deb; the `deb` target also needs cargo).
#
#   make deb           - cargo build --release, then package the fresh binary
#   make deb-prebuilt  - package an ALREADY-built binary (no cargo). Override path:
#                        make deb-prebuilt BINARY=/opt/qeli-src/target/release/qeli
#   make clean
#
# Version/Architecture are read from `control` (single source of truth).

PACKAGE_NAME := qeli
VERSION := $(shell sed -n 's/^Version: //p' control)
ARCH    := $(shell sed -n 's/^Architecture: //p' control)
BINARY  ?= ../target/release/$(PACKAGE_NAME)

BUILD_DIR := build
DEB_DIR   := $(BUILD_DIR)/$(PACKAGE_NAME)_$(VERSION)_$(ARCH)

.PHONY: all deb deb-prebuilt stage clean

all: deb

deb:
	cargo build --release
	$(MAKE) deb-prebuilt BINARY=../target/release/$(PACKAGE_NAME)

deb-prebuilt: stage
	dpkg-deb --root-owner-group --build $(DEB_DIR)
	mv $(BUILD_DIR)/$(PACKAGE_NAME)_$(VERSION)_$(ARCH).deb .
	@echo "OK: $(PACKAGE_NAME)_$(VERSION)_$(ARCH).deb"

stage:
	@test -f "$(BINARY)" || { echo "binary not found: $(BINARY) - run make deb or pass BINARY=<path>"; exit 1; }
	rm -rf $(DEB_DIR)
	install -d $(DEB_DIR)/usr/bin $(DEB_DIR)/etc/$(PACKAGE_NAME) $(DEB_DIR)/lib/systemd/system $(DEB_DIR)/DEBIAN
	install -m755 "$(BINARY)" $(DEB_DIR)/usr/bin/$(PACKAGE_NAME)
	install -m644 ../config/server.conf $(DEB_DIR)/etc/$(PACKAGE_NAME)/server.conf.example
	install -m644 ../config/server-multiprofile.conf $(DEB_DIR)/etc/$(PACKAGE_NAME)/server-multiprofile.conf.example
	install -m644 ../config/users.conf  $(DEB_DIR)/etc/$(PACKAGE_NAME)/users.conf.example
	install -m644 ../config/client.conf $(DEB_DIR)/etc/$(PACKAGE_NAME)/client.conf.example
	install -m644 ../config/client-reality.conf $(DEB_DIR)/etc/$(PACKAGE_NAME)/client-reality.conf.example
	install -m644 qeli.service $(DEB_DIR)/lib/systemd/system/qeli.service
	install -m755 postinst $(DEB_DIR)/DEBIAN/postinst
	install -m755 prerm    $(DEB_DIR)/DEBIAN/prerm
	echo /etc/qeli/server.conf.example >  $(DEB_DIR)/DEBIAN/conffiles
	echo /etc/qeli/server-multiprofile.conf.example >> $(DEB_DIR)/DEBIAN/conffiles
	echo /etc/qeli/users.conf.example  >> $(DEB_DIR)/DEBIAN/conffiles
	echo /etc/qeli/client.conf.example >> $(DEB_DIR)/DEBIAN/conffiles
	echo /etc/qeli/client-reality.conf.example >> $(DEB_DIR)/DEBIAN/conffiles
	install -m644 control $(DEB_DIR)/DEBIAN/control
	echo "Installed-Size: $$(du -sk --exclude=DEBIAN $(DEB_DIR) | cut -f1)" >> $(DEB_DIR)/DEBIAN/control

clean:
	rm -rf $(BUILD_DIR) $(PACKAGE_NAME)_*.deb
