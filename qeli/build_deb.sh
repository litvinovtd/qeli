#!/bin/bash
set -euo pipefail

echo "==> Building qeli binary..."
cargo build --release --target-dir target

echo "==> Preparing .deb package structure..."
PACKAGE_NAME="qeli"
VERSION="0.7.2"
ARCH="amd64"
BUILD_DIR="build"
DEB_DIR="${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCH}"

mkdir -p "${DEB_DIR}/usr/bin"
mkdir -p "${DEB_DIR}/etc/${PACKAGE_NAME}"
mkdir -p "${DEB_DIR}/etc/systemd/system"
mkdir -p "${DEB_DIR}/var/log/${PACKAGE_NAME}"
mkdir -p "${DEB_DIR}/DEBIAN"

echo "==> Copying files..."
install -m 755 "target/release/${PACKAGE_NAME}" "${DEB_DIR}/usr/bin/"
install -m 644 "config/server.json" "${DEB_DIR}/etc/${PACKAGE_NAME}/"
install -m 644 "config/client.json" "${DEB_DIR}/etc/${PACKAGE_NAME}/"
install -m 644 "config/users.json" "${DEB_DIR}/etc/${PACKAGE_NAME}/"
install -m 644 "debian/qeli.service" "${DEB_DIR}/etc/systemd/system/"
install -m 644 "debian/control" "${DEB_DIR}/DEBIAN/"
install -m 755 "debian/postinst" "${DEB_DIR}/DEBIAN/"
install -m 755 "debian/prerm" "${DEB_DIR}/DEBIAN/"

echo "==> Building .deb package..."
dpkg-deb --build "${DEB_DIR}"
mv "${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb" .
rm -rf "${BUILD_DIR}"

echo "==> Done: ${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"
ls -lh "${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"