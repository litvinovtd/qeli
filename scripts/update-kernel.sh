#!/bin/bash
# Kernel Update Script for VPN Servers
# Запуск: ./update-kernel.sh

set -e

echo "=== Kernel Update Script ==="
echo "Current kernel: $(uname -r)"
echo "Current date: $(date)"
echo ""

# Определение дистрибутива
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
    echo "Detected distribution: $DISTRO ($VERSION_ID)"
else
    echo "ERROR: Cannot detect distribution"
    exit 1
fi

# Функция для обновления ядра на Ubuntu/Debian
update_kernel_ubuntu() {
    echo ""
    echo "[1/4] Updating package lists..."
    apt-get update -qq

    echo ""
    echo "[2/4] Installing latest kernel..."
    apt-get install -y linux-generic-hwe-$(lsb_release -rs) || apt-get install -y linux-generic

    echo ""
    echo "[3/4] Installing kernel headers and build tools..."
    apt-get install -y linux-headers-$(uname -r) build-essential

    echo ""
    echo "[4/4] Checking installed kernels..."
    dpkg --list | grep linux-image | awk '{ print $2 }' | sort -V
}

# Функция для обновления ядра на CentOS/RHEL
update_kernel_centos() {
    echo ""
    echo "[1/4] Installing ELRepo for latest kernel..."
    rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
    yum install -y https://www.elrepo.org/elrepo-release-$(rpm -E %rhel).elrepo.el$(rpm -E %rhel).noarch.rpm || true

    echo ""
    echo "[2/4] Installing latest mainline kernel..."
    yum --enablerepo=elrepo-kernel install -y kernel-ml

    echo ""
    echo "[3/4] Installing kernel headers..."
    yum --enablerepo=elrepo-kernel install -y kernel-ml-devel kernel-ml-headers

    echo ""
    echo "[4/4] Setting default kernel..."
    grub2-set-default 0
    grub2-mkconfig -o /boot/grub2/grub.cfg
}

# Функция для обновления ядра на Fedora
update_kernel_fedora() {
    echo ""
    echo "[1/3] Updating system..."
    dnf update -y kernel kernel-headers kernel-devel

    echo ""
    echo "[2/3] Installing build tools..."
    dnf install -y gcc make

    echo ""
    echo "[3/3] Checking installed kernels..."
    rpm -qa | grep kernel | sort
}

# Выполнение обновления в зависимости от дистрибутива
case "$DISTRO" in
    ubuntu|debian)
        update_kernel_ubuntu
        ;;
    centos|rhel|rocky|almalinux)
        update_kernel_centos
        ;;
    fedora)
        update_kernel_fedora
        ;;
    *)
        echo "WARNING: Unsupported distribution $DISTRO"
        echo "Attempting generic update..."
        apt-get update && apt-get install -y linux-generic || yum update -y kernel
        ;;
esac

echo ""
echo "=== Kernel Update Complete ==="
echo ""
echo "New kernel will be: $(ls -v /boot/vmlinuz-* | tail -1 | sed 's/.*vmlinuz-//')"
echo ""
echo "IMPORTANT: System reboot required!"
echo "Run: reboot"
echo ""
echo "After reboot, verify with: uname -r"
echo ""

# Запрос на перезагрузку
read -p "Reboot now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Rebooting..."
    reboot
else
    echo "Please reboot manually: reboot"
fi
