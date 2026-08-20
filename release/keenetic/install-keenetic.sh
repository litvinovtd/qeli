#!/bin/sh
# Установка qeli-client на Keenetic (Entware). Запускать НА РОУТЕРЕ по SSH из папки,
# где лежат бинари (qeli-client-{aarch64,mipsel}) и шаблоны (S99qeli, client.conf.example).
set -e
PKGDIR="$(cd "$(dirname "$0")" && pwd)"

# 1. Определяем арку по пакетному фиду Entware
ARCH="$(opkg print-architecture | awk '{print $2}' | grep -E 'aarch64|mipsel|mips' | head -n1)"
echo "арка пакетов: ${ARCH:-неизвестна} (uname -m: $(uname -m))"
case "$ARCH" in
  *aarch64*) BINSRC="qeli-client-aarch64" ;;
  *mipsel*)  BINSRC="qeli-client-mipsel" ;;
  *) echo "арка '$ARCH' не поддерживается (big-endian mips не собирается)"; exit 1 ;;
esac
[ -f "$PKGDIR/$BINSRC" ] || { echo "нет $BINSRC рядом со скриптом"; exit 1; }

# 2. Зависимости: ip-full (busybox ip без tuntap/route get), iptables/ip6tables
# (dual-stack NAT для режима роутера). В некоторых фидах ip6tables входит в iptables,
# в других идёт отдельным пакетом — вторая команда поэтому диагностическая.
opkg update
opkg install ip-full iptables || true
if ! command -v ip6tables >/dev/null 2>&1; then
  opkg install ip6tables || echo "ВНИМАНИЕ: ip6tables не установлен — ipv6=auto откатится к IPv4, ipv6=required не запустится"
fi

# 3. Проверка /dev/net/tun
[ -e /dev/net/tun ] || echo "ВНИМАНИЕ: нет /dev/net/tun — включи компонент VPN в KeeneticOS"

# 4. Раскладка
install -m755 "$PKGDIR/$BINSRC" /opt/bin/qeli-client
mkdir -p /opt/etc/qeli /opt/var/log /opt/var/run
if [ ! -f /opt/etc/qeli/client.conf ]; then
  install -m600 "$PKGDIR/client.conf.example" /opt/etc/qeli/client.conf
  echo "положил болванку /opt/etc/qeli/client.conf — ОТРЕДАКТИРУЙ её"
fi
install -m755 "$PKGDIR/S99qeli" /opt/etc/init.d/S99qeli

echo
echo "Готово. Дальше:"
echo "  1) vi /opt/etc/qeli/client.conf   # server/user/pass/key/mode + ipv6/gateway/dns"
echo "  2) /opt/etc/init.d/S99qeli start"
echo "  3) tail -f /opt/var/log/qeli-client.log   # ищи 'Auth OK'"
