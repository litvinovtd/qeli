#!/bin/sh
# Own one tagged NAT rule; never flush a table or change forwarding policy.
set -eu
action=${1:?Usage: qeli-chain-egress start|stop}
: "${WAN:?Set WAN in /etc/qeli-chain/egress.env}"
case "$WAN" in ''|*[!a-zA-Z0-9_.-]*) echo 'Invalid WAN interface' >&2; exit 1;; esac
set -- -s 10.80.1.0/24 ! -d 198.19.0.0/24 -o "$WAN" -m comment --comment qeli-chain-egress -j MASQUERADE
case "$action" in
    start) iptables -w 5 -t nat -C POSTROUTING "$@" 2>/dev/null || iptables -w 5 -t nat -A POSTROUTING "$@";;
    stop) if iptables -w 5 -t nat -C POSTROUTING "$@" 2>/dev/null; then iptables -w 5 -t nat -D POSTROUTING "$@"; fi;;
    *) echo 'Usage: qeli-chain-egress start|stop' >&2; exit 1;;
esac
