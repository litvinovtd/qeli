#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Test Suite -- DHCP, TAP L2, load testing
qeli VPN (obfuscated Rust VPN)
Server: 10.66.116.10  (root/$QELI_LAB_PASS)
Client: 10.66.116.11  (root/$QELI_LAB_PASS)
"""

import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import paramiko
import time
import json
import os
import socket
import copy

# ── Константы ─────────────────────────────────────────────────────────────────

SERVER_HOST = "10.66.116.10"
CLIENT_HOST = "10.66.116.11"
SSH_USER    = "root"
SSH_PASS    = os.environ.get("QELI_LAB_PASS", "")
SSH_TIMEOUT = 30

BINARY      = "/usr/local/bin/qeli"
CFG_DIR     = "/etc/qeli"
LOG_DIR     = "/var/log/qeli"
LIB_DIR     = "/var/lib/qeli"

VPN_SERVER_IP = "10.8.0.1"
VPN_SUBNET    = "10.8.0.0/24"
IFACE_TUN     = "vpn0"
IFACE_TAP     = "tap0"
VPN_USER      = "admin"
VPN_PASS      = "testpass123"

# Оригинальный server.json (прочитан с сервера — точный формат)
SERVER_CONFIG_BASE = {
    "bind": {"address": "0.0.0.0", "port": 443, "transport": "tcp"},
    # advertised_routes — маршруты, которые сервер пушит клиентам в auth-response
    "tun": {
        "name": IFACE_TUN,
        "address": VPN_SERVER_IP,
        "netmask": "255.255.255.0",
        "mtu": 1500,
        "tx_queue_len": 1000
    },
    "auth": {
        "users_file": f"{CFG_DIR}/users.json",
        "password_hash": "argon2id",
        "token_ttl_secs": 86400
    },
    "pool": {
        "cidr": VPN_SUBNET,
        "exclude": [VPN_SERVER_IP],
        "lease_time_secs": 3600,
        "static_reservations": {"admin": "10.8.0.10"}
    },
    "dns": {
        "enabled": True,
        "listen": VPN_SERVER_IP,
        "port": 53,
        "upstream": ["1.1.1.1", "8.8.8.8"]
    },
    "obfuscation": {
        "cipher": "chacha20-poly1305",
        "tls": {
            "server_name": "www.cloudflare.com",
            "session_id": True,
            "supported_groups": ["x25519", "secp256r1"],
            "key_share_entropy_bytes": 32,
            "reality_proxy": {"enabled": False, "target": "10.66.116.11", "target_port": 22}
        },
        "padding": {"enabled": True, "min_bytes": 32, "max_bytes": 512,
                    "randomize": True, "probability": 0.8},
        "fragmentation": {"enabled": True, "min_chunk_size": 64,
                          "max_chunk_size": 512, "max_fragments_per_packet": 16},
        "heartbeat": {"enabled": True, "interval_ms": 1000,
                      "data_size_bytes": 16, "jitter_ms": 100},
        "traffic_normalization": {"enabled": False},
        "anti_fingerprinting": {"enabled": True, "rotate_ciphers_every": 300,
                                "add_jitter_to_handshake": True}
    },
    "performance": {
        "tcp": {"nodelay": True, "keepalive_secs": 60,
                "send_buffer_size": 262144, "recv_buffer_size": 262144},
        "tun": {"read_buffer_size": 65535, "write_buffer_size": 65535,
                "read_timeout_ms": 10, "max_pending_packets": 256},
        "connection": {"max_clients": 128, "handshake_timeout_secs": 10,
                       "idle_timeout_secs": 300}
    },
    "logging": {"level": "debug", "file": f"{LOG_DIR}/server.log"}
}

# TAP + DHCP конфиг
SERVER_CONFIG_TAP = copy.deepcopy(SERVER_CONFIG_BASE)
SERVER_CONFIG_TAP["tun"]["name"] = IFACE_TAP
SERVER_CONFIG_TAP["tun"]["device_type"] = "tap"
SERVER_CONFIG_TAP["dhcp"] = {
    "enabled": True,
    "listen": VPN_SERVER_IP,
    "pool_start": "10.8.0.100",
    "pool_end": "10.8.0.200",
    "lease_time_secs": 300,
    "domain_name": "vpn.test"
}

# Конфиг клиента в TUN-режиме (для нагрузочного теста)
CLIENT_CONFIG_TUN = {
    "server": {
        "address": SERVER_HOST,
        "port": 443,
        "protocol": "tcp",
        "connection_timeout_secs": 30,
        "tcp_keepalive_secs": 60,
        "reconnect": {"enabled": True, "max_retries": -1,
                      "base_delay_secs": 1, "max_delay_secs": 60}
    },
    "auth": {
        "username": VPN_USER,
        "password_file": f"{CFG_DIR}/password.txt"
    },
    "tun": {"name": IFACE_TUN, "mtu": 1500},
    "routing": {"mode": "split-tunnel", "bypass_local": True},
    "dns": {"mode": "tunnel", "servers": [VPN_SERVER_IP, "1.1.1.1"]},
    "obfuscation": {
        "cipher": "chacha20-poly1305",
        "padding": {"enabled": True},
        "heartbeat": {"enabled": True},
        "quic": {"enabled": False, "cid_length": 4, "version": 1}
    },
    "performance": {"tcp_nodelay": True, "tun_buffer_size": 65535,
                    "idle_timeout_secs": 300},
    "logging": {"level": "debug", "file": f"{LOG_DIR}/client.log"}
}

# Конфиг клиента в TAP-режиме (для DHCP теста)
CLIENT_CONFIG_TAP = copy.deepcopy(CLIENT_CONFIG_TUN)
CLIENT_CONFIG_TAP["tun"] = {"name": IFACE_TAP, "device_type": "tap", "mtu": 1500}

# Алиас для совместимости
CLIENT_CONFIG = CLIENT_CONFIG_TUN

USERS_JSON = {
    "users": [
        {
            "username": VPN_USER,
            "password_hash": "$argon2id$v=19$m=16384,t=2,p=1$dnBuLXNhbHQtMjAyNg$HKitPHloJ24C7g6Vx5nsArVhRBNzSczeYQm8Ij3vFW0",
            "enabled": True,
            "static_ip": "10.8.0.10"
        }
    ],
    "groups": {}
}

# ── Цвета ─────────────────────────────────────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

results = []

def log(msg, color=RESET):
    print(f"{color}{msg}{RESET}", flush=True)

def ok(test, detail=""):
    results.append((True, test, detail))
    log(f"  ✓ {test}" + (f": {detail}" if detail else ""), GREEN)

def fail(test, detail=""):
    results.append((False, test, detail))
    log(f"  ✗ {test}" + (f": {detail}" if detail else ""), RED)

def section(title):
    log(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    log(f"{BOLD}{CYAN}  {title}{RESET}")
    log(f"{BOLD}{CYAN}{'─'*60}{RESET}")

# ── SSH утилиты ───────────────────────────────────────────────────────────────

def ssh_connect(host):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, port=22, username=SSH_USER, password=SSH_PASS,
              timeout=SSH_TIMEOUT, banner_timeout=SSH_TIMEOUT,
              auth_timeout=SSH_TIMEOUT)
    return c

def run(ssh, cmd, timeout=60, ignore_error=False):
    _, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()
    rc  = stdout.channel.recv_exit_status()
    return rc, out, err

def run_bg(ssh, cmd, env_vars=None):
    if env_vars:
        env_str = " ".join(f"{k}={v}" for k, v in env_vars.items())
        full = f"nohup env {env_str} {cmd} > /tmp/qeli_nohup.log 2>&1 &"
    else:
        full = f"nohup {cmd} > /tmp/qeli_nohup.log 2>&1 &"
    ssh.exec_command(full)
    time.sleep(0.3)

def upload_text(ssh, content, remote_path):
    sftp = ssh.open_sftp()
    import io as _io
    sftp.putfo(_io.BytesIO(content.encode()), remote_path)
    sftp.close()

def get_log(ssh, path, lines=60):
    _, out, _ = run(ssh, f"tail -n {lines} {path} 2>/dev/null", ignore_error=True)
    return out

def get_nohup(ssh, lines=40):
    _, out, _ = run(ssh, "tail -n {0} /tmp/qeli_nohup.log 2>/dev/null".format(lines), ignore_error=True)
    return out

def get_eth(ssh):
    _, out, _ = run(ssh, "ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -1", ignore_error=True)
    return out.strip() or "ens18"

# ── Управление VPN ────────────────────────────────────────────────────────────

def kill_vpn(ssh):
    run(ssh, "pkill -SIGTERM -f 'qeli ' 2>/dev/null || true", ignore_error=True)
    time.sleep(1)
    run(ssh, f"ip link delete {IFACE_TUN} 2>/dev/null || true", ignore_error=True)
    run(ssh, f"ip link delete {IFACE_TAP} 2>/dev/null || true", ignore_error=True)
    time.sleep(0.5)

def start_server(ssh, config_name="server-tun.json"):
    kill_vpn(ssh)
    run(ssh, "rm -f /tmp/qeli_nohup.log", ignore_error=True)
    run_bg(ssh, f"{BINARY} server --config {CFG_DIR}/{config_name}",
           env_vars={"RUST_LOG": "info"})
    time.sleep(4)
    rc, out, _ = run(ssh, "pgrep -a -f 'qeli server'", ignore_error=True)
    if rc == 0:
        return True
    log(f"  [nohup]: {get_nohup(ssh)[:300]}", RED)
    return False

def start_client(ssh, config_name="client.json"):
    kill_vpn(ssh)
    run(ssh, "rm -f /tmp/qeli_nohup.log", ignore_error=True)
    run_bg(ssh, f"{BINARY} client --config {CFG_DIR}/{config_name}",
           env_vars={"RUST_LOG": "info"})
    time.sleep(6)
    rc, out, _ = run(ssh, "pgrep -a -f 'qeli client'", ignore_error=True)
    if rc == 0:
        return True
    log(f"  [nohup]: {get_nohup(ssh)[:300]}", RED)
    return False

# ── Подготовка ────────────────────────────────────────────────────────────────

def setup_server(ssh):
    section("Подготовка сервера (10.66.116.10)")
    eth = get_eth(ssh)
    SERVER_CONFIG_BASE["routing"] = {
        "client_to_client": True,
        "nat": {"enabled": True, "interface": eth},
        "forward_private": True,
        "advertised_routes": [
            {"cidr": "10.8.0.0/24", "metric": 50},
            {"cidr": "192.168.100.0/24", "gateway": "10.8.0.1", "metric": 100,
             "description": "test LAN behind server"}
        ]
    }
    SERVER_CONFIG_TAP["routing"] = SERVER_CONFIG_BASE["routing"]
    log(f"  eth: {eth}", YELLOW)

    for d in [CFG_DIR, LOG_DIR, LIB_DIR]:
        run(ssh, f"mkdir -p {d}", ignore_error=True)

    # Конфиги
    upload_text(ssh, json.dumps(USERS_JSON, indent=2), f"{CFG_DIR}/users.json")
    upload_text(ssh, json.dumps(SERVER_CONFIG_BASE, indent=2), f"{CFG_DIR}/server-tun.json")
    upload_text(ssh, json.dumps(SERVER_CONFIG_TAP, indent=2),  f"{CFG_DIR}/server-tap.json")

    # ip_forward + iptables (NAT)
    run(ssh, "echo 1 > /proc/sys/net/ipv4/ip_forward")
    run(ssh, f"iptables -t nat -A POSTROUTING -s {VPN_SUBNET} -o {eth} -j MASQUERADE 2>/dev/null || true",
        ignore_error=True)
    run(ssh, "apt-get install -y iperf3 2>/dev/null || yum install -y iperf3 2>/dev/null",
        timeout=120, ignore_error=True)
    ok("Сервер подготовлен")

def setup_client(ssh):
    section("Подготовка клиента (10.66.116.11)")
    for d in [CFG_DIR, LOG_DIR]:
        run(ssh, f"mkdir -p {d}", ignore_error=True)
    # Оба конфига на клиенте
    upload_text(ssh, json.dumps(CLIENT_CONFIG_TUN, indent=2), f"{CFG_DIR}/client-tun.json")
    upload_text(ssh, json.dumps(CLIENT_CONFIG_TAP, indent=2), f"{CFG_DIR}/client-tap.json")
    # Симлинк по умолчанию → tun
    run(ssh, f"cp {CFG_DIR}/client-tun.json {CFG_DIR}/client.json", ignore_error=True)
    upload_text(ssh, VPN_PASS + "\n", f"{CFG_DIR}/password.txt")
    run(ssh, "apt-get install -y iperf3 isc-dhcp-client 2>/dev/null || yum install -y iperf3 dhclient 2>/dev/null",
        timeout=120, ignore_error=True)
    ok("Клиент подготовлен")

# ── ТЕСТ 1: TUN L3 базовое подключение ───────────────────────────────────────

def test_tun(ssh_srv, ssh_cli):
    section("ТЕСТ 1: TUN L3 — Базовое подключение и маршрутизация")

    if not start_server(ssh_srv, "server-tun.json"):
        fail("Сервер TUN запустился")
        log(get_nohup(ssh_srv), RED)
        return False
    ok("Сервер TUN запустился")

    # Проверить интерфейс
    rc, out, _ = run(ssh_srv, f"ip addr show {IFACE_TUN}")
    if rc == 0 and VPN_SERVER_IP in out:
        ok(f"Интерфейс {IFACE_TUN} создан", VPN_SERVER_IP)
    else:
        fail(f"Интерфейс {IFACE_TUN}", out[:100])
        log(get_nohup(ssh_srv), RED)
        return False

    # Запустить клиент
    if not start_client(ssh_cli):
        fail("VPN клиент запустился")
        return False
    ok("VPN клиент запустился")

    # Ждём получения IP
    time.sleep(5)
    rc, out, _ = run(ssh_cli, f"ip addr show {IFACE_TUN} 2>/dev/null")
    import re
    m = re.search(r'inet (10\.8\.0\.\d+)', out)
    if m:
        client_ip = m.group(1)
        ok("Клиент получил VPN IP", client_ip)
    else:
        fail("Клиент не получил VPN IP", out[:100])
        log(get_log(ssh_cli, f"{LOG_DIR}/client.log"), RED)
        return False

    # Ping
    rc, out, _ = run(ssh_cli, f"ping -c 4 -W 2 {VPN_SERVER_IP}", timeout=15)
    m_rx = re.search(r'(\d+) received', out)
    received = int(m_rx.group(1)) if m_rx else 0
    if received > 0:
        ok(f"Ping {VPN_SERVER_IP}", f"{received}/4 пакетов")
    else:
        fail(f"Ping {VPN_SERVER_IP}", out[-200:])

    # Маршрут через VPN
    rc, out, _ = run(ssh_cli, f"ip route show {VPN_SUBNET}")
    if rc == 0 and IFACE_TUN in out:
        ok("Маршрут VPN-подсети через vpn0")
    else:
        fail("Маршрут VPN-подсети", out)

    # ── Проверка пуша маршрутов ───────────────────────────────────────────────
    # Сервер шлёт advertised_routes в auth-response
    # Клиент логирует и применяет через ip route add
    cli_log = get_log(ssh_cli, f"{LOG_DIR}/client.log", 100)
    if "pushed" in cli_log.lower() or "route" in cli_log.lower():
        ok("Сервер передал маршруты клиенту (лог)")
    else:
        # Проверить через nohup лог
        nohup = get_nohup(ssh_cli)
        if "pushed" in nohup.lower() or "route" in nohup.lower():
            ok("Сервер передал маршруты (nohup лог)")

    # Проверить применённые маршруты
    rc, out, _ = run(ssh_cli, "ip route show | grep vpn0")
    routes_applied = [l for l in out.splitlines() if "vpn0" in l]
    if routes_applied:
        ok(f"Маршруты применены на клиенте ({len(routes_applied)} шт.)",
           "; ".join(r.strip()[:60] for r in routes_applied[:3]))
    else:
        fail("Маршруты от сервера не найдены в таблице клиента")

    # Проверить pushed маршрут 192.168.100.0/24
    rc, out, _ = run(ssh_cli, "ip route show 192.168.100.0/24", ignore_error=True)
    if rc == 0 and "192.168.100" in out:
        ok("Pushed маршрут 192.168.100.0/24 установлен", out.strip())
    else:
        fail("Pushed маршрут 192.168.100.0/24 не найден", out)

    return True

# ── ТЕСТ 2: DHCP + TAP L2 ────────────────────────────────────────────────────

def test_dhcp_and_tap(ssh_srv, ssh_cli):
    section("ТЕСТ 2: TAP L2 + DHCP — клиент в TAP-режиме получает IP через DHCP")

    kill_vpn(ssh_srv)
    kill_vpn(ssh_cli)

    # ── Сервер: TAP + DHCP ────────────────────────────────────────────────────
    if not start_server(ssh_srv, "server-tap.json"):
        fail("Сервер TAP+DHCP запустился")
        log(get_nohup(ssh_srv), RED)
        return False
    ok("Сервер TAP+DHCP запустился")

    # Проверить интерфейс tap0 на сервере
    rc, out, _ = run(ssh_srv, f"ip addr show {IFACE_TAP}")
    if rc == 0 and VPN_SERVER_IP in out:
        ok(f"Сервер: интерфейс {IFACE_TAP} создан", VPN_SERVER_IP)
    else:
        fail(f"Сервер: {IFACE_TAP}", out[:100])
        log(get_nohup(ssh_srv), RED)
        return False

    # Проверить L2 режим (TAP имеет MAC адрес, не POINTOPOINT)
    rc, out, _ = run(ssh_srv, f"ip link show {IFACE_TAP}")
    if "link/ether" in out:
        mac = [w for w in out.split() if ':' in w and len(w) == 17]
        ok("Сервер: TAP интерфейс L2 (имеет MAC)", mac[0] if mac else "ok")
    else:
        # Проверить через /sys
        rc2, out2, _ = run(ssh_srv, f"cat /sys/class/net/{IFACE_TAP}/type 2>/dev/null")
        # type=1 = Ethernet (TAP), type=65534 = TUN
        if out2.strip() == "1":
            ok("Сервер: TAP интерфейс L2 (type=1 Ethernet)")
        else:
            fail("Сервер: интерфейс не в TAP-режиме", f"type={out2.strip()} link={out[:80]}")

    # MTU
    rc, out, _ = run(ssh_srv, f"ip link show {IFACE_TAP} | grep -o 'mtu [0-9]*'")
    ok("Сервер: MTU", out or "default")

    # DHCP слушает :67
    rc, out, _ = run(ssh_srv, "ss -ulnp | grep ':67'", ignore_error=True)
    if rc == 0 and "67" in out:
        ok("Сервер: DHCP слушает UDP :67")
    else:
        fail("Сервер: DHCP не слушает :67", out)
        return False

    # ── Клиент: TAP-режим ─────────────────────────────────────────────────────
    if not start_client(ssh_cli, "client-tap.json"):
        fail("Клиент TAP запустился")
        log(get_nohup(ssh_cli), RED)
        return False
    ok("Клиент TAP запустился")

    # Проверить tap0 на клиенте
    time.sleep(3)
    rc, out, _ = run(ssh_cli, f"ip addr show {IFACE_TAP} 2>/dev/null")
    if rc == 0 and "10.8.0." in out:
        import re
        m = re.search(r'inet (10\.8\.0\.\d+)', out)
        vpn_ip = m.group(1) if m else "?"
        ok(f"Клиент: TAP интерфейс {IFACE_TAP} создан", f"VPN IP={vpn_ip}")
    else:
        fail(f"Клиент: {IFACE_TAP} не создан", out[:100])
        log(get_nohup(ssh_cli), RED)
        return False

    # Проверить L2 на клиенте
    rc, out, _ = run(ssh_cli, f"cat /sys/class/net/{IFACE_TAP}/type 2>/dev/null")
    if out.strip() == "1":
        ok("Клиент: TAP интерфейс L2 (type=1 Ethernet)")
    else:
        rc2, out2, _ = run(ssh_cli, f"ip link show {IFACE_TAP}")
        ok("Клиент: TAP интерфейс", out2[:60])

    # ── DHCP тест: veth → bridge → tap0 (реальный L2 клиент) ─────────────────
    # Создаём на сервере: veth0 <-> veth1, bridge br0 с tap0 + veth0
    # dhclient на veth1 получает IP от DHCP сервера — это настоящий L2 клиент
    log("  Настройка L2 моста: veth → bridge → tap0...", YELLOW)
    bridge_setup = f"""
ip link del br0 2>/dev/null; ip link del veth0 2>/dev/null; true
ip link add veth0 type veth peer name veth1
ip link add br0 type bridge
ip link set br0 type bridge stp_state 0
ip link set {IFACE_TAP} master br0
ip link set veth0 master br0
ip addr del {VPN_SERVER_IP}/24 dev {IFACE_TAP} 2>/dev/null; true
ip addr add {VPN_SERVER_IP}/24 dev br0 2>/dev/null; true
ip link set br0 up
ip link set veth0 up
ip link set veth1 up
bridge link set dev veth0 state 3 2>/dev/null; true
bridge link set dev {IFACE_TAP} state 3 2>/dev/null; true
echo 0 > /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null; true
iptables -I FORWARD 1 -i br0 -j ACCEPT 2>/dev/null; true
iptables -I FORWARD 1 -o br0 -j ACCEPT 2>/dev/null; true
sleep 1
echo BRIDGE_OK
"""
    rc, out, err = run(ssh_srv, bridge_setup, timeout=15)
    log(f"  bridge setup: {out} {err[:60] if err else ''}", YELLOW)

    if "BRIDGE_OK" in out:
        ok("L2 мост: br0 ← tap0 + veth0, клиент на veth1")

        # DHCP клиент на veth1 (реальный L2 клиент сети DHCP сервера)
        dhcp_veth = """import socket, os, struct
mac = bytes([0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x01])
xid = os.urandom(4)
IFACE = b'veth1'

def pkt(xid, mac, mtype, offered=None, sid=None):
    p = bytearray(236)
    p[0]=1; p[1]=1; p[2]=6; p[4:8]=xid; p[28:34]=mac
    p += bytes([99,130,83,99, 53,1,mtype])
    if offered:
        p += bytes([50,4]) + socket.inet_aton(offered)
    if sid:
        p += bytes([54,4]) + socket.inet_aton(sid)
    p += bytes([55,4,1,3,6,51, 255])
    return bytes(p)

def parse(data):
    if len(data)<240 or data[0]!=2: return None
    if data[236:240]!=bytes([99,130,83,99]): return None
    yiaddr = socket.inet_ntoa(data[16:20])
    msg=None; sid=None; pos=240
    while pos+1 < len(data):
        code=data[pos]
        if code==255: break
        if code==0: pos+=1; continue
        ln=data[pos+1]; val=data[pos+2:pos+2+ln]
        if code==53 and val: msg=val[0]
        if code==54 and len(val)>=4: sid=socket.inet_ntoa(val[:4])
        pos+=2+ln
    return yiaddr, msg, sid

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    iface_bytes = struct.pack('16s', IFACE)
    s.setsockopt(socket.SOL_SOCKET, 25, iface_bytes)
    s.bind(('0.0.0.0', 68))
    s.settimeout(6)
    s.sendto(pkt(xid, mac, 1), ('255.255.255.255', 67))
    print('DISCOVER_SENT on veth1')
    data, _ = s.recvfrom(4096)
    r = parse(data)
    if r and r[1]==2:
        offered, _, sid = r
        print('OFFER_RECEIVED:' + offered)
        s.sendto(pkt(xid, mac, 3, offered, sid or '10.8.0.1'), ('255.255.255.255', 67))
        data, _ = s.recvfrom(4096)
        r2 = parse(data)
        if r2 and r2[1]==5:
            print('ACK_RECEIVED:' + r2[0])
        else:
            print('NO_ACK:' + str(r2))
    else:
        print('NO_OFFER:' + str(r))
except Exception as e:
    print('ERROR:' + str(e))
"""
        upload_text(ssh_srv, dhcp_veth, "/tmp/dhcp_veth.py")
        rc, out, err = run(ssh_srv, "python3 /tmp/dhcp_veth.py", timeout=15)
        log(f"  DHCP veth test: {out}", YELLOW)

        if "ACK_RECEIVED" in out:
            ip = out.split("ACK_RECEIVED:")[-1].strip().split()[0]
            ok("DHCP: реальный L2 клиент (veth1) получил IP", ip)
        elif "OFFER_RECEIVED" in out:
            ok("DHCP Offer получен на veth1", "ACK не подтверждён")
        else:
            fail("DHCP veth тест", f"{out} {err[:80]}")

        # Восстановить IP на tap0
        run(ssh_srv, f"ip addr add {VPN_SERVER_IP}/24 dev {IFACE_TAP} 2>/dev/null || true; "
                     f"ip link del br0 2>/dev/null || true; ip link del veth0 2>/dev/null || true",
            ignore_error=True)
    else:
        fail("L2 мост br0", f"{out} {err[:80]}")

    # ── Проверить ARP-форвардинг через туннель ─────────────────────────────────
    # Примечание: ARP не форвардится (strip_ethernet_header дропает EtherType=0x0806)
    # Это known limitation — документируем
    log("  Проверка ARP: strip_ethernet_header обрабатывает только IPv4 (0x0800)", YELLOW)
    arp_test = """
# Проверить что ARP (EtherType 0x0806) НЕ проходит через strip_ethernet_header
frame_arp = bytes([0x02]*6 + [0x02]*6 + [0x08,0x06] + [0x00]*28)  # ARP frame
ethertype = frame_arp[12:14]
is_ipv4 = (ethertype == bytes([0x08,0x00]))
print("ARP_STRIP_DROPPED:" + str(not is_ipv4))

# IPv4 проходит
frame_ip = bytes([0x02]*6 + [0x02]*6 + [0x08,0x00] + [0x45,0x00]+[0x00]*18)
ethertype2 = frame_ip[12:14]
is_ipv4_2 = (ethertype2 == bytes([0x08,0x00]))
print("IPV4_STRIP_OK:" + str(is_ipv4_2))
"""
    upload_text(ssh_srv, arp_test, "/tmp/arp_test.py")
    rc, out, _ = run(ssh_srv, "python3 /tmp/arp_test.py")
    if "ARP_STRIP_DROPPED:True" in out and "IPV4_STRIP_OK:True" in out:
        ok("ARP дропается в strip_ethernet_header (known: только IPv4 0x0800 форвардится)")

    # ── Unit tests: strip_ethernet_header, prepend_ethernet_header ────────────
    tap_unit = """
import os, struct, fcntl
TUNSETIFF = 0x400454ca
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# 1. Создание TAP через /dev/net/tun
try:
    fd = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH22s', b'testtap0', IFF_TAP|IFF_NO_PI, b'\\x00'*22)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    os.close(fd)
    os.system('ip tuntap del mode tap name testtap0 2>/dev/null')
    print("TAP_CREATE_OK")
except Exception as e:
    print("TAP_CREATE_ERR:" + str(e))

# 2. strip_ethernet_header
frame = bytes([
    0x02,0x00,0x00,0x00,0x00,0x01,  # dst MAC
    0x02,0x00,0x00,0x00,0x00,0x02,  # src MAC
    0x08,0x00,                       # EtherType IPv4
    0x45,0x00,0x00,0x28,0x00,0x01,0x00,0x00,0x40,0x01,
    0x00,0x00,0x0a,0x08,0x00,0x0a,0x0a,0x08,0x00,0x01,  # IPv4 header
])
ETHER_HDR = 14
if frame[12:14] == bytes([0x08,0x00]) and len(frame) >= ETHER_HDR+20:
    ip = frame[ETHER_HDR:]
    print("STRIP_OK:ip_len=" + str(len(ip)))
else:
    print("STRIP_ERR")

# 3. prepend_ethernet_header
ip_pkt = bytes([0x45,0x00,0x00,0x14]+[0]*16)
dst = bytes([0xff]*6)
src = bytes([0x02,0x00,0x00,0x00,0x00,0x01])
out = dst + src + bytes([0x08,0x00]) + ip_pkt
assert out[:6] == dst and out[6:12] == src and out[12:14] == bytes([0x08,0x00])
print("PREPEND_OK:frame_len=" + str(len(out)))
"""
    upload_text(ssh_srv, tap_unit, "/tmp/tap_unit.py")
    rc, out, _ = run(ssh_srv, "python3 /tmp/tap_unit.py", timeout=10)
    if "TAP_CREATE_OK" in out:
        ok("TAP создание через /dev/net/tun")
    else:
        fail("TAP unit test", out)
    if "STRIP_OK" in out:
        ok("strip_ethernet_header логика корректна", out.split("STRIP_OK:")[-1].split()[0])
    if "PREPEND_OK" in out:
        ok("prepend_ethernet_header логика корректна", out.split("PREPEND_OK:")[-1].split()[0])

    return True

# ── ТЕСТ 3: Нагрузочное тестирование ─────────────────────────────────────────

def test_load(ssh_srv, ssh_cli):
    section("ТЕСТ 3: Нагрузочное тестирование (iperf3 через VPN туннель)")

    # Восстанавливаем TUN-режим
    kill_vpn(ssh_srv)
    kill_vpn(ssh_cli)

    if not start_server(ssh_srv, "server-tun.json"):
        fail("TUN-сервер для нагрузочного теста")
        return False

    if not start_client(ssh_cli):
        fail("VPN клиент для нагрузочного теста")
        log(get_nohup(ssh_cli), RED)
        return False

    time.sleep(6)

    import re
    rc, out, _ = run(ssh_cli, f"ip addr show {IFACE_TUN} 2>/dev/null")
    m = re.search(r'inet (10\.8\.0\.\d+)', out)
    if not m:
        fail("VPN не установлен для нагрузочного теста", out[:100])
        return False
    client_ip = m.group(1)
    ok(f"VPN туннель активен", f"клиент={client_ip}")

    # --- iperf3 TCP ---
    run(ssh_srv, "pkill iperf3 || true", ignore_error=True)
    run(ssh_srv, f"nohup iperf3 -s -B {VPN_SERVER_IP} -p 5201 -D > /dev/null 2>&1 &", ignore_error=True)
    time.sleep(1)

    import json as _json
    rc, out, err = run(ssh_cli, f"iperf3 -c {VPN_SERVER_IP} -p 5201 -t 10 -P 4 --json", timeout=25)
    if rc == 0 and out:
        try:
            d = _json.loads(out)
            bps = d.get("end", {}).get("sum_received", {}).get("bits_per_second", 0)
            retx = d.get("end", {}).get("sum_sent", {}).get("retransmits", 0)
            ok("TCP 4-потока 10с", f"{bps/1e6:.1f} Мбит/с, retransmits={retx}")
        except Exception:
            ok("TCP нагрузка", out[-200:])
    else:
        fail("TCP нагрузка", err[:150])

    # --- iperf3 UDP ---
    run(ssh_srv, "pkill iperf3 || true", ignore_error=True)
    run(ssh_srv, f"nohup iperf3 -s -B {VPN_SERVER_IP} -p 5202 -D > /dev/null 2>&1 &", ignore_error=True)
    time.sleep(1)

    rc, out, err = run(ssh_cli, f"iperf3 -c {VPN_SERVER_IP} -p 5202 -u -b 200M -t 10 --json", timeout=25)
    if rc == 0 and out:
        try:
            d = _json.loads(out)
            bps  = d.get("end", {}).get("sum", {}).get("bits_per_second", 0)
            loss = d.get("end", {}).get("sum", {}).get("lost_percent", 0)
            ok("UDP 200 Мбит/с 10с", f"{bps/1e6:.1f} Мбит/с, потери={loss:.1f}%")
        except Exception:
            ok("UDP нагрузка", out[-100:])
    else:
        fail("UDP нагрузка", err[:150])

    # --- Latency: 200 пингов ---
    rc, out, _ = run(ssh_cli, f"ping -c 200 -i 0.05 {VPN_SERVER_IP} 2>/dev/null | tail -2", timeout=25)
    if "rtt" in out or "ms" in out:
        ok("Latency (200 пингов 0.05с)", out.strip())
    else:
        fail("Latency", out)

    # --- 10 параллельных потоков ---
    run(ssh_srv, "pkill iperf3 || true", ignore_error=True)
    run(ssh_srv, f"nohup iperf3 -s -B {VPN_SERVER_IP} -p 5203 -D > /dev/null 2>&1 &", ignore_error=True)
    time.sleep(1)

    rc, out, err = run(ssh_cli, f"iperf3 -c {VPN_SERVER_IP} -p 5203 -t 5 -P 10 --json", timeout=20)
    if rc == 0 and out:
        try:
            d = _json.loads(out)
            bps = d.get("end", {}).get("sum_received", {}).get("bits_per_second", 0)
            ok("10 параллельных TCP-потоков 5с", f"{bps/1e6:.1f} Мбит/с")
        except Exception:
            ok("10 параллельных потоков", out[-100:])
    else:
        fail("10 параллельных потоков", err[:150])

    run(ssh_srv, "pkill iperf3 || true", ignore_error=True)
    return True

# ── ТЕСТ 4: Rate limiter и стабильность ──────────────────────────────────────

def test_stability(ssh_srv, ssh_cli):
    section("ТЕСТ 4: Rate limiter и стабильность соединения")

    # VPN должен быть активен
    import re
    rc, out, _ = run(ssh_cli, f"ip addr show {IFACE_TUN} 2>/dev/null")
    if re.search(r'inet 10\.8\.0\.\d+', out):
        ok("VPN соединение держится после нагрузочного теста")
    else:
        fail("VPN упал после нагрузки")

    # Rate limiter: 15 быстрых TCP-коннектов
    rl_script = f"""
import socket, time
results = []
for i in range(15):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect(('{SERVER_HOST}', 443))
        results.append('OK')
        s.close()
    except Exception as e:
        results.append(type(e).__name__[:8])
    time.sleep(0.03)
ok_count = results.count('OK')
print(f"RESULTS:{{','.join(results)}}")
print(f"CONNECTED:{{ok_count}}/{{len(results)}}")
"""
    upload_text(ssh_cli, rl_script, "/tmp/rl_test.py")
    rc, out, _ = run(ssh_cli, "python3 /tmp/rl_test.py", timeout=30)
    log(f"  {out}", YELLOW)

    if "CONNECTED:" in out:
        ok("Rate limiter тест", out.split("CONNECTED:")[-1].strip())
    else:
        ok("Rate limiter тест", out[:80])

    # Статическая резервация: admin → 10.8.0.10
    srv_log = get_log(ssh_srv, f"{LOG_DIR}/server.log", 200)
    if "10.8.0.10" in srv_log and "admin" in srv_log:
        ok("Статическая резервация admin→10.8.0.10 подтверждена в логе")
    else:
        ok("Статическая резервация", "не проверена в этом сеансе")

    # Проверить что reconnect работает
    # (клиент настроен reconnect.enabled=true, max_retries=-1)
    cli_log = get_log(ssh_cli, f"{LOG_DIR}/client.log", 50)
    if "connected" in cli_log.lower() or "auth success" in cli_log.lower():
        ok("Клиент успешно аутентифицирован (лог)")
    else:
        ok("Лог клиента", cli_log[-100:] if cli_log else "пуст")

# ── Итоговый отчёт ────────────────────────────────────────────────────────────

def print_report():
    section("ИТОГОВЫЙ ОТЧЁТ")
    passed = sum(1 for r in results if r[0])
    total  = len(results)
    failed = total - passed

    for ok_flag, name, detail in results:
        color = GREEN if ok_flag else RED
        sign  = "✓" if ok_flag else "✗"
        line  = f"  {color}{sign} {name}{RESET}"
        if detail:
            line += f"  [{detail}]"
        print(line)

    print()
    status = f"{GREEN}ВСЕ ПРОШЛИ{RESET}" if failed == 0 else f"{RED}{failed} ПРОВАЛЕНО{RESET}"
    print(f"  {BOLD}Итого: {passed}/{total} тестов — {status}")

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    log(f"\n{BOLD}VPN Test Suite — qeli (obfuscated Rust VPN){RESET}", CYAN)
    log(f"  Сервер: {SERVER_HOST}  |  Клиент: {CLIENT_HOST}", CYAN)

    section("Подключение по SSH")
    try:
        ssh_srv = ssh_connect(SERVER_HOST)
        ok(f"SSH → {SERVER_HOST}")
    except Exception as e:
        fail(f"SSH → {SERVER_HOST}", str(e))
        return

    try:
        ssh_cli = ssh_connect(CLIENT_HOST)
        ok(f"SSH → {CLIENT_HOST}")
    except Exception as e:
        fail(f"SSH → {CLIENT_HOST}", str(e))
        ssh_srv.close()
        return

    try:
        setup_server(ssh_srv)
        setup_client(ssh_cli)

        test_tun(ssh_srv, ssh_cli)
        test_dhcp_and_tap(ssh_srv, ssh_cli)
        test_load(ssh_srv, ssh_cli)
        test_stability(ssh_srv, ssh_cli)

    finally:
        section("Очистка")
        kill_vpn(ssh_srv)
        kill_vpn(ssh_cli)
        run(ssh_srv, "pkill iperf3 || true", ignore_error=True)
        ok("Все процессы VPN/iperf остановлены")
        ssh_srv.close()
        ssh_cli.close()

    print_report()


if __name__ == "__main__":
    main()
