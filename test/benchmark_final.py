#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Qeli VPN — финальное нагрузочное тестирование
Режимы: TUN / TAP / REALITY  x  TCP / UDP
"""
import os

import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko, time, json, copy

SERVER_HOST = "10.66.116.10"
CLIENT_HOST = "10.66.116.11"
VPN_SERVER_IP = "10.8.0.1"
CFG_DIR = "/etc/qeli"
LOG_DIR = "/var/log/qeli"
BINARY  = "/usr/bin/qeli"

# ── Конфиги ──────────────────────────────────────────────────────────────────

SERVER_BASE = {
    "bind": {"address": "0.0.0.0", "port": 443, "transport": "tcp"},
    "tun": {"name": "vpn0", "address": VPN_SERVER_IP, "netmask": "255.255.255.0",
             "mtu": 1500, "tx_queue_len": 1000},
    "auth": {"users_file": f"{CFG_DIR}/users.json", "password_hash": "argon2id"},
    "pool": {"cidr": "10.8.0.0/24", "exclude": [VPN_SERVER_IP],
             "lease_time_secs": 3600, "static_reservations": {"admin": "10.8.0.10"}},
    "dns": {"enabled": True, "listen": VPN_SERVER_IP, "port": 53,
             "upstream": ["1.1.1.1", "8.8.8.8"]},
    "routing": {"advertised_routes": [{"cidr": "10.8.0.0/24", "metric": 50}]},
    "obfuscation": {
        "cipher": "chacha20-poly1305",
        "tls": {"server_name": "www.cloudflare.com", "session_id": True,
                "supported_groups": ["x25519", "secp256r1"], "key_share_entropy_bytes": 32,
                "reality_proxy": {"enabled": False, "target": "www.cloudflare.com", "target_port": 443}},
        "padding": {"enabled": True, "min_bytes": 32, "max_bytes": 512, "randomize": True, "probability": 0.8},
        "fragmentation": {"enabled": True, "min_chunk_size": 64, "max_chunk_size": 512, "max_fragments_per_packet": 16},
        "heartbeat": {"enabled": True, "interval_ms": 1000, "data_size_bytes": 16, "jitter_ms": 100},
        "traffic_normalization": {"enabled": False},
        "anti_fingerprinting": {"enabled": True, "rotate_ciphers_every": 300, "add_jitter_to_handshake": True}
    },
    "performance": {
        "tcp": {"nodelay": True, "keepalive_secs": 60, "send_buffer_size": 262144, "recv_buffer_size": 262144},
        "tun": {"read_buffer_size": 65535, "write_buffer_size": 65535, "read_timeout_ms": 10, "max_pending_packets": 256},
        "connection": {"max_clients": 128, "handshake_timeout_secs": 10, "idle_timeout_secs": 600}
    },
    "logging": {"level": "info", "file": f"{LOG_DIR}/server.log"}
}

CLIENT_BASE = {
    "server": {"address": SERVER_HOST, "port": 443, "protocol": "tcp",
                "connection_timeout_secs": 30, "tcp_keepalive_secs": 60,
                "reconnect": {"enabled": True, "max_retries": -1, "base_delay_secs": 1, "max_delay_secs": 10}},
    "auth": {"username": "admin", "password_file": f"{CFG_DIR}/password.txt"},
    "tun": {"name": "vpn0", "mtu": 1500},
    "routing": {"mode": "split-tunnel", "bypass_local": True},
    "dns": {"mode": "tunnel", "servers": [VPN_SERVER_IP, "1.1.1.1"]},
    "obfuscation": {
        "cipher": "chacha20-poly1305",
        "padding": {"enabled": True},
        "heartbeat": {"enabled": True},
        "quic": {"enabled": False, "cid_length": 4, "version": 1}
    },
    "performance": {"tcp_nodelay": True, "tun_buffer_size": 65535, "idle_timeout_secs": 600},
    "logging": {"level": "info", "file": f"{LOG_DIR}/client.log"}
}

# ── SSH helpers ───────────────────────────────────────────────────────────────

def ssh(host):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
    return c

def run(s, cmd, t=60):
    _, o, e = s.exec_command(cmd, timeout=t)
    try:
        out = o.read().decode(errors='replace').strip()
    except Exception:
        out = ""
    try:
        err = e.read().decode(errors='replace').strip()
    except Exception:
        err = ""
    return out, err

def upload(s, content, path):
    sftp = s.open_sftp()
    sftp.putfo(io.BytesIO(content.encode()), path)
    sftp.close()

def kill_vpn(s):
    run(s, "pkill -SIGTERM -f 'qeli ' 2>/dev/null; sleep 1", t=5)
    run(s, "ip link del vpn0 2>/dev/null; ip link del tap0 2>/dev/null", t=3)

def start_server(s, cfg_name):
    kill_vpn(s)
    run(s, "systemctl stop qeli 2>/dev/null; sleep 1", t=5)
    run(s, "rm -f /tmp/qeli_srv.log")
    s.exec_command(f"nohup env RUST_LOG=info {BINARY} server --config {CFG_DIR}/{cfg_name} > /tmp/qeli_srv.log 2>&1 &")
    time.sleep(4)
    out, _ = run(s, "pgrep -f 'qeli server'", t=5)
    if out:
        return True
    # Показать лог если не запустился
    log, _ = run(s, "tail -3 /tmp/qeli_srv.log", t=5)
    print(f"  [srv log]: {log}")
    return False

def start_client(s, cfg_name="client.json"):
    kill_vpn(s)
    run(s, "rm -f /tmp/qeli_cli.log")
    s.exec_command(f"nohup env RUST_LOG=info {BINARY} client --config {CFG_DIR}/{cfg_name} > /tmp/qeli_cli.log 2>&1 &")
    time.sleep(7)
    out, _ = run(s, "pgrep -f 'qeli client'", t=5)
    if out:
        return True
    log, _ = run(s, "tail -3 /tmp/qeli_cli.log", t=5)
    print(f"  [cli log]: {log}")
    return False

def wait_vpn_ip(s, iface="vpn0", timeout=15):
    import re
    for _ in range(timeout):
        out, _ = run(s, f"ip addr show {iface} 2>/dev/null", t=5)
        m = re.search(r'inet (10\.8\.0\.\d+)', out)
        if m:
            return m.group(1)
        time.sleep(1)
    return None

# ── Benchmark ─────────────────────────────────────────────────────────────────

def _start_iperf_srv(srv, port):
    """Запустить iperf3 сервер без -B (слушает 0.0.0.0), убить предыдущий."""
    run(srv, f"pkill iperf3 2>/dev/null; sleep 0.3", t=3)
    run(srv, f"nohup iperf3 -s -p {port} > /tmp/iperf_{port}.log 2>&1 &", t=3)
    time.sleep(1)

def bench_tcp(srv, cli, port=5201, duration=15, parallel=4):
    _start_iperf_srv(srv, port)
    out, err = run(cli, f"iperf3 -c {VPN_SERVER_IP} -p {port} -t {duration} -P {parallel} --json", t=duration+20)
    run(srv, "pkill iperf3 2>/dev/null", t=3)
    try:
        d = json.loads(out)
        bps   = d["end"]["sum_received"]["bits_per_second"]
        retx  = d["end"]["sum_sent"]["retransmits"]
        return round(bps / 1e6, 1), retx
    except:
        return None, None

def bench_udp(srv, cli, port=5202, duration=15, target_mbps=300):
    _start_iperf_srv(srv, port)
    out, err = run(cli, f"iperf3 -c {VPN_SERVER_IP} -p {port} -u -b {target_mbps}M -t {duration} --json", t=duration+20)
    run(srv, "pkill iperf3 2>/dev/null", t=3)
    try:
        d = json.loads(out)
        bps  = d["end"]["sum"]["bits_per_second"]
        loss = d["end"]["sum"]["lost_percent"]
        return round(bps / 1e6, 1), round(loss, 2)
    except:
        return None, None

def bench_latency(cli, count=200):
    out, _ = run(cli, f"ping -c {count} -i 0.05 -W 2 {VPN_SERVER_IP} 2>/dev/null | tail -2", t=60)
    import re
    m = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', out)
    if m:
        return float(m.group(1)), float(m.group(2)), float(m.group(3))
    return None, None, None

def bench_tcp_single(srv, cli, port=5203, duration=15):
    _start_iperf_srv(srv, port)
    out, _ = run(cli, f"iperf3 -c {VPN_SERVER_IP} -p {port} -t {duration} --json", t=duration+20)
    run(srv, "pkill iperf3 2>/dev/null", t=3)
    try:
        d = json.loads(out)
        bps  = d["end"]["sum_received"]["bits_per_second"]
        retx = d["end"]["sum_sent"]["retransmits"]
        return round(bps / 1e6, 1), retx
    except:
        return None, None

# ── Test modes ────────────────────────────────────────────────────────────────

def run_mode(srv, cli, mode_name, srv_cfg, cli_cfg, iface="vpn0", cli_cfg_name="client.json"):
    print(f"\n{'─'*60}")
    print(f"  Режим: {mode_name}")
    print(f"{'─'*60}")

    upload(srv, json.dumps(srv_cfg, indent=2), f"{CFG_DIR}/bench_srv.json")
    upload(cli, json.dumps(cli_cfg, indent=2), f"{CFG_DIR}/{cli_cfg_name}")

    if not start_server(srv, "bench_srv.json"):
        print("  ✗ Сервер не запустился")
        return None

    if not start_client(cli, cli_cfg_name):
        print("  ✗ Клиент не запустился")
        out, _ = run(cli, "tail -5 /tmp/qeli_cli.log", t=5)
        print(f"  Log: {out}")
        return None

    ip = wait_vpn_ip(cli, iface)
    if not ip:
        print(f"  ✗ VPN IP не получен ({iface})")
        return None
    print(f"  ✓ VPN активен, IP={ip}")

    # TAP mode: ARP кадры (EtherType 0x0806) не форвардятся через туннель.
    # Нужно: 1) выставить MAC tap0 на сервере = gateway_mac (02:00:00:00:00:01)
    #         2) включить promisc на сервере (чтобы принимать все Ethernet фреймы)
    #         3) добавить статические ARP на обоих концах
    if iface == "tap0":
        # Код qeli записывает в tap0 фреймы с dst=02:00:00:00:00:01 (gateway_mac).
        # Ядро принимает фрейм только если dst совпадает с MAC интерфейса.
        # Решение: выставить оба tap0 на MAC=02:00:00:00:00:01.
        TAP_MAC = "02:00:00:00:00:01"
        # Меняем MAC без down (чтобы не слетел IP)
        for host in [srv, cli]:
            run(host, f"ip link set {iface} address {TAP_MAC}", t=5)
        # Явно восстанавливаем IP (смена MAC может его снять)
        run(srv, f"ip addr add {VPN_SERVER_IP}/24 dev {iface} 2>/dev/null || true", t=5)
        # Проверяем что IP есть
        ip_check, _ = run(srv, f"ip addr show {iface} | grep {VPN_SERVER_IP}", t=5)
        if not ip_check:
            print(f"  ⚠ IP {VPN_SERVER_IP} не найден на {iface} сервера!")
        # Статические ARP: оба конца знают MAC партнёра без ARP-запроса
        run(srv, f"ip neigh replace 10.8.0.10 lladdr {TAP_MAC} dev {iface} nud permanent", t=5)
        run(cli, f"ip neigh replace {VPN_SERVER_IP} lladdr {TAP_MAC} dev {iface} nud permanent", t=5)
        # Проверить пинг
        ping_ok, _ = run(cli, f"ping -c 3 -W 2 {VPN_SERVER_IP} 2>/dev/null | grep -c '0% packet loss'", t=15)
        status = "OK" if ping_ok.strip() == "1" else "ping failed"
        print(f"  ✓ TAP: оба MAC={TAP_MAC}, статические ARP ({status})")
        time.sleep(1)

    res = {}

    print("  → TCP 1 поток...")
    res["tcp1_mbps"], res["tcp1_retx"] = bench_tcp_single(srv, cli, port=5201, duration=15)
    print(f"     {res['tcp1_mbps']} Мбит/с, retx={res['tcp1_retx']}")

    print("  → TCP 4 потока...")
    res["tcp4_mbps"], res["tcp4_retx"] = bench_tcp(srv, cli, port=5202, duration=15, parallel=4)
    print(f"     {res['tcp4_mbps']} Мбит/с, retx={res['tcp4_retx']}")

    print("  → UDP (target 300 Мбит/с)...")
    res["udp_mbps"], res["udp_loss"] = bench_udp(srv, cli, port=5203, duration=15, target_mbps=300)
    print(f"     {res['udp_mbps']} Мбит/с, потери={res['udp_loss']}%")

    print("  → Latency (200 пингов)...")
    res["lat_min"], res["lat_avg"], res["lat_max"] = bench_latency(cli, 200)
    print(f"     min={res['lat_min']}ms avg={res['lat_avg']}ms max={res['lat_max']}ms")

    kill_vpn(srv)
    kill_vpn(cli)
    time.sleep(2)
    return res

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("="*60)
    print("  QELI VPN — ФИНАЛЬНОЕ НАГРУЗОЧНОЕ ТЕСТИРОВАНИЕ")
    print("="*60)
    print(f"  Сервер: {SERVER_HOST}  Клиент: {CLIENT_HOST}")

    srv = ssh(SERVER_HOST)
    cli = ssh(CLIENT_HOST)

    # Убедиться что iperf3 есть
    run(srv, "apt-get install -y iperf3 2>/dev/null || true", t=60)
    run(cli, "apt-get install -y iperf3 2>/dev/null || true", t=60)

    results = {}

    # ── TUN mode ─────────────────────────────────────────────────────────────
    srv_tun = copy.deepcopy(SERVER_BASE)
    cli_tun = copy.deepcopy(CLIENT_BASE)
    results["TUN"] = run_mode(srv, cli, "TUN (L3)", srv_tun, cli_tun,
                               iface="vpn0", cli_cfg_name="client_tun.json")

    # ── TAP mode ─────────────────────────────────────────────────────────────
    srv_tap = copy.deepcopy(SERVER_BASE)
    srv_tap["tun"]["name"] = "tap0"
    srv_tap["tun"]["device_type"] = "tap"
    cli_tap = copy.deepcopy(CLIENT_BASE)
    cli_tap["tun"] = {"name": "tap0", "device_type": "tap", "mtu": 1500}
    results["TAP"] = run_mode(srv, cli, "TAP (L2)", srv_tap, cli_tap,
                               iface="tap0", cli_cfg_name="client_tap.json")

    # ── REALITY mode ──────────────────────────────────────────────────────────
    srv_reality = copy.deepcopy(SERVER_BASE)
    srv_reality["obfuscation"]["tls"]["reality_proxy"] = {
        "enabled": True,
        "target": "www.cloudflare.com",
        "target_port": 443
    }
    cli_reality = copy.deepcopy(CLIENT_BASE)
    results["REALITY"] = run_mode(srv, cli, "REALITY (TUN + reality proxy)", srv_reality, cli_reality,
                                   iface="vpn0", cli_cfg_name="client_reality.json")

    srv.close()
    cli.close()

    # ── Вывод таблицы ────────────────────────────────────────────────────────
    print("\n")
    print("="*75)
    print("  РЕЗУЛЬТАТЫ")
    print("="*75)

    header = f"{'Режим':<12} {'TCP×1':>9} {'TCP×4':>9} {'UDP':>9} {'Потери':>8} {'RTT min':>9} {'RTT avg':>9} {'RTT max':>9}"
    print(header)
    print("─"*75)

    for mode, r in results.items():
        if not r:
            print(f"{mode:<12} {'N/A':>9}")
            continue
        print(f"{mode:<12}"
              f" {str(r['tcp1_mbps'])+'M':>9}"
              f" {str(r['tcp4_mbps'])+'M':>9}"
              f" {str(r['udp_mbps'])+'M':>9}"
              f" {str(r['udp_loss'])+'%':>8}"
              f" {str(r['lat_min'])+'ms':>9}"
              f" {str(r['lat_avg'])+'ms':>9}"
              f" {str(r['lat_max'])+'ms':>9}")

    print("─"*75)
    print(f"  Параметры: TCP duration=15s | UDP target=300Mbit/s | Ping n=200 i=0.05s")
    print(f"  Инфраструктура: 2 vCPU / 2GB RAM / QEMU KVM / local network")

    return results

if __name__ == "__main__":
    import sys
    results = main()
    # Сохранить JSON для документации
    with open("benchmark_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print("\n  Результаты сохранены: benchmark_results.json")
