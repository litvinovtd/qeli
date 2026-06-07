"""End-to-end load test for qeli on the two lab VMs.

  SERVER 10.66.116.10  — runs `qeli server`, iperf3 -s bound to the tun IP
  CLIENT 10.66.116.11  — runs `qeli client`, iperf3 -c through the tunnel

Usage:
  python loadtest.py deploy      # build-binary push + configs to both VMs
  python loadtest.py tcp         # bring up TCP tunnel, run iperf3 (up + down)
  python loadtest.py udp         # same for the UDP profile
  python loadtest.py dnstest     # verify resolv.conf is restored on teardown
  python loadtest.py down        # stop qeli/iperf3 on both VMs

Safe-by-design: the client uses split-tunnel with an explicit `include` of only
the tunnel subnet, so NO default route is installed (SSH to the VMs survives).
"""
import os
import json
import sys
import time
import io
import paramiko

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SERVER = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
CLIENT = ("10.66.116.11", "root", os.environ.get("QELI_LAB_PASS", ""))
REMOTE_BIN = "/opt/qeli-src/target/release/qeli"
INSTALL_BIN = "/usr/local/bin/qeli"
PASSWORD = "testpass123"
ARGON2_HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"

OBFS_PSK = "qeli-obfs-shared-secret"
PROFILES = {
    "tcp": {"port": 443, "transport": "tcp", "tun_net": "10.9.0", "tun_if": "vpn0"},
    "udp": {"port": 4443, "transport": "udp", "tun_net": "10.10.0", "tun_if": "vpn1"},
    "obfs": {"port": 8443, "transport": "tcp", "tun_net": "10.11.0", "tun_if": "vpn2",
             "mode": "obfs", "obfs_key": OBFS_PSK},
}


def conn(host):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host[0], username=host[1], password=host[2], timeout=20,
              look_for_keys=False, allow_agent=False)
    return c


def run(c, cmd, timeout=120):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def put_text(c, path, text):
    sftp = c.open_sftp()
    sftp.putfo(io.BytesIO(text.encode()), path)
    sftp.close()


def server_config():
    obf = {
        "padding": {"enabled": True, "min_bytes": 32, "max_bytes": 256, "randomize": True, "probability": 0.8},
        "fragmentation": {"enabled": False},
        "heartbeat": {"enabled": True, "interval_ms": 15000, "jitter_ms": 2000},
    }
    def prof(name, p):
        o = dict(obf, quic={"enabled": False}) if p["transport"] == "udp" else dict(obf)
        if "mode" in p:
            o["mode"] = p["mode"]
            o["obfs_key"] = p["obfs_key"]
        return {
            "name": name,
            "bind": {"address": "0.0.0.0", "port": p["port"], "transport": p["transport"]},
            "tun": {"name": p["tun_if"], "address": f"{p['tun_net']}.1", "netmask": "255.255.255.0", "mtu": 1400, "device_type": "tun"},
            "pool": {"cidr": f"{p['tun_net']}.0/24", "exclude": [f"{p['tun_net']}.1"]},
            "routing": {"nat": {"enabled": False}, "forward_private": True},
            "dns": {"enabled": False},
            "obfuscation": o,
            # MUST be explicit: a missing `performance` block deserialises to the
            # derived Default (all zeros) — keepalive_secs=0 → EINVAL on connect,
            # handshake_timeout=0 → instant timeout, max_clients=0 → reject all.
            "performance": {
                "tcp": {"nodelay": True, "keepalive_secs": 60, "send_buffer_size": 262144, "recv_buffer_size": 262144},
                "tun": {"read_buffer_size": 65535, "write_buffer_size": 65535, "read_timeout_ms": 10, "max_pending_packets": 256},
                "connection": {"max_clients": 128, "handshake_timeout_secs": 10, "idle_timeout_secs": 0, "rate_limit_packets_per_sec": 1000000},
            },
        }
    return json.dumps({
        "profiles": [prof("tcp", PROFILES["tcp"]), prof("udp", PROFILES["udp"]), prof("obfs", PROFILES["obfs"])],
        "auth": {"users_file": "/etc/qeli/users.json"},
        "logging": {"level": "info", "file": "/var/log/qeli/server.log"},
        "web": {"enabled": False},
    }, indent=2)


def client_config(proto, dns_mode="off"):
    p = PROFILES[proto]
    obf = {
        "padding": {"enabled": True, "min_bytes": 32, "max_bytes": 256, "randomize": True, "probability": 0.8},
        "heartbeat": {"enabled": True, "interval_ms": 15000, "jitter_ms": 2000},
        "fragmentation": {"enabled": False},
        "quic": {"enabled": False},
    }
    if "mode" in p:
        obf["mode"] = p["mode"]
        obf["obfs_key"] = p["obfs_key"]
    return json.dumps({
        "server": {"address": SERVER[0], "port": p["port"], "protocol": p["transport"],
                   "connection_timeout_secs": 30, "tcp_keepalive_secs": 60, "reconnect": {"enabled": False}},
        "auth": {"username": "load", "password_file": "/etc/qeli/pass.txt"},
        "tun": {"name": p["tun_if"], "mtu": 1400},
        # explicit include => route.rs does NOT add a default route (SSH stays alive)
        "routing": {"mode": "split-tunnel", "include": [f"{p['tun_net']}.0/24"],
                    "bypass_private": True, "bypass_local": True},
        "dns": {"mode": dns_mode, "servers": ["10.9.0.1"]},
        "performance": {"tcp_nodelay": True, "tun_buffer_size": 65535, "idle_timeout_secs": 0},
        "obfuscation": obf,
        "logging": {"level": "info", "file": "/var/log/qeli/client.log"},
    }, indent=2)


def deploy():
    s = conn(SERVER)
    # install binary on server
    run(s, f"install -m755 {REMOTE_BIN} {INSTALL_BIN}")
    run(s, "mkdir -p /etc/qeli")
    put_text(s, "/etc/qeli/server.json", server_config())
    put_text(s, "/etc/qeli/users.json", json.dumps({
        "users": [{"username": "load", "password_hash": ARGON2_HASH, "enabled": True,
                   "bandwidth": {"limit_mbps": 0}}], "groups": {}}, indent=2))
    # pull binary from server, push to client
    sftp = s.open_sftp()
    buf = io.BytesIO()
    sftp.getfo(REMOTE_BIN, buf)
    sftp.close()
    s.close()
    print(f"[deploy] binary {buf.getbuffer().nbytes} bytes")

    cl = conn(CLIENT)
    sf = cl.open_sftp()
    buf.seek(0)
    sf.putfo(buf, INSTALL_BIN)
    sf.close()
    run(cl, f"chmod 755 {INSTALL_BIN}")
    run(cl, "mkdir -p /etc/qeli")
    put_text(cl, "/etc/qeli/pass.txt", PASSWORD + "\n")
    cl.close()
    print("[deploy] done on both VMs")


def down():
    for h in (SERVER, CLIENT):
        c = conn(h)
        run(c, "pkill -9 -f 'qeli (server|client)' 2>/dev/null; pkill -9 iperf3 2>/dev/null; true")
        c.close()
    print("[down] stopped qeli/iperf3 on both")


def start_server():
    s = conn(SERVER)
    run(s, "pkill -9 -f 'qeli server' 2>/dev/null; sleep 1; true")
    run(s, f"RUST_LOG=info nohup {INSTALL_BIN} server --config /etc/qeli/server.json "
           f"> /tmp/qeli-server.log 2>&1 & echo started")
    time.sleep(3)
    rc, out, _ = run(s, "tail -n 8 /tmp/qeli-server.log; echo '---'; ip -o -4 addr show | grep -E 'vpn0|vpn1' || echo NO_TUN")
    print("[server]\n" + out)
    s.close()


def start_client(proto, dns_mode="off"):
    cl = conn(CLIENT)
    run(cl, "pkill -9 -f 'qeli client' 2>/dev/null; sleep 1; true")
    put_text(cl, "/etc/qeli/client.json", client_config(proto, dns_mode))
    run(cl, f"RUST_LOG=info nohup {INSTALL_BIN} client --config /etc/qeli/client.json "
            f"> /tmp/qeli-client.log 2>&1 & echo started")
    time.sleep(5)
    rc, out, _ = run(cl, "tail -n 12 /tmp/qeli-client.log")
    print(f"[client {proto}]\n" + out)
    cl.close()


def iperf(proto):
    p = PROFILES[proto]
    sip = f"{p['tun_net']}.1"
    s = conn(SERVER)
    run(s, f"pkill -9 iperf3 2>/dev/null; sleep 1; nohup iperf3 -s -B {sip} > /tmp/iperf-s.log 2>&1 & echo ok")
    time.sleep(1)
    cl = conn(CLIENT)
    # connectivity first
    rc, ping, _ = run(cl, f"ping -c 3 -W 2 {sip}")
    print(f"[ping {sip}]\n{ping}")

    results = {}
    udp_flag = "-u -b 0 -l 1200" if proto == "udp" else ""
    for label, extra in [("upload", ""), ("download", "-R")]:
        rc, out, err = run(cl, f"iperf3 -c {sip} -t 12 -i 0 {udp_flag} {extra} --json", timeout=60)
        try:
            j = json.loads(out)
            end = j["end"]
            if proto == "udp":
                s_ = end["sum"]
                results[label] = {"mbps": s_["bits_per_second"] / 1e6,
                                  "lost_pct": s_.get("lost_percent"), "jitter_ms": s_.get("jitter_ms")}
            else:
                results[label] = {
                    "mbps": end["sum_received"]["bits_per_second"] / 1e6,
                    "retransmits": end["sum_sent"].get("retransmits"),
                    "cpu_local": round(end["cpu_utilization_percent"]["host_total"], 1),
                    "cpu_remote": round(end["cpu_utilization_percent"]["remote_total"], 1),
                }
        except Exception as e:
            results[label] = {"error": str(e), "raw": out[:300] + err[:300]}
    run(s, "pkill -9 iperf3 2>/dev/null; true")
    s.close(); cl.close()
    print(f"\n===== RESULT [{proto}] =====")
    print(json.dumps(results, indent=2))


def dnstest():
    # connect with dns mode=tunnel, snapshot resolv.conf, kill client (SIGTERM),
    # confirm it is restored.
    cl = conn(CLIENT)
    before = run(cl, "readlink -f /etc/resolv.conf; echo '==='; cat /etc/resolv.conf")[1]
    cl.close()
    start_client("tcp", dns_mode="tunnel")
    cl = conn(CLIENT)
    during = run(cl, "cat /etc/resolv.conf; echo '==='; ls -la /var/lib/qeli/")[1]
    print("[during tunnel]\n" + during)
    run(cl, "pkill -TERM -f 'qeli client'; sleep 2; true")
    after = run(cl, "cat /etc/resolv.conf")[1]
    cl.close()
    print("[before]\n" + before)
    print("[after SIGTERM]\n" + after)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "deploy"
    if cmd == "deploy":
        deploy()
    elif cmd == "down":
        down()
    elif cmd in ("tcp", "udp", "obfs"):
        start_server()
        start_client(cmd)
        iperf(cmd)
    elif cmd == "dnstest":
        start_server()
        dnstest()
    else:
        print(__doc__)
