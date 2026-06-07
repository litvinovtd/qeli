"""
Fully wipe qeli state on both lab VMs and install only what we control.

Steps per host:
  1. systemctl stop qeli, disable
  2. pkill -9 any leftover qeli/iperf3
  3. rm -rf /etc/qeli /var/lib/qeli /var/log/qeli /var/run/qeli
  4. rm -f /usr/bin/qeli /usr/bin/qeli.* (drops .prev .audit etc.)
  5. upload fresh binary -> /usr/bin/qeli
  6. mkdir -p the dirs we need
  7. upload server.json / client.json / users.json / password.txt
  8. systemctl daemon-reload, start qeli
  9. verify tunnel up
"""
from __future__ import annotations
import os
import json, sys, time
from pathlib import Path
import paramiko

LOCAL_BIN = Path(r"C:\Users\Administrator\Documents\project\vpn\release\qeli-linux-amd64")
USER, PASS = "root", os.environ.get("QELI_LAB_PASS", "")
SERVER, CLIENT = "10.66.116.10", "10.66.116.11"


def ssh(ip):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username=USER, password=PASS, timeout=10,
              allow_agent=False, look_for_keys=False)
    return c


def run(c, cmd, t=30, quiet=False):
    _, o, _ = c.exec_command(cmd, timeout=t); o.channel.set_combine_stderr(True)
    out = o.read().decode(errors='replace').rstrip()
    rc = o.channel.recv_exit_status()
    if not quiet:
        print(f"  $ {cmd[:75]}")
        for line in out.splitlines()[:8]:
            print(f"    {line}")
    return rc, out


def put(c, path, content):
    sftp = c.open_sftp()
    with sftp.open(path, "w") as f: f.write(content)
    sftp.close()


def put_file(c, local, remote, mode=0o755):
    sftp = c.open_sftp()
    sftp.put(str(local), remote)
    sftp.chmod(remote, mode)
    sftp.close()


# ── configs ────────────────────────────────────────────────────────────────

USERS_JSON = {
    "users": [{
        "username": "admin",
        # Argon2id of "qelibench" with the salt 'vpn-salt-2026'
        "password_hash":
            "$argon2id$v=19$m=16384,t=2,p=1$dnBuLXNhbHQtMjAyNg$WfCLTjeX2bGS5gga0u2T0hRW3lePv1GfuNZbQzkgRak",
        "static_ip": "10.8.0.10",
        "enabled": True,
        "bandwidth": {"limit_mbps": 0, "burst_mbps": 0},
        "allowed_networks": [], "group": None, "metadata": {},
        "routes": [], "max_sessions": 0,
    }],
    "groups": {},
}

SERVER_JSON = {
    "auth": {"brute_force": {"lockout_secs": 60, "max_attempts": 100, "window_secs": 60},
             "password_hash": "argon2id", "token_ttl_secs": 86400,
             "users_file": "/etc/qeli/users.json"},
    "logging": {"file": "/var/log/qeli/server.log", "format": "plain", "level": "info",
                "rotation": {"compress": True, "max_files": 7, "max_size_mb": 100}},
    "web": {"enabled": False, "bind": "127.0.0.1", "port": 8080,
            "username": "admin", "password_hash": ""},
    "profiles": [{
        "name": "bench-tcp",
        "bind": {"address": "0.0.0.0", "port": 443, "transport": "tcp"},
        "tun": {"address": "10.8.0.1", "device_type": "tun", "mtu": 1380,
                "name": "vpn0", "netmask": "255.255.255.0", "tx_queue_len": 1000},
        "pool": {"cidr": "10.8.0.0/24", "exclude": ["10.8.0.1"],
                 "lease_time_secs": 3600, "static_reservations": {}},
        "routing": {"advertised_routes": [], "client_to_client": True,
                    "forward_private": True,
                    "nat": {"enabled": False, "interface": "ens18"}},
        "dns": {"blocklist": [], "cache_size": 1000, "enabled": False,
                "listen": "10.8.0.1", "port": 53, "timeout_secs": 5,
                "upstream": ["1.1.1.1"], "upstream_protocol": "udp"},
        "dhcp": {"enabled": False, "listen": "0.0.0.0",
                 "lease_time_secs": 3600, "domain_name": ""},
        "obfuscation": {
            "anti_fingerprinting": {"add_jitter_to_handshake": False,
                                    "enabled": False, "rotate_ciphers_every": 300},
            "cipher": "chacha20-poly1305",
            "fragmentation": {"enabled": False, "max_chunk_size": 512,
                              "max_fragments_per_packet": 16, "min_chunk_size": 64},
            "heartbeat": {"data_size_bytes": 16, "enabled": False,
                          "interval_ms": 5000, "jitter_ms": 200},
            "http2_masking": {"enabled": False, "ratio": 0.1},
            "padding": {"enabled": False, "max_bytes": 256, "min_bytes": 32,
                        "probability": 0.5, "randomize": True},
            "quic": {"cid_length": 4, "enabled": False, "version": 1},
            "tls": {"key_share_entropy_bytes": 32,
                    "reality_proxy": {"enabled": False, "target": "www.cloudflare.com",
                                      "target_port": 443},
                    "server_name": "www.cloudflare.com", "session_id": True,
                    "supported_groups": ["x25519", "secp256r1"]},
            "traffic_normalization": {"enabled": False, "randomize_sequence": False,
                                       "round_sizes": []},
        },
        "performance": {
            "connection": {"handshake_timeout_secs": 10, "idle_timeout_secs": 600,
                           "max_clients": 16, "rate_limit_packets_per_sec": 1000000},
            "tcp": {"keepalive_secs": 60, "nodelay": True,
                    "recv_buffer_size": 4194304, "send_buffer_size": 4194304},
            "tun": {"max_pending_packets": 1024, "read_buffer_size": 65535,
                    "read_timeout_ms": 5, "write_buffer_size": 65535},
        },
    }],
}

CLIENT_JSON = {
    "server": {"address": SERVER, "port": 443, "protocol": "tcp",
               "connection_timeout_secs": 10, "tcp_keepalive_secs": 60,
               "reconnect": {"enabled": False, "max_retries": 0,
                             "base_delay_secs": 1, "max_delay_secs": 5}},
    "auth": {"username": "admin", "password_file": "/etc/qeli/password.txt"},
    "tun": {"name": "vpn0", "mtu": 1380, "device_type": "tun"},
    "routing": {"mode": "split-tunnel", "bypass_local": True,
                "bypass_private": False, "include": [], "exclude": [],
                "custom_routes": []},
    "dns": {"mode": "off", "servers": [], "fallback_servers": [],
            "search_domains": [], "redirect_all": False, "timeout_secs": 5},
    "obfuscation": {
        "cipher": "chacha20-poly1305",
        "padding": {"enabled": False, "min_bytes": 32, "max_bytes": 256,
                    "probability": 0.5, "randomize": True},
        "heartbeat": {"enabled": False, "interval_ms": 5000, "jitter_ms": 200,
                      "data_size_bytes": 16},
        "fragmentation": {"enabled": False, "min_chunk_size": 64,
                          "max_chunk_size": 512, "max_fragments_per_packet": 16},
        "quic": {"enabled": False, "cid_length": 4, "version": 1},
        "traffic_normalization": {"enabled": False, "randomize_sequence": False,
                                  "round_sizes": []},
    },
    "performance": {"tcp_nodelay": True, "send_buffer_size": 4194304,
                    "recv_buffer_size": 4194304, "tun_buffer_size": 65535,
                    "idle_timeout_secs": 600},
    "logging": {"level": "info", "file": "/var/log/qeli/client.log", "format": "plain"},
}

SERVER_SYSTEMD = """\
[Unit]
Description=Qeli VPN Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/qeli server --config /etc/qeli/server.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
"""

CLIENT_SYSTEMD = """\
[Unit]
Description=Qeli VPN Client
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/qeli client --config /etc/qeli/client.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
"""


# ── orchestrate ────────────────────────────────────────────────────────────

def wipe_and_install(c, role: str):
    print(f"\n=== {role} wipe ===")
    run(c, "systemctl stop qeli 2>/dev/null; systemctl disable qeli 2>/dev/null || true")
    run(c, "pkill -9 -f qeli 2>/dev/null; pkill -9 -f iperf3 2>/dev/null; sleep 1; true")
    run(c, "ip link del vpn0 2>/dev/null || true; ip link del vpn1 2>/dev/null || true")
    run(c, "rm -rf /etc/qeli /var/lib/qeli /var/log/qeli /var/run/qeli")
    run(c, "rm -f /usr/bin/qeli /usr/bin/qeli.prev /usr/bin/qeli.audit /usr/bin/qeli.new /usr/bin/qeli.old")
    run(c, "ls /usr/bin/qeli* 2>/dev/null || echo no-qeli-binaries-left")

    print(f"\n=== {role} install ===")
    put_file(c, LOCAL_BIN, "/usr/bin/qeli", mode=0o755)
    run(c, "sha256sum /usr/bin/qeli")
    run(c, "mkdir -p /etc/qeli /var/lib/qeli /var/log/qeli /var/run/qeli && chmod 700 /var/lib/qeli")
    if role == "server":
        put(c, "/etc/qeli/server.json", json.dumps(SERVER_JSON, indent=2))
        put(c, "/etc/qeli/users.json", json.dumps(USERS_JSON, indent=2))
        put(c, "/etc/systemd/system/qeli.service", SERVER_SYSTEMD)
    else:
        put(c, "/etc/qeli/client.json", json.dumps(CLIENT_JSON, indent=2))
        put(c, "/etc/qeli/password.txt", "qelibench")
        put(c, "/etc/systemd/system/qeli.service", CLIENT_SYSTEMD)
    run(c, "chmod 600 /etc/qeli/*.json /etc/qeli/password.txt 2>/dev/null; ls -la /etc/qeli/")
    run(c, "systemctl daemon-reload")


def main():
    srv, cli = ssh(SERVER), ssh(CLIENT)
    try:
        wipe_and_install(srv, "server")
        wipe_and_install(cli, "client")

        print("\n=== start server ===")
        run(srv, "systemctl start qeli; sleep 2; systemctl is-active qeli")
        run(srv, "journalctl -u qeli -n 15 --no-pager | tail -10")

        print("\n=== start client ===")
        run(cli, "systemctl start qeli; sleep 3; systemctl is-active qeli")
        run(cli, "journalctl -u qeli -n 20 --no-pager | tail -15")

        print("\n=== verify tunnel ===")
        run(cli, "ip -br a show vpn0; ping -c 5 -i 0.3 10.8.0.1")

        print("\n=== wait 15s, then re-check that the tunnel survived ===")
        time.sleep(15)
        run(cli, "ip -br a show vpn0 2>/dev/null || echo vpn0-gone; ping -c 3 -W 1 10.8.0.1")
        run(cli, "journalctl -u qeli -n 15 --no-pager | tail -10")
    finally:
        srv.close(); cli.close()


if __name__ == "__main__":
    main()
