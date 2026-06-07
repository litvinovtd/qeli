"""Quick post-fix e2e: install the freshly built binary and run a 3-mode
sanity sweep (tcp-plain, tcp-obfs, udp-plain). Exercises the data-plane paths
touched by the hardening pass (client try_send on TCP+UDP, DNS off, no DHCP).
Not a full benchmark — just confirms the tunnel still passes traffic cleanly.
"""
import sys, io, json, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import benchmark as B

def main():
    s = B.conn(B.SERVER); cl = B.conn(B.CLIENT)
    B.out(s, f"install -m755 {B.SRC_BIN} {B.BIN}")
    sf = s.open_sftp(); buf = io.BytesIO(); sf.getfo(B.SRC_BIN, buf); sf.close()
    cf = cl.open_sftp(); buf.seek(0); cf.putfo(buf, B.BIN); cf.close()
    B.out(cl, f"chmod 755 {B.BIN}; mkdir -p /etc/qeli"); B.out(s, "mkdir -p /etc/qeli")
    print("binary:", B.out(s, f"{B.BIN} --version 2>&1"),
          B.out(s, f"sha256sum {B.BIN} | cut -c1-16"))
    # Schema matches benchmark.run_mode (client_mode/server_mode, not the old `mode`).
    modes = [
        {"name": "tcp-faketls", "transport": "tcp", "port": 443,  "client_mode": "fake-tls", "server_mode": "fake-tls"},
        {"name": "tcp-obfs",    "transport": "tcp", "port": 443,  "client_mode": "obfs",     "server_mode": "obfs", "obfs_key": "benchkey", "padding": True},
        {"name": "udp-faketls", "transport": "udp", "port": 4443, "client_mode": "fake-tls", "server_mode": "fake-tls"},
    ]
    res = {}
    for m in modes:
        res[m["name"]] = B.run_mode(s, cl, m)
    B.out(cl, "ip link del vpn0 2>/dev/null; ip link del vpn1 2>/dev/null; printf 'nameserver 1.1.1.1\\n'>/etc/resolv.conf")
    s.close(); cl.close()
    print("\n===== SANITY SUMMARY =====")
    print(json.dumps(res, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
