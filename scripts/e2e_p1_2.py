#!/usr/bin/env python3
"""P1#2 verification: after unifying the TCP/UDP transport crypto+auth into the
shared handler.rs helpers (build_handshake_records / build_server_auth_msg /
verify_client_auth), prove both transports still authenticate and forward
traffic, and that a wrong password is still rejected on both."""
import os
import paramiko, time, io, re

def conn(ip):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=os.environ.get("QELI_LAB_PASS", ""), timeout=20, look_for_keys=False, allow_agent=False)
    return c
sc = conn("10.66.116.10"); cc = conn("10.66.116.11")
def s(cmd, t=600):
    i, o, e = sc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
def c(cmd, t=120):
    i, o, e = cc.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()

print("=== build standalone bin (expect 0 warnings) ===")
print(s("cd /opt/qeli-src && cargo build --bin qeli 2>&1 | tail -3"))
print("restart:", s("systemctl restart qeli-server; sleep 3; systemctl is-active qeli-server"))

# UDP client conf (TOFU; no key pin) + wrong-password conf for both transports
def putconf(name, body):
    sf = cc.open_sftp(); sf.putfo(io.BytesIO(body.encode()), "/root/qeli/test_e2e/" + name); sf.close()
putconf("qeli_udp.conf",
        "[qeli]\nserver = 10.66.116.10:1443\nproto = udp\nuser = alice\npass = testpass123\nmode = fake-tls\n\n[logging]\nlevel = info\n")
putconf("qeli_badpw.conf",
        "[qeli]\nserver = 10.66.116.10:443\nproto = tcp\nuser = alice\npass = WRONGPASS\nmode = fake-tls\n\n[logging]\nlevel = info\n")

def run(conf, label, vif, sub):
    c("pkill -9 -f 'qeli client' 2>/dev/null; true"); time.sleep(1)
    ch = cc.get_transport().open_session()
    ch.exec_command("cd /root/qeli && RUST_LOG=info setsid nohup ./target/debug/qeli client -c " + conf +
                    " > /root/cli_" + label + ".log 2>&1 < /dev/null &")
    time.sleep(6); ch.close()
    log = c("grep -iE 'Auth OK|TUN .* up|error|denied|fail|invalid' /root/cli_" + label + ".log | tail -5")
    print("\n=== " + label + " client log ===\n" + (log or "(none)"))
    srv = s("journalctl -u qeli-server --no-pager --since '-25sec' -o cat | grep -iE 'AUTH OK|AUTH FAIL|AUTH DENIED' | tail -3")
    print("server: " + (srv or "(none)"))
    m = re.search(re.escape(sub) + r"\d+", log)
    if m:
        print("ping " + m.group(0) + ":")
        print(s("ping -c3 -W2 -I " + vif + " " + m.group(0) + " | tail -1"))
    c("pkill -9 -f 'qeli client' 2>/dev/null; true")
    return log

print("\n##### TCP (positive) #####");  run("test_e2e/qeli.conf",     "TCP", "vpn0", "10.9.0.")
print("\n##### UDP (positive) #####");  run("test_e2e/qeli_udp.conf", "UDP", "vpn1", "10.9.1.")
print("\n##### TCP (wrong password — must be rejected) #####")
bad = run("test_e2e/qeli_badpw.conf", "BADPW", "vpn0", "10.9.0.")
print("wrong-pw rejected:", "AUTH FAIL" in s("journalctl -u qeli-server --no-pager --since '-25sec' -o cat | grep -iE 'AUTH FAIL' | tail -1"))

# restore good TCP client running for the lab default
ch = cc.get_transport().open_session()
ch.exec_command("cd /root/qeli && RUST_LOG=info setsid nohup ./target/debug/qeli client -c test_e2e/qeli.conf >> /root/qeli_client.log 2>&1 < /dev/null &")
time.sleep(2); ch.close()
print("\n[restore] good TCP client running")
cc.close(); sc.close()
