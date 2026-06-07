"""Hit iperf3 against the *currently running* tunnel, do NOT restart qeli.
Watch what happens in real time."""
import os
import paramiko, time, sys

def ssh(ip):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username="root", password=os.environ.get("QELI_LAB_PASS", ""), timeout=10,
              allow_agent=False, look_for_keys=False); return c

srv, cli = ssh("10.66.116.10"), ssh("10.66.116.11")

def run(h, cmd, t=30):
    _, o, _ = h.exec_command(cmd, timeout=t); o.channel.set_combine_stderr(True)
    return o.read().decode(errors='replace').rstrip(), o.channel.recv_exit_status()

print("=== state check ===")
print(run(srv, "systemctl is-active qeli; ip -br a show vpn0")[0])
print(run(cli, "systemctl is-active qeli; ip -br a show vpn0")[0])

print("\n=== ping warmup (3 packets) ===")
print(run(cli, "ping -c 3 -W 1 10.8.0.1")[0])

print("\n=== start iperf3 -s on server ===")
run(srv, "pkill -9 iperf3 2>/dev/null; sleep 0.5; setsid iperf3 -s -1 </dev/null >/tmp/iperf.log 2>&1 &")
time.sleep(1)
print(run(srv, "ss -tlnp | grep 5201")[0])

print("\n=== iperf3 -c 10.8.0.1 -t 8 -i 1 (live) ===")
out, _ = run(cli, "iperf3 -c 10.8.0.1 -t 8 -i 1 2>&1", t=30)
for line in out.splitlines():
    print(f"  {line}")

print("\n=== qeli client log (last 20) ===")
print(run(cli, "journalctl -u qeli -n 20 --no-pager | tail -20")[0])
print("\n=== qeli server log (last 20) ===")
print(run(srv, "journalctl -u qeli -n 20 --no-pager | tail -20")[0])

srv.close(); cli.close()
