#!/usr/bin/env python3
"""Verify VPN server is running and healthy."""
import os
import sys
import io
import paramiko

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("YOUR_DEPLOY_HOST", username="root", password=os.environ.get("QELI_DEPLOY_PASS", ""), timeout=15)

def run(cmd, timeout=30):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    return (stdout.read().decode('utf-8', errors='ignore') + stderr.read().decode('utf-8', errors='ignore')).strip()

print("=== Server Health Check ===\n")

# 1. Service status
print("[1] Service status:")
print(run("systemctl is-active qeli"))
print()

# 2. Port listening
print("[2] Port 443 listening:")
print(run("ss -tlnp | grep 443"))
print()

# 3. TUN interface
print("[3] TUN interface:")
print(run("ip addr show vpn0 2>/dev/null || ip addr show | grep -A2 tun"))
print()

# 4. IP forwarding
print("[4] IP forwarding:")
print(run("sysctl net.ipv4.ip_forward"))
print()

# 5. NAT rules
print("[5] NAT rules:")
print(run("iptables -t nat -L POSTROUTING -n | grep 10.10.10"))
print()

# 6. Recent logs
print("[6] Recent server logs:")
print(run("journalctl -u qeli --no-pager -n 15 2>&1"))
print()

# 7. BBR congestion control
print("[7] TCP congestion control:")
print(run("sysctl net.ipv4.tcp_congestion_control"))
print()

# 8. Process check
print("[8] Qeli process:")
print(run("ps aux | grep qeli | grep -v grep"))
print()

ssh.close()
print("=== Check Complete ===")
