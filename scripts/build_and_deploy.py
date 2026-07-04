#!/usr/bin/env python3
"""
Build and Deploy VPN to Servers

OBSOLETE — targets the removed `vpn-obfuscated` binary + JSON config (pre flat-INI);
superseded by install-reality-server.sh. Kept for reference only.
"""
import sys
print("OBSOLETE: build_and_deploy.py targets the removed vpn-obfuscated/JSON layout; "
      "use install-reality-server.sh instead.", file=sys.stderr)
sys.exit(1)
import os

import paramiko
import time
import sys
import json
import io
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

SERVER_IP = "10.66.116.10"
CLIENT_IP = "10.66.116.11"
PASSWORD = os.environ.get("QELI_LAB_PASS", "")
USERNAME = "root"

def connect(ip):
    print(f"\nConnecting to {ip}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=USERNAME, password=PASSWORD, timeout=10)
        print(f"✓ Connected to {ip}")
        return ssh
    except Exception as e:
        print(f"✗ Failed to connect to {ip}: {e}")
        return None

def run_command(ssh, command, timeout=300):
    try:
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        output = stdout.read().decode('utf-8', errors='ignore')
        error = stderr.read().decode('utf-8', errors='ignore')
        return output + error
    except Exception as e:
        return f"Error: {e}"

def build_and_deploy(ip, role):
    print(f"\n{'='*60}")
    print(f"Building and Deploying VPN on {ip} ({role})")
    print(f"{'='*60}")
    
    ssh = connect(ip)
    if not ssh:
        return False
    
    # Install Rust
    print("\n[1/6] Installing Rust...")
    output = run_command(ssh, "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y", timeout=120)
    if "Rust is installed" in output or "already installed" in output:
        print("  ✓ Rust installed")
    else:
        print("  ✓ Rust already installed")
    
    # Source cargo
    print("\n[2/6] Setting up environment...")
    run_command(ssh, "source $HOME/.cargo/env")
    output = run_command(ssh, "source $HOME/.cargo/env && cargo --version")
    print(f"  Cargo version: {output.strip()}")
    
    # Install build dependencies
    print("\n[3/6] Installing build dependencies...")
    output = run_command(ssh, "apt-get update -qq && apt-get install -y -qq build-essential pkg-config libssl-dev", timeout=120)
    print("  ✓ Dependencies installed")
    
    # Create VPN directory
    print("\n[4/6] Setting up VPN directory...")
    run_command(ssh, "mkdir -p /opt/vpn-obfuscated")
    run_command(ssh, "cd /opt/vpn-obfuscated")
    print("  ✓ Directory created")
    
    # Check if source exists
    print("\n[5/6] Checking for VPN source code...")
    output = run_command(ssh, "test -f /opt/vpn-obfuscated/Cargo.toml && echo 'exists' || echo 'missing'")
    
    if 'missing' in output:
        print("  ✗ VPN source code not found at /opt/vpn-obfuscated/")
        print("  Please copy VPN source code to server first:")
        print("    scp -r vpn-obfuscated/* root@{ip}:/opt/vpn-obfuscated/")
        return False
    
    print("  ✓ Source code found")
    
    # Build VPN
    print("\n[6/6] Building VPN (this may take 5-10 minutes)...")
    print("  Building in release mode...")
    output = run_command(ssh, "cd /opt/vpn-obfuscated && source $HOME/.cargo/env && cargo build --release 2>&1 | tail -20", timeout=600)
    
    if "Finished" in output or "Compiling" in output:
        print("  ✓ Build completed")
    else:
        print("  ✗ Build failed")
        print(output)
        return False
    
    # Install binary
    print("\n  Installing binary...")
    output = run_command(ssh, "cp /opt/vpn-obfuscated/target/release/vpn-obfuscated /usr/local/bin/ && chmod +x /usr/local/bin/vpn-obfuscated && echo 'success'")
    
    if 'success' in output:
        print("  ✓ Binary installed to /usr/local/bin/vpn-obfuscated")
    else:
        print("  ✗ Failed to install binary")
        return False
    
    # Verify installation
    print("\n  Verifying installation...")
    output = run_command(ssh, "/usr/local/bin/vpn-obfuscated --help 2>&1 | head -5")
    print(f"  {output.strip()}")
    
    ssh.close()
    print(f"\n✓ VPN successfully built and deployed on {ip}")
    return True

def main():
    print("\n" + "="*60)
    print("VPN BUILD AND DEPLOY")
    print("="*60)
    print(f"Timestamp: {datetime.now()}")
    print(f"Servers: {SERVER_IP}, {CLIENT_IP}")
    print("="*60)
    
    # Build on both servers
    server_ok = build_and_deploy(SERVER_IP, "server")
    client_ok = build_and_deploy(CLIENT_IP, "client")
    
    print("\n" + "="*60)
    print("DEPLOYMENT SUMMARY")
    print("="*60)
    print(f"Server ({SERVER_IP}): {'✓ SUCCESS' if server_ok else '✗ FAILED'}")
    print(f"Client ({CLIENT_IP}): {'✓ SUCCESS' if client_ok else '✗ FAILED'}")
    
    if server_ok and client_ok:
        print("\n✓ VPN built and deployed successfully!")
        print("\nNext steps:")
        print("  1. Run auto_test.py to start VPN and run tests")
        print("  2. Or manually start VPN:")
        print(f"     Server: ssh root@{SERVER_IP} '/usr/local/bin/vpn-obfuscated server -c /etc/vpn-obfuscated/server.json &'")
        print(f"     Client: ssh root@{CLIENT_IP} '/usr/local/bin/vpn-obfuscated client -c /etc/vpn-obfuscated/client.json &'")
    else:
        print("\n✗ Deployment failed")
        print("Please check the errors above")
    
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✗ Interrupted by user")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
