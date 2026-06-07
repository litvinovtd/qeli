#!/usr/bin/env python3
"""
VPN Auto-Fix and Test Script
Automatically connects to servers, fixes VPN, and runs tests
"""
import os

import paramiko
import time
import sys
import json
from datetime import datetime

# Fix encoding for Windows
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Configuration
SERVER_IP = "10.66.116.10"
CLIENT_IP = "10.66.116.11"
PASSWORD = os.environ.get("QELI_LAB_PASS", "")
USERNAME = "root"

class VPNTester:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "servers": {},
            "tests": {},
            "summary": {}
        }
    
    def connect(self, ip):
        """Connect to server via SSH"""
        print(f"\n{'='*60}")
        print(f"Connecting to {ip}...")
        print(f"{'='*60}")
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(ip, username=USERNAME, password=PASSWORD, timeout=10)
            print(f"✓ Connected to {ip}")
            return ssh
        except Exception as e:
            print(f"✗ Failed to connect to {ip}: {e}")
            return None
    
    def run_command(self, ssh, command, timeout=30):
        """Run command and return output"""
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            return output + error
        except Exception as e:
            return f"Error: {e}"
    
    def diagnose_server(self, ssh, ip, role):
        """Run diagnostics on server"""
        print(f"\n[DIAGNOSTICS] {ip} ({role})")
        print("-" * 60)
        
        diagnostics = {}
        
        # Check VPN process
        print("  Checking VPN process...")
        output = self.run_command(ssh, "pgrep -f vpn-obfuscated")
        if output.strip():
            print(f"    ✓ VPN process running (PID: {output.strip()})")
            diagnostics['process'] = 'running'
        else:
            print(f"    ✗ VPN process NOT running")
            diagnostics['process'] = 'stopped'
        
        # Check TUN interface
        print("  Checking TUN interface...")
        output = self.run_command(ssh, "ip link show | grep vpn0")
        if output.strip():
            print(f"    ✓ TUN interface vpn0 exists")
            diagnostics['tun'] = 'up'
            
            # Get IP
            output = self.run_command(ssh, "ip addr show vpn0 | grep inet")
            if output.strip():
                ip_addr = output.strip().split()[1]
                print(f"    ✓ IP: {ip_addr}")
                diagnostics['ip'] = ip_addr
        else:
            print(f"    ✗ TUN interface NOT found")
            diagnostics['tun'] = 'down'
        
        # Check logs
        print("  Checking recent logs...")
        log_file = f"/var/log/vpn-obfuscated/{role}.log"
        output = self.run_command(ssh, f"tail -10 {log_file} 2>/dev/null || echo 'No logs'")
        print(f"    Last logs:")
        for line in output.strip().split('\n')[-5:]:
            print(f"      {line}")
        diagnostics['logs'] = output
        
        # Check config
        print("  Checking configuration...")
        config_file = f"/etc/vpn-obfuscated/{role}.json"
        output = self.run_command(ssh, f"test -f {config_file} && echo 'exists' || echo 'missing'")
        if 'exists' in output:
            print(f"    ✓ Config file exists")
            diagnostics['config'] = 'exists'
        else:
            print(f"    ✗ Config file missing")
            diagnostics['config'] = 'missing'
        
        return diagnostics
    
    def fix_vpn(self, ssh, ip, role):
        """Fix VPN on server"""
        print(f"\n[FIXING VPN] {ip} ({role})")
        print("-" * 60)
        
        # Stop old processes
        print("  Stopping old VPN processes...")
        self.run_command(ssh, "pkill -9 vpn-obfuscated || true")
        self.run_command(ssh, "systemctl stop vpn-obfuscated || true")
        time.sleep(2)
        print("    ✓ Old processes stopped")
        
        # Create config directory
        print("  Creating config directory...")
        self.run_command(ssh, "mkdir -p /etc/vpn-obfuscated")
        self.run_command(ssh, "mkdir -p /var/log/vpn-obfuscated")
        self.run_command(ssh, "mkdir -p /var/lib/vpn-obfuscated")
        print("    ✓ Directories created")
        
        # Create configuration
        print("  Creating configuration...")
        if role == "server":
            config = {
                "bind": {"address": "0.0.0.0", "port": 443},
                "tun": {
                    "name": "vpn0",
                    "address": "10.8.0.1",
                    "netmask": "255.255.255.0",
                    "mtu": 1500,
                    "tx_queue_len": 1000
                },
                "auth": {
                    "users_file": "/etc/vpn-obfuscated/users.json",
                    "password_hash": "argon2id",
                    "token_ttl_secs": 86400
                },
                "pool": {
                    "cidr": "10.8.0.0/24",
                    "exclude": ["10.8.0.1"],
                    "lease_time_secs": 3600,
                    "static_reservations": {"admin": "10.8.0.10"}
                },
                "routing": {
                    "client_to_client": True,
                    "nat": {"enabled": True, "interface": "eth0"},
                    "forward_private": True
                },
                "dns": {"enabled": False},
                "obfuscation": {
                    "cipher": "chacha20-poly1305",
                    "tls": {
                        "server_name": "www.cloudflare.com",
                        "session_id": True,
                        "supported_groups": ["x25519", "secp256r1"],
                        "key_share_entropy_bytes": 32
                    },
                    "padding": {"enabled": False, "min_bytes": 0, "max_bytes": 0},
                    "fragmentation": {"enabled": False},
                    "heartbeat": {"enabled": False, "interval_ms": 1000, "data_size_bytes": 16, "jitter_ms": 100},
                    "http2_masking": {"enabled": False},
                    "traffic_normalization": {"enabled": False},
                    "anti_fingerprinting": {"enabled": False}
                },
                "performance": {
                    "tcp": {
                        "nodelay": True,
                        "keepalive_secs": 60,
                        "send_buffer_size": 262144,
                        "recv_buffer_size": 262144
                    },
                    "tun": {
                        "read_buffer_size": 65535,
                        "write_buffer_size": 65535,
                        "read_timeout_ms": 10,
                        "max_pending_packets": 256
                    },
                    "connection": {
                        "max_clients": 128,
                        "handshake_timeout_secs": 10,
                        "idle_timeout_secs": 300,
                        "rate_limit_packets_per_sec": 10000
                    }
                },
                "logging": {
                    "level": "info",
                    "file": "/var/log/vpn-obfuscated/server.log",
                    "format": "plain"
                }
            }
            
            users_config = {
                "users": [{
                    "username": "admin",
                    "password_hash": "$argon2id$v=19$m=16384,t=2,p=1$dnBuLXNhbHQtMjAyNg$HKitPHloJ24C7g6Vx5nsArVhRBNzSczeYQm8Ij3vFW0",
                    "static_ip": "10.8.0.10",
                    "enabled": True,
                    "bandwidth": {"limit_mbps": 100, "burst_mbps": 150},
                    "allowed_networks": ["0.0.0.0/0"],
                    "group": "premium"
                }],
                "groups": {
                    "premium": {
                        "bandwidth_limit_mbps": 100,
                        "max_sessions": 3,
                        "allowed_networks": ["0.0.0.0/0"]
                    }
                }
            }
            
            self.run_command(ssh, f"cat > /etc/vpn-obfuscated/server.json << 'EOF'\n{json.dumps(config, indent=2)}\nEOF")
            self.run_command(ssh, f"cat > /etc/vpn-obfuscated/users.json << 'EOF'\n{json.dumps(users_config, indent=2)}\nEOF")
            print("    ✓ Server config created")
        else:
            config = {
                "server": {
                    "address": SERVER_IP,
                    "port": 443,
                    "connection_timeout_secs": 30,
                    "reconnect": {"enabled": True, "max_retries": -1, "base_delay_secs": 1, "max_delay_secs": 60}
                },
                "auth": {
                    "username": "admin",
                    "password_file": "/etc/vpn-obfuscated/password.txt"
                },
                "tun": {"name": "vpn0", "mtu": 1500},
                "routing": {
                    "mode": "split-tunnel",
                    "include": ["10.8.0.0/24"],
                    "exclude": [],
                    "bypass_private": True,
                    "bypass_local": True
                },
                "dns": {
                    "mode": "tunnel",
                    "servers": ["10.8.0.1"],
                    "redirect_all": False,
                    "fallback_servers": ["1.1.1.1", "8.8.8.8"]
                },
                "obfuscation": {
                    "cipher": "chacha20-poly1305",
                    "padding": {"enabled": False, "min_bytes": 0, "max_bytes": 0},
                    "heartbeat": {"enabled": False, "interval_ms": 1000, "data_size_bytes": 16, "jitter_ms": 100},
                    "fragmentation": {"enabled": False}
                },
                "performance": {
                    "tcp_nodelay": True,
                    "send_buffer_size": 262144,
                    "recv_buffer_size": 262144,
                    "tun_buffer_size": 65535
                },
                "logging": {
                    "level": "info",
                    "file": "/var/log/vpn-obfuscated/client.log",
                    "format": "plain"
                }
            }
            
            self.run_command(ssh, f"cat > /etc/vpn-obfuscated/client.json << 'EOF'\n{json.dumps(config, indent=2)}\nEOF")
            self.run_command(ssh, "echo 'testpass123' > /etc/vpn-obfuscated/password.txt && chmod 600 /etc/vpn-obfuscated/password.txt")
            print("    ✓ Client config created")
        
        # Check if binary exists
        print("  Checking VPN binary...")
        output = self.run_command(ssh, "which vpn-obfuscated 2>/dev/null || echo 'not found'")
        
        vpn_binary = None
        if 'not found' not in output and output.strip():
            vpn_binary = output.strip()
            print(f"    ✓ VPN binary found at: {vpn_binary}")
        else:
            # Try to find existing binary
            print("    Binary not in PATH, searching...")
            output = self.run_command(ssh, "find /root /usr /opt -name vpn-obfuscated -type f 2>/dev/null | head -1")
            if output.strip():
                vpn_binary = output.strip().split('\n')[0]
                print(f"    Found at: {vpn_binary}")
                # Install to /usr/local/bin
                self.run_command(ssh, f"cp {vpn_binary} /usr/local/bin/vpn-obfuscated && chmod +x /usr/local/bin/vpn-obfuscated")
                vpn_binary = "/usr/local/bin/vpn-obfuscated"
                print("    ✓ Binary installed to /usr/local/bin/")
            else:
                print("    ✗ VPN binary not found anywhere!")
                print("    Please build and install VPN binary first:")
                print("      cargo build --release")
                print("      cp target/release/vpn-obfuscated /usr/local/bin/")
                return False
        
        # Start VPN
        print("  Starting VPN...")
        if role == "server":
            self.run_command(ssh, f"nohup {vpn_binary} server -c /etc/vpn-obfuscated/server.json > /var/log/vpn-obfuscated/server.log 2>&1 &")
        else:
            self.run_command(ssh, f"nohup {vpn_binary} client -c /etc/vpn-obfuscated/client.json > /var/log/vpn-obfuscated/client.log 2>&1 &")
        
        time.sleep(3)
        
        # Check if started
        output = self.run_command(ssh, "pgrep -f vpn-obfuscated")
        if output.strip():
            print(f"    ✓ VPN started (PID: {output.strip()})")
            return True
        else:
            print("    ✗ VPN failed to start")
            print("    Checking logs...")
            log_output = self.run_command(ssh, f"tail -20 /var/log/vpn-obfuscated/{role}.log")
            print(log_output)
            return False
    
    def run_tests(self, ssh, ip, role):
        """Run performance tests"""
        if role != "client":
            print(f"\n[SKIPPING TESTS] {ip} (server mode)")
            return {}
        
        print(f"\n[RUNNING TESTS] {ip} ({role})")
        print("-" * 60)
        
        tests = {}
        
        # Install tools
        print("  Installing benchmark tools...")
        self.run_command(ssh, "apt-get update -qq && apt-get install -y -qq iperf3 sysstat bc jq", timeout=60)
        print("    ✓ Tools installed")
        
        # Start iperf3 server on server
        print("  Starting iperf3 server on 10.66.116.10...")
        server_ssh = self.connect(SERVER_IP)
        if server_ssh:
            self.run_command(server_ssh, "pkill -9 iperf3 || true")
            self.run_command(server_ssh, "nohup iperf3 -s > /dev/null 2>&1 &")
            time.sleep(2)
            server_ssh.close()
            print("    ✓ iperf3 server started")
        
        # Test 1: Direct connection
        print("  Test 1: Direct connection...")
        output = self.run_command(ssh, "iperf3 -c 10.66.116.10 -t 10 -P 4 -J", timeout=30)
        try:
            data = json.loads(output)
            bandwidth = data['end']['sum_received']['bits_per_second'] / 1000000
            tests['direct_bandwidth'] = f"{bandwidth:.2f} Mbps"
            print(f"    ✓ Direct: {bandwidth:.2f} Mbps")
        except:
            tests['direct_bandwidth'] = 'N/A'
            print("    ✗ Direct test failed")
        
        # Test 2: VPN connection
        print("  Test 2: VPN connection...")
        output = self.run_command(ssh, "iperf3 -c 10.8.0.1 -t 10 -P 4 -J", timeout=30)
        try:
            data = json.loads(output)
            bandwidth = data['end']['sum_received']['bits_per_second'] / 1000000
            tests['vpn_bandwidth'] = f"{bandwidth:.2f} Mbps"
            print(f"    ✓ VPN: {bandwidth:.2f} Mbps")
        except:
            tests['vpn_bandwidth'] = 'N/A'
            print("    ✗ VPN test failed")
        
        # Test 3: Latency
        print("  Test 3: Latency...")
        output = self.run_command(ssh, "ping -c 100 -i 0.01 10.66.116.10 | tail -1")
        try:
            latency = output.split('/')[4]
            tests['direct_latency'] = f"{latency} ms"
            print(f"    ✓ Direct latency: {latency} ms")
        except:
            tests['direct_latency'] = 'N/A'
        
        output = self.run_command(ssh, "ping -c 100 -i 0.01 10.8.0.1 | tail -1")
        try:
            latency = output.split('/')[4]
            tests['vpn_latency'] = f"{latency} ms"
            print(f"    ✓ VPN latency: {latency} ms")
        except:
            tests['vpn_latency'] = 'N/A'
        
        # Test 4: CPU usage
        print("  Test 4: CPU usage...")
        output = self.run_command(ssh, "mpstat 1 5 | tail -1")
        try:
            cpu_idle = float(output.split()[-1])
            cpu_usage = 100 - cpu_idle
            tests['cpu_usage'] = f"{cpu_usage:.1f}%"
            print(f"    ✓ CPU usage: {cpu_usage:.1f}%")
        except:
            tests['cpu_usage'] = 'N/A'
        
        return tests
    
    def run_all(self):
        """Run complete test suite"""
        print("\n" + "="*60)
        print("VPN AUTO-FIX AND TEST SUITE")
        print("="*60)
        print(f"Timestamp: {datetime.now()}")
        print(f"Server: {SERVER_IP}")
        print(f"Client: {CLIENT_IP}")
        print("="*60)
        
        # Connect to servers
        server_ssh = self.connect(SERVER_IP)
        client_ssh = self.connect(CLIENT_IP)
        
        if not server_ssh or not client_ssh:
            print("\n✗ Failed to connect to servers")
            return
        
        # Diagnose
        self.results['servers'][SERVER_IP] = self.diagnose_server(server_ssh, SERVER_IP, "server")
        self.results['servers'][CLIENT_IP] = self.diagnose_server(client_ssh, CLIENT_IP, "client")
        
        # Fix VPN
        print("\n" + "="*60)
        print("FIXING VPN")
        print("="*60)
        
        server_fixed = self.fix_vpn(server_ssh, SERVER_IP, "server")
        time.sleep(2)
        client_fixed = self.fix_vpn(client_ssh, CLIENT_IP, "client")
        
        if not server_fixed or not client_fixed:
            print("\n✗ Failed to fix VPN")
            server_ssh.close()
            client_ssh.close()
            return
        
        # Wait for connection
        print("\n  Waiting for VPN connection to establish...")
        time.sleep(5)
        
        # Test connection
        print("\n  Testing VPN connection...")
        output = self.run_command(client_ssh, "ping -c 3 -W 2 10.8.0.1")
        if "3 received" in output:
            print("    ✓ VPN connection working!")
        else:
            print("    ✗ VPN connection failed")
            print(output)
        
        # Run tests
        self.results['tests'] = self.run_tests(client_ssh, CLIENT_IP, "client")
        
        # Generate summary
        self.results['summary'] = {
            "vpn_status": "UP" if server_fixed and client_fixed else "DOWN",
            "server_ip": SERVER_IP,
            "client_ip": CLIENT_IP,
            "vpn_network": "10.8.0.0/24"
        }
        
        # Close connections
        server_ssh.close()
        client_ssh.close()
        
        # Print final report
        self.print_report()
        
        # Save results
        with open('/tmp/vpn_test_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n✓ Results saved to /tmp/vpn_test_results.json")
    
    def print_report(self):
        """Print final report"""
        print("\n" + "="*60)
        print("FINAL REPORT")
        print("="*60)
        print(f"\nTimestamp: {self.results['timestamp']}")
        print(f"\nVPN Status: {self.results['summary']['vpn_status']}")
        print(f"Server: {self.results['summary']['server_ip']}")
        print(f"Client: {self.results['summary']['client_ip']}")
        print(f"VPN Network: {self.results['summary']['vpn_network']}")
        
        print("\nPerformance Tests:")
        print("-" * 60)
        for key, value in self.results['tests'].items():
            print(f"  {key:.<40} {value}")
        
        print("\n" + "="*60)

if __name__ == "__main__":
    try:
        tester = VPNTester()
        tester.run_all()
    except KeyboardInterrupt:
        print("\n\n✗ Interrupted by user")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
