import paramiko
import time

# Create a simple test script on server 11
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

test_script = """
import socket
import struct
import random
import os

def put_u24(buf, val):
    buf.append((val >> 16) & 0xFF)
    buf.append((val >> 8) & 0xFF)
    buf.append(val & 0xFF)

def build_client_hello():
    # Generate random key pair (fake for testing)
    client_pub = os.urandom(32)
    
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)
    
    # Build extensions
    extensions = bytearray()
    
    # SNI extension
    server_name = b"10.66.116.10"
    sni_data = bytearray()
    sni_data.append(0x00)  # hostname type
    sni_data.extend(struct.pack('!H', len(server_name)))
    sni_data.extend(server_name)
    extensions.extend(struct.pack('!HH', 0x0000, len(sni_data)))  # SNI type
    extensions.extend(sni_data)
    
    # Supported groups
    groups_data = struct.pack('!H', 2) + struct.pack('!H', 0x001d) + struct.pack('!H', 0x0017)
    extensions.extend(struct.pack('!HH', 0x000a, len(groups_data)))
    extensions.extend(groups_data)
    
    # Key share extension
    key_share_data = bytearray()
    key_share_data.extend(struct.pack('!H', 36))  # entry length
    key_share_data.extend(struct.pack('!H', 0x001d))  # x25519
    key_share_data.extend(struct.pack('!H', 32))  # 32 bytes
    key_share_data.extend(client_pub)
    extensions.extend(struct.pack('!HH', 0x0033, len(key_share_data)))
    extensions.extend(key_share_data)
    
    # Signature algorithms
    sig_data = struct.pack('!H', 4) + struct.pack('!H', 0x0403) + struct.pack('!H', 0x0804)
    extensions.extend(struct.pack('!HH', 0x000d, len(sig_data)))
    extensions.extend(sig_data)
    
    # Build handshake body
    body = bytearray()
    body.append(0x01)  # ClientHello
    put_u24(body, 0)  # placeholder length
    
    body.extend([0x03, 0x03])  # Protocol version
    body.extend(random_bytes)  # Random
    body.append(0x20)  # Session ID length
    body.extend(session_id)  # Session ID
    
    # Cipher suites
    body.extend(struct.pack('!H', 8))  # 8 bytes = 4 suites
    body.extend([0x13, 0x01])  # TLS_AES_128_GCM_SHA256
    body.extend([0x13, 0x02])  # TLS_AES_256_GCM_SHA384
    body.extend([0x13, 0x03])  # TLS_CHACHA20_POLY1305_SHA256
    body.extend([0xcc, 0xa9])  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    
    # Compression
    body.append(0x01)  # 1 compression method
    body.append(0x00)  # null
    
    # Extensions
    body.extend(struct.pack('!H', len(extensions)))
    body.extend(extensions)
    
    # Fill in body length
    body_len = len(body) - 4
    body[1] = (body_len >> 16) & 0xFF
    body[2] = (body_len >> 8) & 0xFF
    body[3] = body_len & 0xFF
    
    # Wrap in TLS record
    record = bytearray()
    record.append(0x16)  # Handshake
    record.extend([0x03, 0x03])  # TLS 1.2
    record.extend(struct.pack('!H', len(body)))
    record.extend(body)
    
    return bytes(record)

# Connect and send
print("Connecting to 10.66.116.10:443...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)
sock.connect(('10.66.116.10', 443))

client_hello = build_client_hello()
print(f"Sending ClientHello: {len(client_hello)} bytes")
sock.sendall(client_hello)

# Wait for response
print("Waiting for response...")
response = sock.recv(4096)
print(f"Received: {len(response)} bytes")
print(f"First 50 bytes: {response[:50].hex()}")

sock.close()
"""

# Write script
stdin, stdout, stderr = ssh.exec_command("cat > /tmp/test_handshake.py")
stdin.write(test_script)
stdin.channel.shutdown_write()
stdout.channel.recv_exit_status()

# Run script
print("=== Running handshake test ===")
stdin, stdout, stderr = ssh.exec_command("python3 /tmp/test_handshake.py 2>&1")
output = stdout.read().decode(errors='replace')
print(output)

# Check server logs
print("\n=== Server logs ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=10)

stdin2, stdout2, stderr2 = ssh2.exec_command("journalctl -u vpn-obfuscated --no-pager -n 10 --since '22:31:00'")
print(stdout2.read().decode(errors='replace'))

ssh.close()
ssh2.close()
