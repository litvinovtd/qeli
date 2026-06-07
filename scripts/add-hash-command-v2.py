import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Read main.rs
print("=== Reading main.rs ===")
stdin, stdout, stderr = ssh.exec_command("cat /root/vpn_project/src/main.rs")
content = stdout.read().decode(errors='replace')

# Add GenHash to Commands enum
old_enum = """    /// Run in client mode
    Client {
        #[arg(short, long, default_value = "/etc/vpn-obfuscated/client.json")]
        config: PathBuf,
    },
}"""

new_enum = """    /// Run in client mode
    Client {
        #[arg(short, long, default_value = "/etc/vpn-obfuscated/client.json")]
        config: PathBuf,
    },
    /// Generate argon2id password hash
    GenHash {
        #[arg(short, long)]
        password: String,
    },
}"""

if old_enum in content:
    content = content.replace(old_enum, new_enum)
    print("Patched Commands enum")
else:
    print("ERROR: Could not find Commands enum")

# Add match arm
old_match = """    match cli.command {
        Commands::Server { config } => {"""

new_match = """    match cli.command {
        Commands::GenHash { password } => {
            use argon2::{
                password_hash::{rand_core::OsRng, SaltString, PasswordHasher},
                Argon2
            };
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();
            println!("{}", hash);
            return Ok(());
        }
        Commands::Server { config } => {"""

if old_match in content:
    content = content.replace(old_match, new_match)
    print("Patched match")
else:
    print("ERROR: Could not find match")
    # Show what we have
    import re
    match = re.search(r'match cli\.command \{[^}]+\}', content, re.DOTALL)
    if match:
        print(f"Found: {match.group()[:200]}")

# Write back
stdin, stdout, stderr = ssh.exec_command("cat > /root/vpn_project/src/main.rs")
stdin.write(content)
stdin.channel.shutdown_write()
exit_code = stdout.channel.recv_exit_status()
print(f"Write exit code: {exit_code}")

# Rebuild
print("\n=== Rebuilding ===")
stdin, stdout, stderr = ssh.exec_command("cd /root/vpn_project && cargo build --release 2>&1 | grep -E 'Compiling|Finished|error'")
print(stdout.read().decode(errors='replace'))

# Generate hash
print("\n=== Generating hash ===")
stdin, stdout, stderr = ssh.exec_command("/root/vpn_project/target/release/vpn-obfuscated gen-hash --password admin")
new_hash = stdout.read().decode(errors='replace').strip()
print(new_hash)

# Update users.json
if new_hash and '$argon2id' in new_hash:
    print("\n=== Updating users.json ===")
    stdin, stdout, stderr = ssh.exec_command("cat /etc/vpn-obfuscated/users.json")
    users_content = stdout.read().decode(errors='replace')
    
    import re
    users_content = re.sub(r'"password_hash":\s*"[^"]+"', f'"password_hash": "{new_hash}"', users_content)
    
    stdin, stdout, stderr = ssh.exec_command("cat > /etc/vpn-obfuscated/users.json")
    stdin.write(users_content)
    stdin.channel.shutdown_write()
    
    stdin, stdout, stderr = ssh.exec_command("grep password_hash /etc/vpn-obfuscated/users.json")
    print(stdout.read().decode(errors='replace'))
    
    # Install new binary
    print("\n=== Installing ===")
    stdin, stdout, stderr = ssh.exec_command("""
rm -f /usr/bin/vpn-obfuscated
cp /root/vpn_project/target/release/vpn-obfuscated /usr/bin/vpn-obfuscated
chmod +x /usr/bin/vpn-obfuscated
systemctl restart vpn-obfuscated
""")
    stdout.channel.recv_exit_status()
    
    import time
    time.sleep(2)
    
    # Test
    print("\n=== Testing ===")
    ssh2 = paramiko.SSHClient()
    ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)
    
    stdin2, stdout2, stderr2 = ssh2.exec_command("systemctl stop vpn-obfuscated; sleep 1")
    stdout2.channel.recv_exit_status()
    
    stdin2, stdout2, stderr2 = ssh2.exec_command("timeout 15 /usr/bin/vpn-obfuscated client --config /etc/vpn-obfuscated/client.json 2>&1")
    start_time = time.time()
    while time.time() - start_time < 20:
        if stdout2.channel.recv_ready():
            chunk = stdout2.channel.recv(4096).decode(errors='replace')
            print(chunk, end='')
        if stderr2.channel.recv_ready():
            chunk = stderr2.channel.recv(4096).decode(errors='replace')
            print(chunk, end='')
        if stdout2.channel.exit_status_ready():
            break
        time.sleep(0.5)
    
    ssh2.close()
else:
    print("ERROR: Could not generate hash")

ssh.close()
