import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Create a small Rust program to generate argon2 hash
print("=== Creating hash generator ===")
hash_code = '''
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};

fn main() {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(b"admin", &salt).unwrap();
    println!("{}", hash);
}
'''

stdin, stdout, stderr = ssh.exec_command(f"cat > /tmp/gen_hash.rs << 'EOF'\n{hash_code}\nEOF")
stdout.channel.recv_exit_status()

# Try to compile and run
print("\n=== Compiling hash generator ===")
stdin, stdout, stderr = ssh.exec_command("cd /tmp && rustc gen_hash.rs --edition 2021 -L /root/vpn_project/target/release/deps --extern argon2=/root/vpn_project/target/release/deps/libargon2-*.rlib 2>&1 | head -20")
print(stdout.read().decode(errors='replace'))

# Alternative: use the vpn-obfuscated binary itself if it has a hash command
print("\n=== Check if vpn-obfuscated has hash command ===")
stdin, stdout, stderr = ssh.exec_command("/usr/bin/vpn-obfuscated --help 2>&1")
print(stdout.read().decode(errors='replace'))

ssh.close()
