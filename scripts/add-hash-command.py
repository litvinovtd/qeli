import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Add a hash generation subcommand to the project
print("=== Adding hash gen command ===")

# Read main.rs
stdin, stdout, stderr = ssh.exec_command("cat /root/vpn_project/src/main.rs")
content = stdout.read().decode(errors='replace')

# Add hash command before the main match
old_main = """    match args.command {
        Command::Server { config } => {"""

new_main = """    match args.command {
        Command::GenHash { password } => {
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
        Command::Server { config } => {"""

if old_main in content:
    content = content.replace(old_main, new_main)
    print("Patched main.rs")
else:
    print("ERROR: Could not find patch point")
    print(content[:500])

# Check Command enum
print("\n=== Checking Command enum ===")
stdin, stdout, stderr = ssh.exec_command("grep -A 20 'enum Command' /root/vpn_project/src/main.rs")
print(stdout.read().decode(errors='replace'))

ssh.close()
