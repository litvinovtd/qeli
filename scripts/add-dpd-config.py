import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Read config mod.rs
print("=== Reading config mod.rs ===")
stdin, stdout, stderr = ssh.exec_command("cat /root/vpn_project/src/config/mod.rs")
mod_content = stdout.read().decode(errors='replace')

# Add DPD config struct before the test section
old_test_section = """#[cfg(test)]
mod tests {"""

new_dpd_struct = """#[derive(Debug, Default, Deserialize, Clone)]
pub struct DpdConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dpd_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_dpd_max_retries")]
    pub max_retries: u32,
}

#[cfg(test)]
mod tests {"""

if old_test_section in mod_content:
    mod_content = mod_content.replace(old_test_section, new_dpd_struct)
    print("Added DpdConfig struct")
else:
    print("ERROR: Could not find test section")

# Add DPD default functions
old_defaults_end = """fn default_rate_limit() -> u32 { 10000 }"""

new_dpd_defaults = """fn default_rate_limit() -> u32 { 10000 }
fn default_dpd_interval() -> u64 { 30 }
fn default_dpd_max_retries() -> u32 { 3 }"""

if old_defaults_end in mod_content:
    mod_content = mod_content.replace(old_defaults_end, new_dpd_defaults)
    print("Added DPD default functions")
else:
    print("ERROR: Could not find defaults end")

# Write back
stdin, stdout, stderr = ssh.exec_command("cat > /root/vpn_project/src/config/mod.rs")
stdin.write(mod_content)
stdin.channel.shutdown_write()
exit_code = stdout.channel.recv_exit_status()
print(f"Write exit code: {exit_code}")

# Now add DPD to ServerConfig
print("\n=== Updating server config ===")
stdin, stdout, stderr = ssh.exec_command("cat /root/vpn_project/src/config/server.rs")
server_config = stdout.read().decode(errors='replace')

# Add DPD field to ServerConfig struct
old_server_struct = """    #[serde(default)]
    pub performance: ServerPerformanceConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}"""

new_server_struct = """    #[serde(default)]
    pub performance: ServerPerformanceConfig,
    #[serde(default)]
    pub dpd: crate::config::DpdConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}"""

if old_server_struct in server_config:
    server_config = server_config.replace(old_server_struct, new_server_struct)
    print("Added DPD field to ServerConfig")
else:
    print("ERROR: Could not find ServerConfig struct end")

# Write back
stdin, stdout, stderr = ssh.exec_command("cat > /root/vpn_project/src/config/server.rs")
stdin.write(server_config)
stdin.channel.shutdown_write()
exit_code = stdout.channel.recv_exit_status()
print(f"Write exit code: {exit_code}")

# Add DPD to ClientConfig
print("\n=== Updating client config ===")
ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

stdin2, stdout2, stderr2 = ssh2.exec_command("cat /root/vpn_project/src/config/client.rs")
client_config = stdout2.read().decode(errors='replace')

# Add DPD field to ClientConfig struct
old_client_struct = """    #[serde(default)]
    pub performance: ClientPerformanceConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}"""

new_client_struct = """    #[serde(default)]
    pub performance: ClientPerformanceConfig,
    #[serde(default)]
    pub dpd: crate::config::DpdConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}"""

if old_client_struct in client_config:
    client_config = client_config.replace(old_client_struct, new_client_struct)
    print("Added DPD field to ClientConfig")
else:
    print("ERROR: Could not find ClientConfig struct end")

# Write back
stdin2, stdout2, stderr2 = ssh2.exec_command("cat > /root/vpn_project/src/config/client.rs")
stdin2.write(client_config)
stdin2.channel.shutdown_write()
exit_code = stdout2.channel.recv_exit_status()
print(f"Write exit code: {exit_code}")

ssh.close()
ssh2.close()
