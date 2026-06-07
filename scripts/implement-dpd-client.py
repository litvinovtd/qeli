import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

ssh2 = paramiko.SSHClient()
ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh2.connect('10.66.116.11', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Read client mod.rs
print("=== Reading client mod.rs ===")
stdin2, stdout2, stderr2 = ssh2.exec_command("cat /root/vpn_project/src/client/mod.rs")
client = stdout2.read().decode(errors='replace')

# Replace heartbeat config with DPD config
old_hb_config = """    let hb_config = &config.obfuscation.heartbeat;
    let padding_min = config.obfuscation.padding.min_bytes;
    let padding_max = config.obfuscation.padding.max_bytes;
    let tun_buf_size = config.performance.tun_buffer_size;"""

new_dpd_config = """    // DPD (Dead Peer Detection) configuration
    let dpd_enabled = config.dpd.enabled;
    let dpd_interval = Duration::from_secs(config.dpd.interval_secs);
    let dpd_max_retries = config.dpd.max_retries;
    let mut dpd_retries = 0u32;

    let padding_min = config.obfuscation.padding.min_bytes;
    let padding_max = config.obfuscation.padding.max_bytes;
    let tun_buf_size = config.performance.tun_buffer_size;"""

if old_hb_config in client:
    client = client.replace(old_hb_config, new_dpd_config)
    print("Replaced heartbeat config with DPD config")
else:
    print("ERROR: Could not find heartbeat config")

# Replace heartbeat tick with DPD tick
old_hb_tick = """    let heartbeat_interval = Duration::from_millis(hb_config.interval_ms);
    let mut heartbeat_tick = tokio::time::interval(heartbeat_interval);
    heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);"""

new_dpd_tick = """    let mut dpd_tick = tokio::time::interval(dpd_interval);
    dpd_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);"""

if old_hb_tick in client:
    client = client.replace(old_hb_tick, new_dpd_tick)
    print("Replaced heartbeat tick with DPD tick")
else:
    print("ERROR: Could not find heartbeat tick")

# Replace heartbeat handler with DPD handler
old_hb_handler = """            _ = heartbeat_tick.tick() => {
                // Lightweight heartbeat — no padding
                let heartbeat = client_tx.encrypt_packet(&[], &[]).ok();
                if let Some(hb) = heartbeat {
                    if stream.write_all(&hb).await.is_err() {
                        break;
                    }
                }
                last_activity = tokio::time::Instant::now();
            }"""

new_dpd_handler = """            _ = dpd_tick.tick(), if dpd_enabled => {
                // DPD: only send probe if connection has been idle
                let idle_duration = tokio::time::Instant::now().duration_since(last_activity);
                if idle_duration >= dpd_interval {
                    dpd_retries += 1;
                    if dpd_retries > dpd_max_retries {
                        log::warn!("DPD timeout ({} retries), reconnecting", dpd_retries);
                        break;
                    }
                    // Send DPD probe (empty encrypted packet)
                    let probe = client_tx.encrypt_packet(&[], &[]).ok();
                    if let Some(pkt) = probe {
                        if stream.write_all(&pkt).await.is_err() {
                            break;
                        }
                    }
                    log::debug!("DPD probe #{}", dpd_retries);
                } else {
                    // Reset retry counter since we had activity
                    dpd_retries = 0;
                }
            }"""

if old_hb_handler in client:
    client = client.replace(old_hb_handler, new_dpd_handler)
    print("Replaced heartbeat handler with DPD handler")
else:
    print("ERROR: Could not find heartbeat handler")
    # Show what we have around heartbeat
    import re
    match = re.search(r'heartbeat_tick\.tick.*?\n.*?\n.*?\n.*?\n.*?\n.*?\n.*?\n.*?\n.*?\}', client, re.DOTALL)
    if match:
        print(f"Found: {match.group()[:300]}")

# Add dpd_retries reset on stream activity
old_stream_read = """                last_activity = tokio::time::Instant::now();
                match client_rx.decrypt_packet(&tcp_buf[..n]) {"""

new_stream_read = """                last_activity = tokio::time::Instant::now();
                dpd_retries = 0;
                match client_rx.decrypt_packet(&tcp_buf[..n]) {"""

if old_stream_read in client:
    client = client.replace(old_stream_read, new_stream_read)
    print("Added DPD retry reset on stream read")
else:
    print("ERROR: Could not find stream read")

# Add dpd_retries reset on tun_read
old_tun_read = """            Some(ip_packet) = tun_read_rx.recv() => {
                last_activity = tokio::time::Instant::now();"""

new_tun_read = """            Some(ip_packet) = tun_read_rx.recv() => {
                last_activity = tokio::time::Instant::now();
                dpd_retries = 0;"""

if old_tun_read in client:
    client = client.replace(old_tun_read, new_tun_read)
    print("Added DPD retry reset on tun read")
else:
    print("ERROR: Could not find tun read")

# Write back
stdin2, stdout2, stderr2 = ssh2.exec_command("cat > /root/vpn_project/src/client/mod.rs")
stdin2.write(client)
stdin2.channel.shutdown_write()
exit_code = stdout2.channel.recv_exit_status()
print(f"Write exit code: {exit_code}")

ssh2.close()
