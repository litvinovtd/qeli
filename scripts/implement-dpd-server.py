import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Read current handler.rs
print("=== Reading handler.rs ===")
stdin, stdout, stderr = ssh.exec_command("cat /root/vpn_project/src/server/handler.rs")
handler = stdout.read().decode(errors='replace')

# Replace heartbeat with DPD
old_heartbeat_config = """    // Heartbeat & idle timeout configuration
    let hb_config = &state.config.obfuscation.heartbeat;
    let heartbeat_enabled = hb_config.enabled;
    let heartbeat_interval = Duration::from_millis(hb_config.interval_ms);
    let idle_timeout = Duration::from_secs(state.config.performance.connection.idle_timeout_secs);

    let mut heartbeat_tick = tokio::time::interval(heartbeat_interval);
    heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);"""

new_dpd_config = """    // DPD (Dead Peer Detection) configuration
    // DPD probes are sent only when the connection is idle
    let dpd_enabled = state.config.dpd.enabled;
    let dpd_interval = Duration::from_secs(state.config.dpd.interval_secs);
    let dpd_max_retries = state.config.dpd.max_retries;
    let idle_timeout = Duration::from_secs(state.config.performance.connection.idle_timeout_secs);

    let mut dpd_tick = tokio::time::interval(dpd_interval);
    dpd_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut dpd_retries = 0u32;"""

if old_heartbeat_config in handler:
    handler = handler.replace(old_heartbeat_config, new_dpd_config)
    print("Replaced heartbeat config with DPD config")
else:
    print("ERROR: Could not find heartbeat config")

# Replace heartbeat tick with DPD tick
old_heartbeat_tick = """            _ = heartbeat_tick.tick(), if heartbeat_enabled => {
                // Lightweight heartbeat — no padding, minimal overhead
                let heartbeat = server_tx.encrypt_packet(&[], &[]).ok();
                if let Some(hb) = heartbeat {
                    if stream.write_all(&hb).await.is_err() {
                        break;
                    }
                }
                last_activity = tokio::time::Instant::now();
            }"""

new_dpd_tick = """            _ = dpd_tick.tick(), if dpd_enabled => {
                // DPD: only send probe if connection has been idle
                let idle_duration = tokio::time::Instant::now().duration_since(last_activity);
                if idle_duration >= dpd_interval {
                    dpd_retries += 1;
                    if dpd_retries > dpd_max_retries {
                        log::warn!("Client {} DPD timeout ({} retries), disconnecting", addr, dpd_retries);
                        break;
                    }
                    // Send DPD probe (empty encrypted packet)
                    let probe = server_tx.encrypt_packet(&[], &[]).ok();
                    if let Some(pkt) = probe {
                        if stream.write_all(&pkt).await.is_err() {
                            break;
                        }
                    }
                    log::debug!("Client {} DPD probe #{}", addr, dpd_retries);
                } else {
                    // Reset retry counter since we had activity
                    dpd_retries = 0;
                }
            }"""

if old_heartbeat_tick in handler:
    handler = handler.replace(old_heartbeat_tick, new_dpd_tick)
    print("Replaced heartbeat tick with DPD tick")
else:
    print("ERROR: Could not find heartbeat tick")

# Reset dpd_retries on activity
old_activity_reset = """                last_activity = tokio::time::Instant::now();"""

# We need to add dpd_retries = 0 on each activity
# Find the first occurrence in stream.read block
old_stream_activity = """                last_activity = tokio::time::Instant::now();

                match server_rx.decrypt_packet(&buf[..n]) {"""

new_stream_activity = """                last_activity = tokio::time::Instant::now();
                dpd_retries = 0;

                match server_rx.decrypt_packet(&buf[..n]) {"""

if old_stream_activity in handler:
    handler = handler.replace(old_stream_activity, new_stream_activity)
    print("Added DPD retry reset on stream activity")

# Also reset on rx.recv
old_rx_activity = """            Some(packet) = rx.recv() => {
                last_activity = tokio::time::Instant::now();"""

new_rx_activity = """            Some(packet) = rx.recv() => {
                last_activity = tokio::time::Instant::now();
                dpd_retries = 0;"""

if old_rx_activity in handler:
    handler = handler.replace(old_rx_activity, new_rx_activity)
    print("Added DPD retry reset on rx activity")

# Write back
stdin, stdout, stderr = ssh.exec_command("cat > /root/vpn_project/src/server/handler.rs")
stdin.write(handler)
stdin.channel.shutdown_write()
exit_code = stdout.channel.recv_exit_status()
print(f"Write exit code: {exit_code}")

ssh.close()
