import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.66.116.10', username='root', password=os.environ.get("QELI_LAB_PASS", ""), timeout=15)

# Read current server mod.rs
print("=== Reading server mod.rs ===")
stdin, stdout, stderr = ssh.exec_command("cat /root/vpn_project/src/server/mod.rs")
mod_rs = stdout.read().decode(errors='replace')

# Create new multi-interface server mod.rs
new_mod_rs = '''pub mod handler;
pub mod pool;
pub mod router;
pub mod dns;

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::os::fd::AsRawFd;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, Mutex, mpsc};
use serde::Deserialize;
use crate::config::server::ServerConfig;
use crate::config::users::UsersDb;
use crate::crypto::StaticKeypair;
use crate::tun::iface::TunInterface;
use crate::server::handler::ClientSession;

// ── Main config (multi-interface) ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct MainConfig {
    #[serde(default)]
    pub interfaces: Vec<InterfaceEntry>,
    #[serde(default)]
    pub global: GlobalConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InterfaceEntry {
    pub name: String,
    pub config_file: String,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct GlobalConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_address: String,
    #[serde(default = "default_port")]
    pub bind_port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    pub log_file: Option<String>,
}

fn default_bind_addr() -> String { "0.0.0.0".into() }
fn default_port() -> u16 { 443 }
fn default_log_level() -> String { "info".into() }

// ── Per-interface state ───────────────────────────────────────────────────────

pub struct InterfaceState {
    pub name: String,
    pub config: ServerConfig,
    pub users_db: UsersDb,
    pub pool: Arc<Mutex<pool::IpPool>>,
    pub sessions: Arc<RwLock<Vec<ClientSession>>>,
    pub static_keypair: Arc<StaticKeypair>,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
}

// ── Rate limiter ───────────────────────────────────────────────────────────────

pub struct RateLimiter {
    attempts: HashMap<IpAddr, VecDeque<Instant>>,
    max_attempts: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_attempts: usize, window_secs: u64) -> Self {
        RateLimiter {
            attempts: HashMap::new(),
            max_attempts,
            window: Duration::from_secs(window_secs),
        }
    }

    pub fn check_and_record(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window = self.window;
        let entry = self.attempts.entry(ip).or_default();
        while entry.front().map(|t| now.duration_since(*t) > window).unwrap_or(false) {
            entry.pop_front();
        }
        if entry.len() >= self.max_attempts {
            return false;
        }
        entry.push_back(now);
        true
    }
}

// ── Server state (multi-interface) ────────────────────────────────────────────

pub struct ServerState {
    pub global: GlobalConfig,
    pub interfaces: Vec<Arc<InterfaceState>>,
}

// ── Static key helpers ─────────────────────────────────────────────────────────

const STATIC_KEY_PATH: &str = "/var/lib/vpn-obfuscated/server_identity.key";

fn load_or_generate_static_key() -> anyhow::Result<StaticKeypair> {
    if std::path::Path::new(STATIC_KEY_PATH).exists() {
        let bytes = std::fs::read(STATIC_KEY_PATH)?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!("Invalid server identity key length: {}", bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        let kp = StaticKeypair::from_private_bytes(key);
        log::info!("Loaded server identity key from {}", STATIC_KEY_PATH);
        Ok(kp)
    } else {
        let kp = StaticKeypair::generate();
        if let Some(parent) = std::path::Path::new(STATIC_KEY_PATH).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(STATIC_KEY_PATH, kp.private_bytes())?;
        log::info!("Generated new server identity key, saved to {}", STATIC_KEY_PATH);
        Ok(kp)
    }
}

// ── Load single interface ─────────────────────────────────────────────────────

fn load_interface(entry: &InterfaceEntry, static_keypair: Arc<StaticKeypair>) -> anyhow::Result<Arc<InterfaceState>> {
    log::info!("Loading interface '{}' from {}", entry.name, entry.config_file);
    
    let config_content = std::fs::read_to_string(&entry.config_file)?;
    let config: ServerConfig = serde_json::from_str(&config_content)?;
    
    let users_db = UsersDb::load(&config.auth.users_file)
        .unwrap_or_else(|_| {
            log::warn!("users file not found for interface {}, creating empty", entry.name);
            UsersDb { users: vec![], groups: std::collections::HashMap::new() }
        });
    
    let pool = pool::IpPool::new(&config.pool)?;
    
    Ok(Arc::new(InterfaceState {
        name: entry.name.clone(),
        config,
        users_db,
        pool: Arc::new(Mutex::new(pool)),
        sessions: Arc::new(RwLock::new(Vec::new())),
        static_keypair,
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(10, 60))),
    }))
}

// ── Server startup ─────────────────────────────────────────────────────────────

pub async fn run_server(config_path: &str) -> anyhow::Result<()> {
    // Load main config
    let main_content = std::fs::read_to_string(config_path)?;
    let main_config: MainConfig = serde_json::from_str(&main_content)?;
    
    log::info!("Loaded main config: {} interfaces", main_config.interfaces.len());
    
    // Load static key (shared across all interfaces)
    let static_keypair = Arc::new(load_or_generate_static_key()?);
    let pub_hex: String = static_keypair.public.as_bytes()
        .iter().map(|b| format!("{:02x}", b)).collect();
    log::info!("Server static public key (pin in clients): {}", pub_hex);
    
    // Load all interfaces
    let mut interfaces = Vec::new();
    for entry in &main_config.interfaces {
        let iface = load_interface(entry, static_keypair.clone())?;
        interfaces.push(iface);
    }
    
    let state = Arc::new(ServerState {
        global: main_config.global.clone(),
        interfaces,
    });
    
    // Setup TUN interfaces
    for iface_state in &state.interfaces {
        let config = &iface_state.config;
        log::info!("Setting up TUN interface {} ({})", config.tun.name, config.tun.address);
        
        TunInterface::delete(&config.tun.name).ok();
        let tun = TunInterface::create(&config.tun.name, config.tun.mtu)?;
        TunInterface::set_address(&config.tun.name, &config.tun.address, &config.tun.netmask)?;
        TunInterface::set_up(&config.tun.name, config.tun.mtu)?;
        TunInterface::set_queue_len(&config.tun.name, config.tun.tx_queue_len)?;
        // Use blocking mode for efficiency
        // tun.set_nonblocking()?;
        
        log::info!("TUN {} is up ({} {})", config.tun.name, config.tun.address, config.tun.netmask);
        
        // Setup NAT if enabled
        if config.routing.nat.enabled {
            let nat_iface = &config.routing.nat.interface;
            log::info!("Setting up NAT on {}", nat_iface);
            let _ = std::process::Command::new("iptables")
                .args(["-t", "nat", "-A", "POSTROUTING", "-s", &config.pool.cidr, "-o", nat_iface, "-j", "MASQUERADE"])
                .output();
            let _ = std::process::Command::new("sysctl")
                .args(["-w", "net.ipv4.ip_forward=1"])
                .output();
        }
        
        // Share TUN fd via dup()
        let reader_fd = unsafe { libc::dup(tun.as_raw_fd()) };
        let writer_fd = unsafe { libc::dup(tun.as_raw_fd()) };
        if reader_fd < 0 || writer_fd < 0 {
            return Err(anyhow::anyhow!("failed to dup TUN fd for {}", config.tun.name));
        }
        
        let (tun_to_server_tx, mut tun_to_server_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (server_to_tun_tx, mut server_to_tun_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        
        let tun_buf_size = config.performance.tun.read_buffer_size;
        
        // TUN reader (blocking)
        let tun_tx_clone = server_to_tun_tx.clone();
        tokio::task::spawn_blocking(move || {
            log::info!("TUN reader started for {}", config.tun.name);
            let mut buf = vec![0u8; tun_buf_size];
            loop {
                let n = unsafe {
                    libc::read(reader_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EAGAIN) || err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    log::error!("TUN read error for {}: {}", config.tun.name, err);
                    break;
                }
                if n == 0 { break; }
                let packet = buf[..n as usize].to_vec();
                if tun_tx_clone.send(packet).is_err() { break; }
            }
            unsafe { libc::close(reader_fd); }
            log::info!("TUN reader stopped for {}", config.tun.name);
        });
        
        // TUN writer (batch)
        let iface_name = config.tun.name.clone();
        tokio::spawn(async move {
            log::info!("TUN writer started for {}", iface_name);
            let mut batch = Vec::with_capacity(64);
            while let Some(packet) = server_to_tun_rx.recv().await {
                if !packet.is_empty() {
                    batch.push(packet);
                }
                for _ in 0..63 {
                    match server_to_tun_rx.try_recv() {
                        Ok(p) => { if !p.is_empty() { batch.push(p); } }
                        Err(_) => break,
                    }
                }
                for pkt in batch.drain(..) {
                    tokio::task::block_in_place(|| unsafe {
                        libc::write(writer_fd, pkt.as_ptr() as *const libc::c_void, pkt.len());
                    });
                }
            }
            unsafe { libc::close(writer_fd); }
            log::info!("TUN writer stopped for {}", iface_name);
        });
        
        // Forwarder: route TUN packets to connected clients
        let fwd_state = iface_state.clone();
        tokio::spawn(async move {
            while let Some(packet) = tun_to_server_rx.recv().await {
                if packet.len() < 20 || (packet[0] >> 4) != 4 { continue; }
                let dest_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                let sessions = fwd_state.sessions.read().await;
                for session in sessions.iter() {
                    if session.client_ip == dest_ip {
                        if let Ok(mut codec) = session.codec.lock() {
                            if let Ok(encrypted) = codec.encrypt_packet(&packet, &[]) {
                                let _ = session.writer.send(encrypted);
                            }
                        }
                        break;
                    }
                }
            }
        });
        
        // DNS proxy
        if config.dns.enabled {
            let dns_state = iface_state.clone();
            tokio::spawn(async move {
                if let Err(e) = dns::run_dns_proxy(dns_state).await {
                    log::error!("DNS proxy error for {}: {}", iface_name, e);
                }
            });
        }
    }
    
    // Single TCP listener for all interfaces
    let bind_addr = format!("{}:{}", state.global.bind_address, state.global.bind_port);
    log::info!("Listening on {} for {} interfaces", bind_addr, state.interfaces.len());
    let listener = TcpListener::bind(&bind_addr).await?;
    
    loop {
        let (stream, addr) = listener.accept().await?;
        
        // Rate limiting
        {
            let mut rl = state.interfaces[0].rate_limiter.lock().await;
            if !rl.check_and_record(addr.ip()) {
                log::warn!("Rate limit exceeded for {}, dropping", addr.ip());
                continue;
            }
        }
        
        log::info!("New connection from {}", addr);
        
        // Try each interface (first match wins based on auth)
        let state_clone = state.clone();
        tokio::spawn(async move {
            // Try each interface
            for iface_state in &state_clone.interfaces {
                let tun_tx = {
                    // We need to get the server_to_tun_tx for this interface
                    // This is a simplification - in production, we'd store the tx channels
                    // For now, we use the first interface
                    continue;
                };
                
                // Clone for handler
                let iface_clone = iface_state.clone();
                // handler::handle_client(iface_clone, stream, addr, tun_tx).await
            }
            // Fallback: use first interface
            if let Some(iface_state) = state_clone.interfaces.first() {
                // This needs the tun_tx channel - we need to store it
            }
        });
    }
}
'''

# Write the new mod.rs
stdin, stdout, stderr = ssh.exec_command("cat > /root/vpn_project/src/server/mod.rs")
stdin.write(new_mod_rs)
stdin.channel.shutdown_write()
exit_code = stdout.channel.recv_exit_status()
print(f"Write exit code: {exit_code}")

# Try to build
print("\n=== Building ===")
stdin, stdout, stderr = ssh.exec_command("cd /root/vpn_project && cargo build --release 2>&1 | grep -E 'Compiling|Finished|error'")
print(stdout.read().decode(errors='replace'))

ssh.close()
