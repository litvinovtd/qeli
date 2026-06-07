use crate::server::pool::{u32_from_ip, IpPool};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};

#[allow(dead_code)] // standard DHCP port constant kept for reference
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

const BOOTP_REPLY: u8 = 2;
const DHCP_OPCODE: u8 = 53;
const DHCP_MSG_TYPE_OFFER: u8 = 2;
const DHCP_MSG_TYPE_ACK: u8 = 5;
const DHCP_MSG_TYPE_NAK: u8 = 6;
const DHCP_OPTION_END: u8 = 255;
const DHCP_OPTION_SUBNET_MASK: u8 = 1;
const DHCP_OPTION_ROUTER: u8 = 3;
const DHCP_OPTION_DNS: u8 = 6;
const DHCP_OPTION_LEASE_TIME: u8 = 51;
const DHCP_OPTION_REBINDING_TIME: u8 = 59;
const DHCP_OPTION_RENEWAL_TIME: u8 = 58;
const DHCP_OPTION_SERVER_ID: u8 = 54;
const DHCP_OPTION_DOMAIN_NAME: u8 = 15;

#[derive(Clone)]
struct DhcpLease {
    ip: Ipv4Addr,
    mac: MacAddr,
    expires_at: u64,
}

#[derive(Clone, Copy)]
struct MacAddr([u8; 6]);

impl MacAddr {
    fn from_bytes(data: &[u8]) -> Self {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&data[..6]);
        MacAddr(mac)
    }
}

pub struct DhcpServer {
    server_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    gateway: Ipv4Addr,
    dns_servers: Vec<Ipv4Addr>,
    domain_name: String,
    lease_time_secs: u32,
    pool_start: u32,
    pool_end: u32,
    leases: RwLock<Vec<Option<DhcpLease>>>,
    start_time: std::time::Instant,
    /// Shared IP pool — DHCP allocates through it to prevent overlap with VPN sessions
    shared_pool: Arc<Mutex<IpPool>>,
}

impl DhcpServer {
    #[allow(clippy::too_many_arguments)] // a DHCP server is configured by exactly these fields
    pub fn new(
        server_ip: Ipv4Addr,
        subnet_mask: Ipv4Addr,
        gateway: Ipv4Addr,
        dns_servers: Vec<Ipv4Addr>,
        domain_name: String,
        lease_time_secs: u32,
        pool_start: Ipv4Addr,
        pool_end: Ipv4Addr,
        shared_pool: Arc<Mutex<IpPool>>,
    ) -> Self {
        let start = u32_from_ip(pool_start);
        let end = u32_from_ip(pool_end);
        let pool_size = (end - start + 1) as usize;
        let leases = vec![None; pool_size];

        DhcpServer {
            server_ip,
            subnet_mask,
            gateway,
            dns_servers,
            domain_name,
            lease_time_secs,
            pool_start: start,
            pool_end: end,
            leases: RwLock::new(leases),
            start_time: std::time::Instant::now(),
            shared_pool,
        }
    }

    pub async fn run(self: Arc<Self>, bind_addr: &str) -> anyhow::Result<()> {
        log::info!("DHCP run() starting, binding to {}", bind_addr);
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.set_broadcast(true)?;
        log::info!("DHCP server bound to {}, starting recv loop", bind_addr);

        let mut buf = vec![0u8; 1500];

        loop {
            log::trace!("DHCP waiting for packet...");
            let (n, src) = socket.recv_from(&mut buf).await?;
            log::info!("DHCP received {} bytes from {}", n, src);
            if let Err(e) = self.handle_packet(&buf[..n], &socket, &src).await {
                log::debug!("DHCP error from {}: {}", src, e);
            }
        }
    }

    async fn handle_packet(
        &self,
        data: &[u8],
        socket: &UdpSocket,
        _src: &std::net::SocketAddr,
    ) -> anyhow::Result<()> {
        if data.len() < 240 {
            log::warn!("DHCP: packet too short ({} bytes)", data.len());
            return Err(anyhow::anyhow!("packet too short"));
        }
        if data[0] != 1 {
            log::warn!("DHCP: not BOOTREQUEST (op={})", data[0]);
            return Err(anyhow::anyhow!("not a BOOTREQUEST"));
        }

        let msg_type =
            Self::find_dhcp_option(data, DHCP_OPCODE).and_then(|opt| opt.get(2).copied());
        log::info!("DHCP: received message type {:?}", msg_type);

        match msg_type {
            Some(1) => self.handle_discover(data, socket).await,
            Some(3) => self.handle_request(data, socket).await,
            other => {
                log::warn!("DHCP: unsupported message type {:?}", other);
                Err(anyhow::anyhow!("unsupported DHCP message type"))
            }
        }
    }

    async fn handle_discover(&self, data: &[u8], socket: &UdpSocket) -> anyhow::Result<()> {
        let mac = MacAddr::from_bytes(&data[28..34]);
        let requested_ip = Self::find_dhcp_option(data, 50)
            .and_then(|opt| opt.get(2..6))
            .map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]));

        log::info!(
            "DHCP DISCOVER from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, requested_ip: {:?}",
            mac.0[0],
            mac.0[1],
            mac.0[2],
            mac.0[3],
            mac.0[4],
            mac.0[5],
            requested_ip
        );

        let offered_ip = match self.allocate_ip(&mac, requested_ip).await {
            Some(ip) => ip,
            None => {
                log::error!("DHCP: no IP available in pool for allocation");
                return Err(anyhow::anyhow!("no IP available"));
            }
        };

        let reply = match self.build_reply(data, offered_ip, DHCP_MSG_TYPE_OFFER) {
            Ok(r) => r,
            Err(e) => {
                log::error!("DHCP: failed to build reply: {}", e);
                return Err(e);
            }
        };

        log::info!(
            "DHCP: sending OFFER for {} ({} bytes) via broadcast",
            offered_ip,
            reply.len()
        );

        let broadcast = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
            DHCP_CLIENT_PORT,
        );
        match socket.send_to(&reply, broadcast).await {
            Ok(n) => log::info!(
                "DHCP OFFER {} sent to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ({} bytes)",
                offered_ip,
                mac.0[0],
                mac.0[1],
                mac.0[2],
                mac.0[3],
                mac.0[4],
                mac.0[5],
                n
            ),
            Err(e) => log::error!("DHCP: failed to send broadcast: {}", e),
        }
        Ok(())
    }

    async fn handle_request(&self, data: &[u8], socket: &UdpSocket) -> anyhow::Result<()> {
        let mac = MacAddr::from_bytes(&data[28..34]);
        let requested_ip = Self::find_dhcp_option(data, 50)
            .or_else(|| Self::find_dhcp_option(data, 54))
            .and_then(|opt| opt.get(2..6))
            .map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]));

        let broadcast = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
            DHCP_CLIENT_PORT,
        );

        // Never ACK an address just because the client asked for it. Run the
        // request through the real allocator (which honours this MAC's existing
        // lease and only hands out addresses inside our pool). ACK only when the
        // allocator agrees with the requested address; otherwise NAK so the
        // client restarts with DISCOVER. Previously the requested IP was echoed
        // straight into an ACK, letting a client claim any address it named.
        let granted = self.allocate_ip(&mac, requested_ip).await;
        match (requested_ip, granted) {
            (Some(req), Some(ip)) if ip == req => {
                let reply = self.build_reply(data, ip, DHCP_MSG_TYPE_ACK)?;
                socket.send_to(&reply, broadcast).await?;
                log::info!(
                    "DHCP ACK {} to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    ip,
                    mac.0[0],
                    mac.0[1],
                    mac.0[2],
                    mac.0[3],
                    mac.0[4],
                    mac.0[5]
                );
            }
            (Some(req), granted) => {
                log::warn!("DHCP NAK: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} requested {} but pool grants {:?}",
                    mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5], req, granted);
                let reply = self.build_nak(data);
                socket.send_to(&reply, broadcast).await?;
            }
            (None, _) => {
                log::warn!("DHCP REQUEST without requested-IP option from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5]);
            }
        }

        Ok(())
    }

    /// Minimal DHCPNAK (message-type + server-id, yiaddr = 0.0.0.0). Sent when a
    /// REQUEST asks for an address the allocator will not grant, forcing the
    /// client back to DISCOVER.
    fn build_nak(&self, request: &[u8]) -> Vec<u8> {
        let mut reply = vec![0u8; 240];
        reply[0] = BOOTP_REPLY;
        reply[1] = 1;
        reply[2] = 6;
        reply[4..8].copy_from_slice(&request[4..8]); // xid
                                                     // yiaddr stays 0.0.0.0
        reply[20..24].copy_from_slice(&self.server_ip.octets());
        reply[28..34].copy_from_slice(&request[28..34]); // client MAC
        reply[236] = 99;
        reply[237] = 130;
        reply[238] = 83;
        reply[239] = 99; // magic cookie

        let mut options = Vec::new();
        options.extend_from_slice(&[DHCP_OPCODE, 1, DHCP_MSG_TYPE_NAK]);
        options.extend_from_slice(&[DHCP_OPTION_SERVER_ID, 4]);
        options.extend_from_slice(&self.server_ip.octets());
        options.push(DHCP_OPTION_END);
        reply.extend_from_slice(&options);
        reply
    }

    async fn allocate_ip(&self, mac: &MacAddr, preferred: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        let mac_str = format!(
            "dhcp:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5]
        );

        let mut leases = self.leases.write().await;
        let now_secs = self.start_time.elapsed().as_secs();

        // Check if this MAC already has an active lease — reuse it without re-allocating
        for lease in leases.iter().flatten() {
            if lease.mac.0 == mac.0 && now_secs <= lease.expires_at {
                return Some(lease.ip);
            }
        }

        // Release expired leases from the shared pool so their IPs become available again
        for slot in leases.iter_mut() {
            if let Some(lease) = slot {
                if now_secs > lease.expires_at {
                    let expired_mac = format!(
                        "dhcp:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                        lease.mac.0[0],
                        lease.mac.0[1],
                        lease.mac.0[2],
                        lease.mac.0[3],
                        lease.mac.0[4],
                        lease.mac.0[5]
                    );
                    let mut pool = self.shared_pool.lock().await;
                    pool.release(&expired_mac);
                    *slot = None;
                }
            }
        }

        // Try to honour the preferred IP if it falls in our DHCP range and is available
        if let Some(pref) = preferred {
            let pref_u32 = u32_from_ip(pref);
            if pref_u32 >= self.pool_start && pref_u32 <= self.pool_end {
                let idx = (pref_u32 - self.pool_start) as usize;
                if idx < leases.len() && leases[idx].is_none() {
                    let mut pool = self.shared_pool.lock().await;
                    // Temporarily allocate under this MAC's key; if the slot is taken in the
                    // shared pool it will return a different address — fall through below.
                    if pool.get_ip_by_username(&mac_str).is_none() {
                        if let Some(allocated) = pool.allocate(&mac_str) {
                            if allocated == pref {
                                leases[idx] = Some(DhcpLease {
                                    ip: pref,
                                    mac: *mac,
                                    expires_at: now_secs + self.lease_time_secs as u64,
                                });
                                return Some(pref);
                            }
                            // Got a different IP from pool — record it and return it
                            let alloc_u32 = u32_from_ip(allocated);
                            if alloc_u32 >= self.pool_start && alloc_u32 <= self.pool_end {
                                let alloc_idx = (alloc_u32 - self.pool_start) as usize;
                                if alloc_idx < leases.len() {
                                    leases[alloc_idx] = Some(DhcpLease {
                                        ip: allocated,
                                        mac: *mac,
                                        expires_at: now_secs + self.lease_time_secs as u64,
                                    });
                                }
                            }
                            return Some(allocated);
                        }
                    }
                }
            }
        }

        // Dynamic allocation through the shared pool
        let mut pool = self.shared_pool.lock().await;
        if let Some(allocated) = pool.allocate(&mac_str) {
            let alloc_u32 = u32_from_ip(allocated);
            if alloc_u32 >= self.pool_start && alloc_u32 <= self.pool_end {
                let alloc_idx = (alloc_u32 - self.pool_start) as usize;
                if alloc_idx < leases.len() {
                    leases[alloc_idx] = Some(DhcpLease {
                        ip: allocated,
                        mac: *mac,
                        expires_at: now_secs + self.lease_time_secs as u64,
                    });
                }
            }
            return Some(allocated);
        }

        None
    }

    fn build_reply(
        &self,
        request: &[u8],
        offered_ip: Ipv4Addr,
        msg_type: u8,
    ) -> anyhow::Result<Vec<u8>> {
        let mut reply = vec![0u8; 240];

        reply[0] = BOOTP_REPLY;
        reply[1] = 1; // hardware type: Ethernet
        reply[2] = 6; // hardware address length
        reply[3] = 0; // hops

        reply[4..8].copy_from_slice(&request[4..8]); // xid

        reply[16..20].copy_from_slice(&offered_ip.octets());
        reply[20..24].copy_from_slice(&self.server_ip.octets());
        reply[28..34].copy_from_slice(&request[28..34]); // client MAC

        reply[236] = 99;
        reply[237] = 130;
        reply[238] = 83;
        reply[239] = 99; // magic cookie

        let mut options = Vec::new();
        options.extend_from_slice(&[DHCP_OPCODE, 1, msg_type]);
        options.extend_from_slice(&[DHCP_OPTION_SUBNET_MASK, 4]);
        options.extend_from_slice(&self.subnet_mask.octets());
        options.extend_from_slice(&[DHCP_OPTION_ROUTER, 4]);
        options.extend_from_slice(&self.gateway.octets());

        if !self.dns_servers.is_empty() {
            options.extend_from_slice(&[DHCP_OPTION_DNS, (4 * self.dns_servers.len()) as u8]);
            for dns in &self.dns_servers {
                options.extend_from_slice(&dns.octets());
            }
        }

        options.extend_from_slice(&[DHCP_OPTION_LEASE_TIME, 4]);
        options.extend_from_slice(&self.lease_time_secs.to_be_bytes());

        let t1 = self.lease_time_secs / 2;
        options.extend_from_slice(&[DHCP_OPTION_RENEWAL_TIME, 4]);
        options.extend_from_slice(&t1.to_be_bytes());

        let t2 = self.lease_time_secs * 3 / 4;
        options.extend_from_slice(&[DHCP_OPTION_REBINDING_TIME, 4]);
        options.extend_from_slice(&t2.to_be_bytes());

        options.extend_from_slice(&[DHCP_OPTION_SERVER_ID, 4]);
        options.extend_from_slice(&self.server_ip.octets());

        if !self.domain_name.is_empty() {
            options.extend_from_slice(&[DHCP_OPTION_DOMAIN_NAME, self.domain_name.len() as u8]);
            options.extend_from_slice(self.domain_name.as_bytes());
        }

        options.push(DHCP_OPTION_END);
        reply.extend_from_slice(&options);
        Ok(reply)
    }

    #[cfg(test)]
    fn find_dhcp_option_pub(data: &[u8], option_code: u8) -> Option<&[u8]> {
        Self::find_dhcp_option(data, option_code)
    }

    fn find_dhcp_option(data: &[u8], option_code: u8) -> Option<&[u8]> {
        if data.len() < 240 {
            return None;
        }
        if data[236..240] != [99, 130, 83, 99] {
            return None;
        }

        let mut pos = 240;
        while pos + 1 < data.len() {
            let code = data[pos];
            if code == 255 {
                return None;
            }
            if code == 0 {
                pos += 1;
                continue;
            }
            if pos + 2 > data.len() {
                return None;
            }
            let len = data[pos + 1] as usize;
            // Bound-check the declared option length before slicing — a crafted
            // DHCP packet with len past the buffer would otherwise panic
            // (index out of bounds), which under panic=abort crashes the server.
            if pos + 2 + len > data.len() {
                return None;
            }
            if code == option_code {
                return Some(&data[pos..pos + 2 + len]);
            }
            pos += 2 + len;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dhcp_base() -> Vec<u8> {
        let mut d = vec![0u8; 240];
        d[236..240].copy_from_slice(&[99, 130, 83, 99]); // magic cookie
        d
    }

    #[test]
    fn malicious_option_length_does_not_panic() {
        // Option 53, declared len 200, but only 1 byte of value present.
        let mut d = dhcp_base();
        d.push(53); // code
        d.push(200); // len far past the buffer
        d.push(0x01);
        // Must return None (bounded), never panic / OOB.
        assert_eq!(DhcpServer::find_dhcp_option_pub(&d, 53), None);
    }

    #[test]
    fn valid_option_is_returned() {
        let mut d = dhcp_base();
        d.extend_from_slice(&[53, 1, 3]); // DHCP message type = REQUEST(3)
        d.push(255); // END
        let opt = DhcpServer::find_dhcp_option_pub(&d, 53).unwrap();
        assert_eq!(opt, &[53, 1, 3]);
    }

    #[test]
    fn truncated_packet_returns_none() {
        assert_eq!(DhcpServer::find_dhcp_option_pub(&[0u8; 10], 53), None);
    }
}
