use crate::server::pool::{u32_from_ip, IpPool};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{self, Duration, MissedTickBehavior};

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

const BOOTP_REPLY: u8 = 2;
const DHCP_OPTION_MSG_TYPE: u8 = 53;
const DHCP_MSG_TYPE_OFFER: u8 = 2;
const DHCP_MSG_TYPE_DECLINE: u8 = 4;
const DHCP_MSG_TYPE_ACK: u8 = 5;
const DHCP_MSG_TYPE_NAK: u8 = 6;
const DHCP_MSG_TYPE_RELEASE: u8 = 7;
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
    /// Addresses reported as conflicting by a client. They are held out of dynamic allocation
    /// for a bounded interval, then automatically become eligible again.
    declined: RwLock<HashMap<Ipv4Addr, u64>>,
    start_time: std::time::Instant,
    /// Shared IP pool — DHCP allocates through it to prevent overlap with VPN sessions
    shared_pool: Arc<Mutex<IpPool>>,
    /// Per-client-MAC rate limit on inbound DHCP packets. DHCP is unauthenticated,
    /// so a single source spraying DISCOVERs could otherwise churn the shared pool
    /// or drown the recv loop. Excess packets from one source are dropped silently.
    recv_limiter: Mutex<crate::server::RateLimiter>,
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
        // Defensive: `end < start` (a misconfig — run_profile rejects it up front)
        // or an overflow at the very top of the v4 space must never panic/OOM the
        // lease Vec. Clamp to a generous backstop so an absurd range can't exhaust
        // memory either. A degenerate range yields an empty pool (hands out nothing)
        // rather than crashing the worker.
        const MAX_DHCP_POOL: usize = 1 << 20; // ~1M addresses
        let pool_size = end
            .checked_sub(start)
            .map(|d| (d as usize).saturating_add(1).min(MAX_DHCP_POOL))
            .unwrap_or(0);
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
            declined: RwLock::new(HashMap::new()),
            start_time: std::time::Instant::now(),
            shared_pool,
            // 60 packets per 10s window per complete client MAC: comfortably above a
            // legitimate DISCOVER/REQUEST handshake (a few packets) while capping
            // an unauthenticated flood from any single address.
            recv_limiter: Mutex::new(crate::server::RateLimiter::new(60, 10)),
        }
    }

    /// Preserve all six hardware-address bytes; IPv6 keys avoid prefix collisions
    /// between clients whose NIC addresses differ only in their final bytes.
    fn client_mac_key(data: &[u8]) -> Option<std::net::IpAddr> {
        let mac = data.get(28..34)?;
        if mac.iter().all(|&b| b == 0) {
            return None;
        }
        let mut key = [0u8; 16];
        key[10..].copy_from_slice(mac);
        Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(key)))
    }

    /// Bind the DHCP socket, separately from serving on it.
    ///
    /// A DHCP client without an address sends DISCOVER/REQUEST to 255.255.255.255. A socket
    /// bound only to the profile gateway address does not receive that traffic on Linux. Bind
    /// UDP/67 to INADDR_ANY and scope it to the actual TAP/TUN device with SO_BINDTODEVICE:
    /// this receives standards-compliant broadcast without exposing the unauthenticated server
    /// on WAN. The configured address remains a validation/display value and supplies the port.
    #[cfg(target_os = "linux")]
    pub async fn bind(bind_addr: &str, interface_name: &str) -> anyhow::Result<UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};

        let requested: SocketAddrV4 = bind_addr
            .parse()
            .map_err(|e| anyhow::anyhow!("DHCP invalid IPv4 listen address {bind_addr}: {e}"))?;
        if interface_name.trim().is_empty() {
            anyhow::bail!("DHCP cannot bind an empty profile interface name");
        }

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| anyhow::anyhow!("DHCP cannot create UDP socket: {e}"))?;
        socket
            .set_reuse_address(true)
            .map_err(|e| anyhow::anyhow!("DHCP cannot enable SO_REUSEADDR: {e}"))?;
        socket
            .bind_device(Some(interface_name.as_bytes()))
            .map_err(|e| {
                anyhow::anyhow!(
                    "DHCP cannot restrict UDP/{} to interface '{}': {e}",
                    requested.port(),
                    interface_name
                )
            })?;
        socket.set_broadcast(true).map_err(|e| {
            anyhow::anyhow!("DHCP cannot enable broadcast on {interface_name}: {e}")
        })?;
        socket
            .set_nonblocking(true)
            .map_err(|e| anyhow::anyhow!("DHCP cannot make socket nonblocking: {e}"))?;
        let actual = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, requested.port());
        socket.bind(&actual.into()).map_err(|e| {
            anyhow::anyhow!(
                "DHCP cannot bind {actual} on interface '{interface_name}' (requested {bind_addr}): {e}"
            )
        })?;
        UdpSocket::from_std(socket.into())
            .map_err(|e| anyhow::anyhow!("DHCP cannot register socket with Tokio: {e}"))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn bind(bind_addr: &str, _interface_name: &str) -> anyhow::Result<UdpSocket> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| anyhow::anyhow!("DHCP cannot bind {bind_addr}: {e}"))?;
        socket
            .set_broadcast(true)
            .map_err(|e| anyhow::anyhow!("DHCP cannot enable broadcast on {bind_addr}: {e}"))?;
        Ok(socket)
    }

    pub async fn run(self: Arc<Self>, bind_addr: &str, socket: UdpSocket) -> anyhow::Result<()> {
        log::info!("DHCP server bound to {}, starting recv loop", bind_addr);

        // Receive the complete UDP datagram so a valid prefix cannot hide a malformed tail.
        let mut buf = vec![0u8; 65_535];
        let mut reaper = time::interval(Duration::from_secs(Self::OFFER_RESERVATION_SECS));
        reaper.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            log::trace!("DHCP waiting for packet...");
            tokio::select! {
                _ = reaper.tick() => {
                    let expired = self.reap_expired().await;
                    if expired != 0 {
                        log::info!("DHCP: released {expired} expired lease(s)");
                    }
                }
                received = socket.recv_from(&mut buf) => {
                    let (n, src) = match received {
                        Ok(v) => v,
                        Err(e) => {
                            // A transient recv error must not kill the profile DHCP service.
                            log::warn!("DHCP recv error: {} — continuing", e);
                            continue;
                        }
                    };
                    log::debug!("DHCP received {} bytes from {}", n, src);
                    if let Err(e) = self.handle_packet(&buf[..n], &socket, &src).await {
                        log::debug!("DHCP error from {}: {}", src, e);
                    }
                }
            }
        }
    }

    async fn handle_packet(
        &self,
        data: &[u8],
        socket: &UdpSocket,
        _src: &std::net::SocketAddr,
    ) -> anyhow::Result<()> {
        Self::validate_request(data)?;
        // Per-CLIENT rate limit: DHCP is unauthenticated, so cap how fast any one client can
        // drive the recv/allocate path. Excess packets are dropped silently (no reply, no pool
        // churn) rather than erroring.
        //
        // Keyed on the client's MAC, not its source IP. A DHCPDISCOVER comes from 0.0.0.0 by
        // definition — the client has no address yet, that is why it is asking — so an
        // IP-keyed bucket lumped EVERY new client on the network into one counter: the tenth
        // machine to boot after a power cut was throttled because nine others had just asked.
        // The MAC is the only identity present in the packet at that point. It is spoofable,
        // but a limiter here is about accidental floods and cheap abuse, and spoofing MACs
        // costs an attacker exactly as much as spoofing source IPs did.
        // (Audit 2026-08-01, §12.)
        {
            let key = Self::client_mac_key(data).unwrap_or_else(|| _src.ip());
            let mut rl = self.recv_limiter.lock().await;
            if !rl.check_and_record(key) {
                log::debug!("DHCP: rate limit exceeded for {}, dropping packet", _src);
                return Ok(());
            }
        }
        let msg_type =
            Self::find_dhcp_option(data, DHCP_OPTION_MSG_TYPE).and_then(|opt| opt.get(2).copied());
        log::debug!("DHCP: received message type {:?}", msg_type);

        match msg_type {
            Some(1) => self.handle_discover(data, socket).await,
            Some(3) => self.handle_request(data, socket).await,
            Some(DHCP_MSG_TYPE_DECLINE) => self.handle_decline(data).await,
            Some(DHCP_MSG_TYPE_RELEASE) => self.handle_release(data).await,
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

        let offered_ip = match self.allocate_ip(&mac, requested_ip, true, true).await {
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

        // A DISCOVER comes from a client with no address, so this is normally the broadcast —
        // but a relayed one must go back to the relay, or it never reaches the client.
        let dest = Self::reply_destination(data);
        match socket.send_to(&reply, dest).await {
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

    /// Where a reply for `data` must be sent (RFC 2131 §4.1).
    ///
    /// Everything used to go to the limited broadcast address. That is right for a client that
    /// has no address yet, and wrong for the two cases below — and on a shared segment it also
    /// means every reply is seen by every host.
    ///
    ///   * `giaddr` non-zero: the request came through a RELAY, and the reply belongs to the
    ///     relay's SERVER port so it can be forwarded back down. Broadcasting instead simply
    ///     never reached a client on the far side of the relay — DHCP through a relay could
    ///     not work at all.
    ///   * `ciaddr` non-zero with the BROADCAST flag clear: a RENEWING client already has the
    ///     address and asked to be answered directly.
    ///
    /// (Audit 2026-08-01, §12.)
    fn reply_destination(data: &[u8]) -> std::net::SocketAddr {
        let broadcast = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
            DHCP_CLIENT_PORT,
        );
        if data.len() < 44 {
            return broadcast;
        }
        let giaddr = Ipv4Addr::new(data[24], data[25], data[26], data[27]);
        // Relay replies go to the relay — but only to a PLAUSIBLE one.
        //
        // `giaddr` is attacker-chosen: it is a field of an unauthenticated packet, and the
        // reply was sent wherever it pointed. That makes the server a reflector — a
        // DHCPDISCOVER with `giaddr` = victim produces server-port traffic aimed at the
        // victim from OUR address, with the source hidden. Amplification is poor (~1.3x), so
        // the value is anonymisation rather than volume, but there is no reason to offer it.
        //
        // A real relay is on a network this server can plausibly serve; a public address
        // never is. Restrict to private / link-local / loopback and drop the rest back to
        // broadcast, which is the correct answer for a client with no address anyway.
        // (Audit 2026-08-04.)
        if !giaddr.is_unspecified() {
            if giaddr.is_private() || giaddr.is_link_local() || giaddr.is_loopback() {
                return std::net::SocketAddr::new(std::net::IpAddr::V4(giaddr), DHCP_SERVER_PORT);
            }
            log::warn!(
                "DHCP: ignoring giaddr {giaddr} — not a private/link-local relay address; \
                 answering by broadcast instead (a public giaddr would make this server a \
                 reflector)"
            );
        }
        // flags (bytes 10..12), high bit = BROADCAST.
        let wants_broadcast = data[10] & 0x80 != 0;
        let ciaddr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        if !wants_broadcast && !ciaddr.is_unspecified() {
            return std::net::SocketAddr::new(std::net::IpAddr::V4(ciaddr), DHCP_CLIENT_PORT);
        }
        broadcast
    }

    /// RFC 2131 requires a DHCPNAK to be broadcast unless it came through a relay.
    /// In particular, `ciaddr` must never turn a NAK into a unicast response.
    fn nak_destination(data: &[u8]) -> std::net::SocketAddr {
        let broadcast = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
            DHCP_CLIENT_PORT,
        );
        if data.len() < 28 {
            return broadcast;
        }
        let giaddr = Ipv4Addr::new(data[24], data[25], data[26], data[27]);
        if !giaddr.is_unspecified()
            && (giaddr.is_private() || giaddr.is_link_local() || giaddr.is_loopback())
        {
            return std::net::SocketAddr::new(std::net::IpAddr::V4(giaddr), DHCP_SERVER_PORT);
        }
        broadcast
    }

    /// True when Option 54 (Server Identifier) names a DIFFERENT server.
    ///
    /// A client in SELECTING state puts the server it chose in the DHCPREQUEST it broadcasts.
    /// Every other server on the segment must then stay SILENT — answering means NAKing a
    /// perfectly good lease another server just offered, which knocks the client back to
    /// DISCOVER and can loop as long as both servers keep replying. This proxy answered every
    /// request it saw, so on a shared network it actively broke other people's DHCP.
    /// (Audit 2026-08-01, §12.)
    fn addressed_to_other_server(data: &[u8], me: Ipv4Addr) -> bool {
        match Self::find_dhcp_option(data, DHCP_OPTION_SERVER_ID).and_then(|o| o.get(2..6)) {
            Some(b) => Ipv4Addr::new(b[0], b[1], b[2], b[3]) != me,
            None => false, // no Option 54: RENEWING/REBINDING, addressed to whoever answers
        }
    }

    async fn handle_request(&self, data: &[u8], socket: &UdpSocket) -> anyhow::Result<()> {
        let mac = MacAddr::from_bytes(&data[28..34]);
        // Not for us — say nothing at all. See `addressed_to_other_server`.
        if Self::addressed_to_other_server(data, self.server_ip) {
            log::debug!("DHCP: REQUEST selects another server, staying silent");
            return Ok(());
        }
        // Prefer Option 50 (Requested IP Address). If absent, fall back to ciaddr
        // (BOOTP header bytes 12..16), where a RENEWING/REBINDING client carries
        // its current address. Option 54 (Server Identifier) is NOT a source of
        // the requested address and must not be used here. A ciaddr of 0.0.0.0
        // (SELECTING with no Option 50) is treated as "no requested IP".
        let requested_ip = Self::find_dhcp_option(data, 50)
            .and_then(|opt| opt.get(2..6))
            .map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            .or_else(|| {
                let c = &data[12..16];
                let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
                (!ip.is_unspecified()).then_some(ip)
            });

        // Relay-aware, and unicast to a RENEWING client that asked for it.
        let destination = Self::reply_destination(data);

        // Never ACK an address just because the client asked for it. Run the
        // request through the real allocator (which honours this MAC's existing
        // lease and only hands out addresses inside our pool). ACK only when the
        // allocator agrees with the requested address; otherwise NAK so the
        // client restarts with DISCOVER. Previously the requested IP was echoed
        // straight into an ACK, letting a client claim any address it named.
        // REQUEST is exact: falling back would send a NAK while leaking the fallback lease.
        let granted = self.allocate_ip(&mac, requested_ip, false, false).await;
        match (requested_ip, granted) {
            (Some(req), Some(ip)) if ip == req => {
                let reply = self.build_reply(data, ip, DHCP_MSG_TYPE_ACK)?;
                socket.send_to(&reply, destination).await?;
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
                socket.send_to(&reply, Self::nak_destination(data)).await?;
            }
            (None, _) => {
                log::warn!("DHCP REQUEST without requested-IP option from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5]);
            }
        }

        Ok(())
    }
    async fn handle_release(&self, data: &[u8]) -> anyhow::Result<()> {
        if Self::addressed_to_other_server(data, self.server_ip) {
            return Ok(());
        }
        let mac = MacAddr::from_bytes(&data[28..34]);
        let ciaddr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        if ciaddr.is_unspecified() {
            log::debug!("DHCP RELEASE without ciaddr ignored");
            return Ok(());
        }
        self.release_client_address(&mac, ciaddr, false).await;
        Ok(())
    }

    async fn handle_decline(&self, data: &[u8]) -> anyhow::Result<()> {
        if Self::addressed_to_other_server(data, self.server_ip) {
            return Ok(());
        }
        let mac = MacAddr::from_bytes(&data[28..34]);
        let Some(address) = Self::find_dhcp_option(data, 50)
            .and_then(|opt| opt.get(2..6))
            .map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        else {
            log::debug!("DHCP DECLINE without requested address ignored");
            return Ok(());
        };
        self.release_client_address(&mac, address, true).await;
        Ok(())
    }

    async fn release_client_address(&self, mac: &MacAddr, address: Ipv4Addr, quarantine: bool) {
        const DECLINE_QUARANTINE_SECS: u64 = 600;
        let key = Self::lease_key(mac);
        let now = self.start_time.elapsed().as_secs();
        let mut leases = self.leases.write().await;
        let Some(slot) = leases.iter_mut().find(|slot| {
            slot.as_ref()
                .is_some_and(|lease| lease.mac.0 == mac.0 && lease.ip == address)
        }) else {
            log::warn!("DHCP: ignoring release/decline for unowned address {address}");
            return;
        };
        *slot = None;

        // Keep the lock order consistent with allocation: leases -> declined -> shared pool.
        let mut declined = self.declined.write().await;
        let mut pool = self.shared_pool.lock().await;
        if pool.get_ip_by_username(&key) == Some(address) {
            pool.release(&key);
        }
        if quarantine {
            declined.insert(address, now.saturating_add(DECLINE_QUARANTINE_SECS));
            log::warn!("DHCP: {address} declined; quarantined for {DECLINE_QUARANTINE_SECS}s");
        } else {
            log::info!("DHCP: released {address}");
        }
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
        reply[8..12].copy_from_slice(&request[8..12]); // secs, flags; ciaddr stays zero
                                                       // yiaddr stays 0.0.0.0
        reply[20..24].copy_from_slice(&self.server_ip.octets());
        reply[24..28].copy_from_slice(&request[24..28]); // giaddr
        reply[28..34].copy_from_slice(&request[28..34]); // client MAC
        reply[236] = 99;
        reply[237] = 130;
        reply[238] = 83;
        reply[239] = 99; // magic cookie

        let mut options = Vec::new();
        options.extend_from_slice(&[DHCP_OPTION_MSG_TYPE, 1, DHCP_MSG_TYPE_NAK]);
        options.extend_from_slice(&[DHCP_OPTION_SERVER_ID, 4]);
        options.extend_from_slice(&self.server_ip.octets());
        options.push(DHCP_OPTION_END);
        reply.extend_from_slice(&options);
        reply
    }

    /// Reservation held for an OFFER that has not been REQUESTed yet.
    ///
    /// RFC 2131 §3.1 has DISCOVER produce an offer and REQUEST commit it; this recorded the
    /// FULL `lease_time_secs` (default 86400) straight from DISCOVER. Since DISCOVER is
    /// unauthenticated and the only throttle keys on `chaddr` — four bytes out of the packet
    /// the sender writes — incrementing the MAC per packet walked past the limiter and burned
    /// one pool address per packet for a day each. A few hundred packets exhausted the window
    /// and no legitimate client could get a lease until the next day.
    ///
    /// A real client sends its REQUEST within seconds, so a short reservation costs nothing
    /// and bounds what an unauthenticated packet can hold. (Audit 2026-08-04.)
    const OFFER_RESERVATION_SECS: u64 = 30;

    fn lease_key(mac: &MacAddr) -> String {
        format!(
            "dhcp:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5]
        )
    }

    async fn reap_expired(&self) -> usize {
        self.reap_expired_at(self.start_time.elapsed().as_secs())
            .await
    }

    async fn reap_expired_at(&self, now_secs: u64) -> usize {
        let mut leases = self.leases.write().await;
        let mut expired_keys = Vec::new();
        for slot in leases.iter_mut() {
            if slot
                .as_ref()
                .is_some_and(|lease| now_secs >= lease.expires_at)
            {
                let lease = slot.take().expect("checked as Some");
                expired_keys.push(Self::lease_key(&lease.mac));
            }
        }
        self.declined
            .write()
            .await
            .retain(|_, expires_at| now_secs < *expires_at);
        if expired_keys.is_empty() {
            return 0;
        }
        let count = expired_keys.len();
        let mut pool = self.shared_pool.lock().await;
        for key in expired_keys {
            pool.release(&key);
        }
        count
    }

    /// `offer_only` = this came from a DISCOVER: reserve briefly instead of committing a
    /// full lease. The REQUEST that follows re-runs the allocator and promotes it.
    async fn allocate_ip(
        &self,
        mac: &MacAddr,
        preferred: Option<Ipv4Addr>,
        offer_only: bool,
        allow_fallback: bool,
    ) -> Option<Ipv4Addr> {
        let hold_secs = if offer_only {
            Self::OFFER_RESERVATION_SECS
        } else {
            self.lease_time_secs as u64
        };
        let mac_str = Self::lease_key(mac);
        let now_secs = self.start_time.elapsed().as_secs();
        self.reap_expired_at(now_secs).await;
        let mut leases = self.leases.write().await;

        // Reuse this MAC's active lease — but only if the SHARED POOL still agrees it is ours.
        //
        // The lease table and the pool are two records of the same fact, and only one of them
        // was consulted here. The VPN static-IP path calls `IpPool::allocate_fixed`, which
        // evicts any other holder of that address from `user_allocations` — and knows nothing
        // about `self.leases`. So after a VPN user with `static_ip = <addr in the DHCP window>`
        // connected, the pool said the address belonged to them while this table still said it
        // belonged to the MAC, and the next DHCPREQUEST from that MAC got an ACK for it. Two
        // hosts, one address: ingress goes to whoever holds `sessions.by_ip`, ARP fights in TAP
        // mode, and the traffic accounting lands on the wrong user. `pool.release()` from the
        // reaper or a VPN teardown produced the same divergence from the other side.
        //
        // Cross-checking the pool makes the pool authoritative and turns a stale lease into a
        // fresh allocation instead of a collision. (Audit 2026-08-04.)
        for slot in leases.iter_mut() {
            let Some(lease) = slot else { continue };
            if lease.mac.0 != mac.0 || now_secs >= lease.expires_at {
                continue;
            }
            let still_ours = {
                let pool = self.shared_pool.lock().await;
                pool.get_ip_by_username(&mac_str) == Some(lease.ip)
            };
            if still_ours {
                if !allow_fallback && preferred != Some(lease.ip) {
                    return None;
                }
                let requested_expiry = now_secs.saturating_add(hold_secs);
                // A repeated DISCOVER must not shorten an already committed lease to the
                // 30-second offer hold; REQUEST promotes an offer and renews a full lease.
                lease.expires_at = if offer_only {
                    lease.expires_at.max(requested_expiry)
                } else {
                    requested_expiry
                };
                return Some(lease.ip);
            }
            log::info!(
                "DHCP: lease for {} is stale — the shared pool no longer records it for this \
                 MAC (a VPN static IP or a release took it). Re-allocating.",
                lease.ip
            );
            *slot = None;
            break;
        }

        // Try to honour the preferred IP if it falls in our DHCP range and is available
        let quarantined: HashSet<u32> = self
            .declined
            .read()
            .await
            .keys()
            .copied()
            .map(u32_from_ip)
            .collect();
        if let Some(pref) = preferred {
            let pref_u32 = u32_from_ip(pref);
            if pref_u32 >= self.pool_start
                && pref_u32 <= self.pool_end
                && !quarantined.contains(&pref_u32)
            {
                let idx = (pref_u32 - self.pool_start) as usize;
                if idx < leases.len() && leases[idx].is_none() {
                    let mut pool = self.shared_pool.lock().await;
                    // Ask for the requested address SPECIFICALLY. `allocate_fixed` returns it
                    // or nothing, so a client re-requesting the address it already had keeps
                    // it; anything else falls through to the windowed dynamic path below,
                    // which is where the shared allocator is consulted at all.
                    // `allocate_fixed_unclaimed`, NOT `allocate_fixed`. The latter EVICTS the
                    // current holder and leaves it to the caller to tear that session down —
                    // authority the static-IP path has and DHCP does not. A client naming an
                    // address in Option 50 would otherwise take it straight off a live VPN
                    // session, which kept using the same IP: two peers on one address.
                    // (Audit 2026-08-02, §1.)
                    if pool.get_ip_by_username(&mac_str).is_none()
                        && pool.allocate_fixed_unclaimed(&mac_str, pref).is_some()
                    {
                        leases[idx] = Some(DhcpLease {
                            ip: pref,
                            mac: *mac,
                            expires_at: now_secs.saturating_add(hold_secs),
                        });
                        return Some(pref);
                    }
                }
            }
        }

        // Dynamic allocation, constrained to the DHCP window.
        if !allow_fallback {
            return None;
        }

        //
        // This used to call the plain `pool.allocate()` and then reject anything outside the
        // window — which did not just waste the call, it DEADLOCKED the service. The rejected
        // address went back through `release`, `release` pushes onto the pool's `freed` list,
        // and `freed` is exactly what the next `allocate` pops FIRST. Every DHCPDISCOVER
        // therefore received the same out-of-window address, released it again, and reported
        // "no IP available" while the configured window sat entirely free. Asking the pool for
        // an address IN the window removes the reject-and-retry loop altogether.
        // (Audit 2026-08-01, §1.)
        let mut pool = self.shared_pool.lock().await;
        if let Some(allocated) =
            pool.allocate_in_range_excluding(&mac_str, self.pool_start, self.pool_end, &quarantined)
        {
            let alloc_u32 = u32_from_ip(allocated);
            let alloc_idx = (alloc_u32 - self.pool_start) as usize;
            if alloc_idx < leases.len() {
                leases[alloc_idx] = Some(DhcpLease {
                    ip: allocated,
                    mac: *mac,
                    expires_at: now_secs.saturating_add(hold_secs),
                });
                return Some(allocated);
            }
            // The window and the lease table are built from the same bounds, so this cannot
            // happen — but handing out an address with no lease slot would leak it forever
            // (nothing could ever expire it), so give it back rather than trust the invariant.
            log::warn!("DHCP: {allocated} has no lease slot, releasing");
            pool.release(&mac_str);
        }

        None
    }

    fn build_reply(
        &self,
        request: &[u8],
        offered_ip: Ipv4Addr,
        msg_type: u8,
    ) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            self.dns_servers.len() <= 63,
            "DHCP supports at most 63 IPv4 DNS servers"
        );
        let mut reply = vec![0u8; 240];

        reply[0] = BOOTP_REPLY;
        reply[1] = 1; // hardware type: Ethernet
        reply[2] = 6; // hardware address length
        reply[3] = 0; // hops

        reply[4..8].copy_from_slice(&request[4..8]); // xid
        reply[8..12].copy_from_slice(&request[8..12]); // secs, flags; ciaddr stays zero

        reply[16..20].copy_from_slice(&offered_ip.octets());
        reply[20..24].copy_from_slice(&self.server_ip.octets());
        reply[24..28].copy_from_slice(&request[24..28]); // giaddr
        reply[28..34].copy_from_slice(&request[28..34]); // client MAC

        reply[236] = 99;
        reply[237] = 130;
        reply[238] = 83;
        reply[239] = 99; // magic cookie

        let mut options = Vec::new();
        options.extend_from_slice(&[DHCP_OPTION_MSG_TYPE, 1, msg_type]);
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

        // Widen before multiplying: saturation would place T2 before T1 on long leases.
        let t2 = (u64::from(self.lease_time_secs) * 3 / 4) as u32;
        options.extend_from_slice(&[DHCP_OPTION_REBINDING_TIME, 4]);
        options.extend_from_slice(&t2.to_be_bytes());

        options.extend_from_slice(&[DHCP_OPTION_SERVER_ID, 4]);
        options.extend_from_slice(&self.server_ip.octets());

        // Guard the u8 option-length: a domain_name > 255 B would truncate the length
        // byte and emit a malformed option; drop it rather than corrupt the packet.
        if !self.domain_name.is_empty() && self.domain_name.len() <= 255 {
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

    /// Visit complete TLVs in wire order, including RFC 2132 option overload.
    /// Only fields explicitly selected by option 52 are interpreted as options.
    fn visit_dhcp_options<'a>(
        data: &'a [u8],
        mut visitor: impl FnMut(&'a [u8]) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(data.len() >= 240, "DHCP packet too short");
        anyhow::ensure!(data[236..240] == [99, 130, 83, 99], "invalid DHCP cookie");
        fn walk<'a>(
            region: &'a [u8],
            visitor: &mut impl FnMut(&'a [u8]) -> anyhow::Result<()>,
        ) -> anyhow::Result<()> {
            let mut pos = 0;
            while pos < region.len() {
                match region[pos] {
                    0 => {
                        pos += 1;
                        continue;
                    }
                    DHCP_OPTION_END => return Ok(()),
                    _ => {}
                }
                let len = *region
                    .get(pos + 1)
                    .ok_or_else(|| anyhow::anyhow!("truncated DHCP option length"))?
                    as usize;
                let end = pos + 2 + len;
                let option = region
                    .get(pos..end)
                    .ok_or_else(|| anyhow::anyhow!("truncated DHCP option value"))?;
                visitor(option)?;
                pos = end;
            }
            anyhow::bail!("DHCP options missing END")
        }
        let mut overload = None;
        walk(&data[240..], &mut |option: &'a [u8]| {
            if option[0] == 52 {
                anyhow::ensure!(
                    option.len() == 3 && (1..=3).contains(&option[2]),
                    "invalid DHCP option overload"
                );
                anyhow::ensure!(
                    overload.replace(option[2]).is_none(),
                    "duplicate DHCP option overload"
                );
            }
            visitor(option)
        })?;
        let overload = overload.unwrap_or(0);
        for (mask, region) in [(1, &data[108..236]), (2, &data[44..108])] {
            if overload & mask != 0 {
                walk(region, &mut |option: &'a [u8]| {
                    anyhow::ensure!(option[0] != 52, "nested DHCP option overload");
                    visitor(option)
                })?;
            }
        }
        Ok(())
    }

    /// Validate before rate accounting or allocation, including options after message type.
    fn validate_request(data: &[u8]) -> anyhow::Result<()> {
        anyhow::ensure!(data.len() >= 240, "DHCP packet too short");
        anyhow::ensure!(
            data[..3] == [1, 1, 6],
            "DHCP requires Ethernet BOOTREQUEST with six-byte address"
        );
        let mac = &data[28..34];
        anyhow::ensure!(
            mac[0] & 1 == 0 && mac.iter().any(|&b| b != 0),
            "invalid DHCP client MAC"
        );
        let mut seen = [false; 3];
        Self::visit_dhcp_options(data, |option| {
            let (slot, len) = match option[0] {
                DHCP_OPTION_MSG_TYPE => (0, 1),
                50 => (1, 4),
                DHCP_OPTION_SERVER_ID => (2, 4),
                _ => return Ok(()),
            };
            anyhow::ensure!(option[1] == len, "invalid DHCP control option length");
            anyhow::ensure!(!seen[slot], "duplicate DHCP control option");
            seen[slot] = true;
            Ok(())
        })?;
        anyhow::ensure!(seen[0], "DHCP message type missing");
        Ok(())
    }

    fn find_dhcp_option(data: &[u8], option_code: u8) -> Option<&[u8]> {
        let mut found = None;
        Self::visit_dhcp_options(data, |option| {
            if option[0] == option_code && found.is_none() {
                found = Some(option);
            }
            Ok(())
        })
        .ok()?;
        found
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

    /// A DHCPREQUEST that names ANOTHER server must be ignored, not answered.
    ///
    /// A client in SELECTING state puts the server it chose in Option 54. Answering anyway
    /// means NAKing a lease another server just offered, which knocks the client back to
    /// DISCOVER and can loop for as long as both servers keep replying — so on a shared
    /// segment this proxy actively broke other people's DHCP. No Option 54 at all is a
    /// RENEWING/REBINDING client, addressed to whoever can answer. (Audit 2026-08-01, §12.)
    #[test]
    fn a_request_selecting_another_server_is_ignored() {
        let me = Ipv4Addr::new(10, 8, 0, 1);
        fn with_server_id(ip: [u8; 4]) -> Vec<u8> {
            let mut d = vec![0u8; 240];
            d[236..240].copy_from_slice(&[99, 130, 83, 99]);
            d.extend_from_slice(&[53, 1, 3]); // REQUEST
            d.extend_from_slice(&[54, 4, ip[0], ip[1], ip[2], ip[3]]);
            d.push(255);
            d
        }
        assert!(DhcpServer::addressed_to_other_server(
            &with_server_id([10, 8, 0, 99]),
            me
        ));
        assert!(!DhcpServer::addressed_to_other_server(
            &with_server_id([10, 8, 0, 1]),
            me
        ));
        // No Option 54 — a renewing client, ours to answer.
        let mut renew = dhcp_base();
        renew.extend_from_slice(&[53, 1, 3]);
        renew.push(255);
        assert!(!DhcpServer::addressed_to_other_server(&renew, me));
    }

    /// Replies go to the relay, or unicast to a renewing client, or broadcast — in that order.
    ///
    /// Everything used to be broadcast, which meant DHCP through a relay could not work at all
    /// (the reply never crossed back) and every renewal was seen by every host on the segment.
    /// (Audit 2026-08-01, §12.)
    #[test]
    fn replies_are_addressed_per_rfc_2131() {
        let bcast =
            std::net::SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::BROADCAST), DHCP_CLIENT_PORT);

        // A fresh DISCOVER: no ciaddr, no giaddr — broadcast.
        assert_eq!(DhcpServer::reply_destination(&dhcp_base()), bcast);

        // Relayed: back to the relay's SERVER port, whatever else the packet says.
        let mut relayed = dhcp_base();
        relayed[24..28].copy_from_slice(&[10, 9, 0, 1]);
        relayed[12..16].copy_from_slice(&[10, 8, 0, 5]); // ciaddr must not win over giaddr
        assert_eq!(
            DhcpServer::reply_destination(&relayed),
            std::net::SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1)), 67)
        );

        // Renewing with the broadcast flag CLEAR: straight to the client.
        let mut renew = dhcp_base();
        renew[12..16].copy_from_slice(&[10, 8, 0, 5]);
        assert_eq!(
            DhcpServer::reply_destination(&renew),
            std::net::SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 8, 0, 5)), 68)
        );

        // ...but a client that SET the broadcast flag is honoured, address or not.
        let mut wants_bcast = renew.clone();
        wants_bcast[10] = 0x80;
        assert_eq!(DhcpServer::reply_destination(&wants_bcast), bcast);

        // A runt packet must not index out of bounds.
        assert_eq!(DhcpServer::reply_destination(&[0u8; 12]), bcast);
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

    fn test_server(lease_time_secs: u32) -> DhcpServer {
        let config = crate::config::server::PoolConfig {
            cidr: "10.9.0.0/24".into(),
            ..Default::default()
        };
        let pool = IpPool::new_with_tun(&config, Ipv4Addr::new(10, 9, 0, 1)).unwrap();
        DhcpServer::new(
            Ipv4Addr::new(10, 9, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 9, 0, 1),
            vec![],
            "qeli.test".into(),
            lease_time_secs,
            Ipv4Addr::new(10, 9, 0, 100),
            Ipv4Addr::new(10, 9, 0, 110),
            Arc::new(Mutex::new(pool)),
        )
    }

    #[tokio::test]
    async fn request_promotes_offer_and_renews_existing_lease() {
        let server = test_server(3_600);
        let mac = MacAddr([0x02, 0, 0, 0, 0, 1]);
        let offered = server.allocate_ip(&mac, None, true, true).await.unwrap();
        let offered_expiry = server
            .leases
            .read()
            .await
            .iter()
            .flatten()
            .find(|lease| lease.mac.0 == mac.0)
            .unwrap()
            .expires_at;
        assert_eq!(offered_expiry, DhcpServer::OFFER_RESERVATION_SECS);

        assert_eq!(
            server.allocate_ip(&mac, Some(offered), false, false).await,
            Some(offered)
        );
        let committed_expiry = server
            .leases
            .read()
            .await
            .iter()
            .flatten()
            .find(|lease| lease.mac.0 == mac.0)
            .unwrap()
            .expires_at;
        assert_eq!(committed_expiry, 3_600);

        // A later DISCOVER from the same client cannot shorten the committed lease.
        assert_eq!(
            server.allocate_ip(&mac, None, true, true).await,
            Some(offered)
        );
        let after_discover = server
            .leases
            .read()
            .await
            .iter()
            .flatten()
            .find(|lease| lease.mac.0 == mac.0)
            .unwrap()
            .expires_at;
        assert_eq!(after_discover, committed_expiry);
    }

    #[tokio::test]
    async fn periodic_reaper_releases_expired_shared_pool_reservation() {
        let server = test_server(3_600);
        let mac = MacAddr([0x02, 0, 0, 0, 0, 2]);
        let offered = server.allocate_ip(&mac, None, true, true).await.unwrap();
        let key = DhcpServer::lease_key(&mac);
        assert_eq!(
            server.shared_pool.lock().await.get_ip_by_username(&key),
            Some(offered)
        );

        assert_eq!(
            server
                .reap_expired_at(DhcpServer::OFFER_RESERVATION_SECS)
                .await,
            1
        );
        assert_eq!(
            server.shared_pool.lock().await.get_ip_by_username(&key),
            None
        );
        assert!(server.leases.read().await.iter().all(Option::is_none));
    }
    #[tokio::test]
    async fn exact_request_rejection_does_not_consume_a_fallback_lease() {
        let server = test_server(3_600);
        let holder = MacAddr([0x02, 0, 0, 0, 0, 3]);
        let requester = MacAddr([0x02, 0, 0, 0, 0, 4]);
        let held = Ipv4Addr::new(10, 9, 0, 100);
        assert_eq!(
            server.allocate_ip(&holder, Some(held), true, true).await,
            Some(held)
        );

        assert_eq!(
            server
                .allocate_ip(&requester, Some(held), false, false)
                .await,
            None
        );
        let requester_key = DhcpServer::lease_key(&requester);
        assert_eq!(
            server
                .shared_pool
                .lock()
                .await
                .get_ip_by_username(&requester_key),
            None
        );
        assert_eq!(server.leases.read().await.iter().flatten().count(), 1);

        assert_eq!(
            server
                .allocate_ip(&requester, Some(Ipv4Addr::new(192, 0, 2, 10)), false, false,)
                .await,
            None
        );
        assert_eq!(server.leases.read().await.iter().flatten().count(), 1);
    }

    #[tokio::test]
    async fn release_returns_address_and_decline_quarantines_it() {
        let server = test_server(3_600);
        let first = MacAddr([0x02, 0, 0, 0, 0, 5]);
        let second = MacAddr([0x02, 0, 0, 0, 0, 6]);
        let third = MacAddr([0x02, 0, 0, 0, 0, 7]);

        let released = server.allocate_ip(&first, None, false, true).await.unwrap();
        server.release_client_address(&first, released, false).await;
        assert_eq!(
            server.allocate_ip(&second, None, false, true).await,
            Some(released)
        );

        server.release_client_address(&second, released, true).await;
        let replacement = server.allocate_ip(&third, None, false, true).await.unwrap();
        assert_ne!(replacement, released);
        assert!(server.declined.read().await.contains_key(&released));

        server.reap_expired_at(600).await;
        assert!(!server.declined.read().await.contains_key(&released));
    }

    #[test]
    fn replies_preserve_bootp_routing_fields_and_naks_broadcast() {
        let server = test_server(3_600);
        let mut request = dhcp_base();
        request[8..10].copy_from_slice(&[0x12, 0x34]);
        request[10..12].copy_from_slice(&[0x80, 0x01]);
        request[12..16].copy_from_slice(&[10, 9, 0, 100]);
        request[24..28].copy_from_slice(&[10, 9, 0, 2]);

        let reply = server
            .build_reply(&request, Ipv4Addr::new(10, 9, 0, 100), DHCP_MSG_TYPE_ACK)
            .unwrap();
        let nak = server.build_nak(&request);
        assert_eq!(&reply[8..12], &request[8..12]);
        assert_eq!(&reply[12..16], &[0, 0, 0, 0]);
        assert_eq!(&reply[24..28], &request[24..28]);
        assert_eq!(&nak[8..12], &request[8..12]);
        assert_eq!(&nak[12..16], &[0, 0, 0, 0]);
        assert_eq!(&nak[24..28], &request[24..28]);
        assert_eq!(
            DhcpServer::nak_destination(&request),
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2)),
                DHCP_SERVER_PORT,
            )
        );

        request[24..28].fill(0);
        assert_eq!(
            DhcpServer::nak_destination(&request),
            std::net::SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::BROADCAST), DHCP_CLIENT_PORT,)
        );
    }
    fn ethernet_request(options: &[u8]) -> Vec<u8> {
        let mut data = dhcp_base();
        data[..3].copy_from_slice(&[1, 1, 6]);
        data[28..34].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        data.extend_from_slice(options);
        data
    }

    #[test]
    fn rate_limit_distinguishes_the_complete_client_mac() {
        let first = ethernet_request(&[53, 1, 1, 255]);
        let mut second = first.clone();
        second[33] = 2;
        let first_key = DhcpServer::client_mac_key(&first).unwrap();
        let second_key = DhcpServer::client_mac_key(&second).unwrap();
        assert_ne!(first_key, second_key);
        let mut limiter = crate::server::RateLimiter::new(60, 10);
        for _ in 0..60 {
            assert!(limiter.check_and_record(first_key));
        }
        assert!(!limiter.check_and_record(first_key));
        assert!(limiter.check_and_record(second_key));
    }

    #[tokio::test]
    async fn malformed_requests_cannot_reserve_addresses() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let src = "127.0.0.1:68".parse().unwrap();
        let mut packets = vec![
            ethernet_request(&[53, 2, 1, 0, 255]),
            ethernet_request(&[53, 1, 1, 50, 3, 10, 9, 0, 255]),
            ethernet_request(&[53, 1, 1, 54, 5, 10, 9, 0, 1, 0, 255]),
            ethernet_request(&[53, 1, 1, 53, 1, 3, 255]),
            ethernet_request(&[53, 1, 1, 200, 10, 1]),
            ethernet_request(&[53, 1, 1]),
        ];
        for (offset, value) in [(1, 2), (2, 0), (2, 16), (28, 3)] {
            let mut data = ethernet_request(&[53, 1, 1, 255]);
            data[offset] = value;
            packets.push(data);
        }
        let mut zero_mac = ethernet_request(&[53, 1, 1, 255]);
        zero_mac[28..34].fill(0);
        packets.push(zero_mac);
        for (index, data) in packets.iter().enumerate() {
            let server = test_server(3600);
            assert!(
                server.handle_packet(data, &socket, &src).await.is_err(),
                "case {index}"
            );
            assert!(
                server.leases.read().await.iter().all(Option::is_none),
                "case {index}"
            );
            let mac = MacAddr::from_bytes(&data[28..34]);
            assert!(server
                .shared_pool
                .lock()
                .await
                .get_ip_by_username(&DhcpServer::lease_key(&mac))
                .is_none());
        }
    }

    #[test]
    fn rebinding_timer_preserves_large_lease_arithmetic() {
        for lease in [3600, u32::MAX / 3 + 1, u32::MAX - 1, u32::MAX] {
            let server = test_server(lease);
            let reply = server
                .build_reply(
                    &dhcp_base(),
                    Ipv4Addr::new(10, 9, 0, 100),
                    DHCP_MSG_TYPE_ACK,
                )
                .unwrap();
            let t1 = u32::from_be_bytes(
                DhcpServer::find_dhcp_option(&reply, 58).unwrap()[2..6]
                    .try_into()
                    .unwrap(),
            );
            let t2 = u32::from_be_bytes(
                DhcpServer::find_dhcp_option(&reply, 59).unwrap()[2..6]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(u64::from(t2), u64::from(lease) * 3 / 4);
            assert!(t1 < t2 && t2 < lease);
        }
    }

    #[test]
    fn dns_option_length_never_wraps() {
        let mut server = test_server(3600);
        server.dns_servers = vec![Ipv4Addr::new(10, 9, 0, 1); 63];
        let reply = server
            .build_reply(
                &dhcp_base(),
                Ipv4Addr::new(10, 9, 0, 100),
                DHCP_MSG_TYPE_ACK,
            )
            .unwrap();
        assert_eq!(DhcpServer::find_dhcp_option(&reply, 6).unwrap().len(), 254);
        assert!(DhcpServer::find_dhcp_option(&reply, 51).is_some());
        server.dns_servers.push(Ipv4Addr::new(10, 9, 0, 2));
        assert!(server
            .build_reply(
                &dhcp_base(),
                Ipv4Addr::new(10, 9, 0, 100),
                DHCP_MSG_TYPE_ACK
            )
            .is_err());
    }

    #[test]
    fn overload_fields_are_validated_and_used_in_wire_order() {
        let mut data = ethernet_request(&[53, 1, 3, 52, 1, 3, 255]);
        data[108..115].copy_from_slice(&[50, 4, 10, 9, 0, 100, 255]);
        data[44..51].copy_from_slice(&[54, 4, 10, 9, 0, 1, 255]);
        DhcpServer::validate_request(&data).unwrap();
        assert_eq!(
            DhcpServer::find_dhcp_option(&data, 50).unwrap(),
            &[50, 4, 10, 9, 0, 100]
        );
        assert_eq!(
            DhcpServer::find_dhcp_option(&data, 54).unwrap(),
            &[54, 4, 10, 9, 0, 1]
        );
        data[44..48].copy_from_slice(&[53, 1, 3, 255]);
        assert!(DhcpServer::validate_request(&data).is_err());
        data[44..48].copy_from_slice(&[200, 100, 0, 255]);
        assert!(DhcpServer::validate_request(&data).is_err());
        assert!(DhcpServer::find_dhcp_option(&data, 50).is_none());
    }

    #[tokio::test]
    async fn exhausted_and_empty_pools_do_not_evict_vpn_or_underflow() {
        let server = test_server(3600);
        let reserved = Ipv4Addr::new(10, 9, 0, 100);
        assert_eq!(
            server
                .shared_pool
                .lock()
                .await
                .allocate_fixed_unclaimed("vpn-session", reserved),
            Some(reserved)
        );
        for suffix in 1..=10 {
            let mac = MacAddr([2, 0, 0, 0, 0, suffix]);
            assert!(server.allocate_ip(&mac, None, true, true).await.is_some());
        }
        assert!(server
            .allocate_ip(&MacAddr([2, 0, 0, 0, 0, 11]), None, true, true)
            .await
            .is_none());
        assert_eq!(
            server
                .shared_pool
                .lock()
                .await
                .get_ip_by_username("vpn-session"),
            Some(reserved)
        );
        assert_eq!(server.reap_expired_at(30).await, 10);
        assert!(server
            .allocate_ip(&MacAddr([2, 0, 0, 0, 0, 11]), None, true, true)
            .await
            .is_some());
        let mut empty = test_server(3600);
        empty.pool_end = empty.pool_start - 1;
        *empty.leases.get_mut() = Vec::new();
        assert!(empty
            .allocate_ip(&MacAddr([2, 0, 0, 0, 0, 12]), None, true, true)
            .await
            .is_none());
    }
}
