use crate::server::pool::{u32_from_ip, IpPool};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};

#[allow(dead_code)] // standard DHCP port constant kept for reference
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

const BOOTP_REPLY: u8 = 2;
const DHCP_OPTION_MSG_TYPE: u8 = 53;
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
    /// Per-source-IP rate limit on inbound DHCP packets. DHCP is unauthenticated,
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
            start_time: std::time::Instant::now(),
            shared_pool,
            // 60 packets per 10s window per source IP: comfortably above a
            // legitimate DISCOVER/REQUEST handshake (a few packets) while capping
            // an unauthenticated flood from any single address.
            recv_limiter: Mutex::new(crate::server::RateLimiter::new(60, 10)),
        }
    }

    /// A rate-limiter key derived from the BOOTP client hardware address (`chaddr`, offset 28),
    /// packed into an IPv4 address because that is what the shared limiter is keyed on.
    ///
    /// The first four MAC bytes are the OUI plus one — enough to separate machines on a LAN,
    /// and the limiter is a flood guard rather than an access control. `None` for a packet too
    /// short to contain a `chaddr` or with an all-zero one, so the caller falls back to the
    /// source IP.
    fn client_mac_key(data: &[u8]) -> Option<std::net::IpAddr> {
        let mac = data.get(28..34)?;
        if mac.iter().all(|&b| b == 0) {
            return None;
        }
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            mac[0], mac[1], mac[2], mac[3],
        )))
    }

    /// Bind the DHCP socket, SEPARATELY from serving on it.
    ///
    /// The bind used to happen inside the detached serve task, so a taken port, a bad address
    /// or a refused `set_broadcast` surfaced as one log line while the profile came up and was
    /// counted as running — clients then connected and never got a lease, with the cause buried
    /// in the journal. Binding here lets the caller fail the profile BEFORE it claims to serve
    /// DHCP. Same split as the DNS proxy, for the same reason. (Audit 2026-08-01, §2.)
    pub async fn bind(bind_addr: &str) -> anyhow::Result<UdpSocket> {
        // DHCP is unauthenticated; a listen on a non-private (or wildcard) address
        // exposes the pool to anyone who can reach the port. Warn loudly so an
        // operator who did not intend a public DHCP surface notices at startup.
        let listen_ip = bind_addr
            .rsplit_once(':')
            .map_or(bind_addr, |(host, _)| host);
        if let Ok(ip) = listen_ip.parse::<Ipv4Addr>() {
            if ip.is_unspecified() || !(ip.is_private() || ip.is_loopback() || ip.is_link_local()) {
                log::warn!(
                    "DHCP listening on non-private address {} — unauthenticated clients on this network can request leases; bind to a private/internal address unless this is intended",
                    ip
                );
            }
        }
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

        let mut buf = vec![0u8; 1500];

        loop {
            log::trace!("DHCP waiting for packet...");
            let (n, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    // A transient recv error (e.g. ICMP port-unreachable surfaced on the
                    // UDP socket) must not kill the whole DHCP service for the profile.
                    log::warn!("DHCP recv error: {} — continuing", e);
                    continue;
                }
            };
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
                log::warn!("DHCP: rate limit exceeded for {}, dropping packet", _src);
                return Ok(());
            }
        }
        if data.len() < 240 {
            log::warn!("DHCP: packet too short ({} bytes)", data.len());
            return Err(anyhow::anyhow!("packet too short"));
        }
        if data[0] != 1 {
            log::warn!("DHCP: not BOOTREQUEST (op={})", data[0]);
            return Err(anyhow::anyhow!("not a BOOTREQUEST"));
        }

        let msg_type =
            Self::find_dhcp_option(data, DHCP_OPTION_MSG_TYPE).and_then(|opt| opt.get(2).copied());
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

        let offered_ip = match self.allocate_ip(&mac, requested_ip, true).await {
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
        let broadcast = Self::reply_destination(data);

        // Never ACK an address just because the client asked for it. Run the
        // request through the real allocator (which honours this MAC's existing
        // lease and only hands out addresses inside our pool). ACK only when the
        // allocator agrees with the requested address; otherwise NAK so the
        // client restarts with DISCOVER. Previously the requested IP was echoed
        // straight into an ACK, letting a client claim any address it named.
        let granted = self.allocate_ip(&mac, requested_ip, false).await;
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

    /// `offer_only` = this came from a DISCOVER: reserve briefly instead of committing a
    /// full lease. The REQUEST that follows re-runs the allocator and promotes it.
    async fn allocate_ip(
        &self,
        mac: &MacAddr,
        preferred: Option<Ipv4Addr>,
        offer_only: bool,
    ) -> Option<Ipv4Addr> {
        let hold_secs = if offer_only {
            Self::OFFER_RESERVATION_SECS
        } else {
            self.lease_time_secs as u64
        };
        let mac_str = format!(
            "dhcp:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5]
        );

        let mut leases = self.leases.write().await;
        let now_secs = self.start_time.elapsed().as_secs();

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
            if lease.mac.0 != mac.0 || now_secs > lease.expires_at {
                continue;
            }
            let still_ours = {
                let pool = self.shared_pool.lock().await;
                pool.get_ip_by_username(&mac_str) == Some(lease.ip)
            };
            if still_ours {
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
                            expires_at: now_secs + hold_secs,
                        });
                        return Some(pref);
                    }
                }
            }
        }

        // Dynamic allocation, constrained to the DHCP window.
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
        if let Some(allocated) = pool.allocate_in_range(&mac_str, self.pool_start, self.pool_end) {
            let alloc_u32 = u32_from_ip(allocated);
            let alloc_idx = (alloc_u32 - self.pool_start) as usize;
            if alloc_idx < leases.len() {
                leases[alloc_idx] = Some(DhcpLease {
                    ip: allocated,
                    mac: *mac,
                    expires_at: now_secs + hold_secs,
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

        // saturating_mul: `lease * 3` overflows u32 for a lease > ~1.43e9 s (wraps in
        // release, panics in debug) on a pathological config value.
        let t2 = self.lease_time_secs.saturating_mul(3) / 4;
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
}
