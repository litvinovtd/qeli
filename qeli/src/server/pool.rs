use crate::config::server::PoolConfig;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

#[allow(dead_code)] // gateway/subnet_mask retained for DHCP/reporting use
pub struct IpPool {
    pub gateway: Ipv4Addr,
    pub subnet_mask: u8,
    pub start_ip: u32,
    pub end_ip: u32,
    pub excluded: HashSet<u32>,
    pub lease_time_secs: u64,
    static_reservations: Vec<(String, u32)>,
    allocated: HashSet<u32>,
    user_allocations: HashMap<String, u32>,
    /// Reuse stack of released addresses — popped before scanning fresh ground, so
    /// a release/allocate churn stays O(1) and the pool stays compact.
    freed: Vec<u32>,
    /// Next never-yet-tried address (u64 so an `end_ip` of 255.255.255.254 can't
    /// overflow). Replaces the old O(range) rescan-from-`start_ip` on every
    /// allocate; released addresses come back via `freed`, not by rewinding this.
    cursor: u64,
}

impl IpPool {
    pub fn new(config: &PoolConfig) -> anyhow::Result<Self> {
        let (network, subnet_mask) = parse_cidr(&config.cidr)?;

        if subnet_mask > 30 {
            anyhow::bail!(
                "subnet mask /{} is too small for IP pool (minimum /30)",
                subnet_mask
            );
        }

        let total_ips = 1u32
            .checked_shl((32 - subnet_mask) as u32)
            .ok_or_else(|| anyhow::anyhow!("invalid subnet mask"))?;

        let start_ip = network | 2;
        let end_ip = network | total_ips.saturating_sub(2);

        let mut excluded = HashSet::new();
        excluded.insert(network);
        excluded.insert(network | (total_ips - 1));

        for ip_str in &config.exclude {
            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                excluded.insert(u32_from_ip(ip));
            }
        }

        excluded.insert(network | 1);

        let mut static_reservations = Vec::new();
        for (username, ip_str) in &config.static_reservations {
            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                let ip_val = u32_from_ip(ip);
                excluded.insert(ip_val);
                static_reservations.push((username.clone(), ip_val));
            }
        }

        Ok(IpPool {
            gateway: ip_from_u32(network | 1),
            subnet_mask,
            start_ip,
            end_ip,
            excluded,
            lease_time_secs: config.lease_time_secs,
            static_reservations,
            allocated: HashSet::new(),
            user_allocations: HashMap::new(),
            freed: Vec::new(),
            cursor: start_ip as u64,
        })
    }

    pub fn allocate(&mut self, username: &str) -> Option<Ipv4Addr> {
        // Check if already allocated to this user
        if let Some(ip_val) = self.user_allocations.get(username) {
            return Some(ip_from_u32(*ip_val));
        }

        // Check static reservation
        for (uname, ip_val) in &self.static_reservations {
            if uname == username {
                self.allocated.insert(*ip_val);
                self.user_allocations.insert(username.to_string(), *ip_val);
                return Some(ip_from_u32(*ip_val));
            }
        }

        // Dynamic allocation: reuse a released address first (compact + O(1)), else
        // advance the cursor over never-tried ground.
        while let Some(ip_val) = self.freed.pop() {
            if !self.excluded.contains(&ip_val) && !self.allocated.contains(&ip_val) {
                self.allocated.insert(ip_val);
                self.user_allocations.insert(username.to_string(), ip_val);
                return Some(ip_from_u32(ip_val));
            }
        }
        while self.cursor <= self.end_ip as u64 {
            let ip_val = self.cursor as u32;
            self.cursor += 1;
            if !self.excluded.contains(&ip_val) && !self.allocated.contains(&ip_val) {
                self.allocated.insert(ip_val);
                self.user_allocations.insert(username.to_string(), ip_val);
                return Some(ip_from_u32(ip_val));
            }
        }
        None
    }

    pub fn release(&mut self, username: &str) {
        if let Some(ip_val) = self.user_allocations.remove(username) {
            self.allocated.remove(&ip_val);
            // Offer it back to the next allocate (re-checked against excluded/allocated
            // on pop, so a stale entry is harmless).
            self.freed.push(ip_val);
        }
    }

    /// Current lease for `username` (used by the DHCP allocator to reuse a lease).
    pub fn get_ip_by_username(&self, username: &str) -> Option<Ipv4Addr> {
        self.user_allocations.get(username).map(|&v| ip_from_u32(v))
    }
}

pub fn parse_cidr(cidr: &str) -> anyhow::Result<(u32, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("invalid CIDR: {}", cidr);
    }
    let ip: Ipv4Addr = parts[0].parse()?;
    let prefix: u8 = parts[1].parse()?;
    let ip_val = u32_from_ip(ip);
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let network = ip_val & mask;
    Ok((network, prefix))
}

pub fn u32_from_ip(ip: Ipv4Addr) -> u32 {
    let octets = ip.octets();
    (octets[0] as u32) << 24 | (octets[1] as u32) << 16 | (octets[2] as u32) << 8 | octets[3] as u32
}

pub fn ip_from_u32(val: u32) -> Ipv4Addr {
    Ipv4Addr::new(
        (val >> 24) as u8,
        (val >> 16) as u8,
        (val >> 8) as u8,
        val as u8,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn pool_config(cidr: &str) -> PoolConfig {
        PoolConfig {
            cidr: cidr.into(),
            exclude: Vec::new(),
            lease_time_secs: 3600,
            static_reservations: HashMap::new(),
        }
    }

    #[test]
    fn parse_cidr_basic() {
        let (net, prefix) = parse_cidr("10.0.0.0/24").unwrap();
        assert_eq!(net, u32_from_ip("10.0.0.0".parse().unwrap()));
        assert_eq!(prefix, 24);
        // host bits are masked off
        let (net2, _) = parse_cidr("10.0.0.137/24").unwrap();
        assert_eq!(net2, u32_from_ip("10.0.0.0".parse().unwrap()));
    }

    #[test]
    fn ip_u32_roundtrip() {
        for s in ["0.0.0.0", "10.0.0.1", "192.168.1.100", "255.255.255.255"] {
            let ip: Ipv4Addr = s.parse().unwrap();
            assert_eq!(ip_from_u32(u32_from_ip(ip)), ip);
        }
    }

    #[test]
    fn allocate_is_idempotent_per_user() {
        let mut pool = IpPool::new(&pool_config("10.0.0.0/24")).unwrap();
        let first = pool.allocate("alice").unwrap();
        let again = pool.allocate("alice").unwrap();
        assert_eq!(first, again, "same user must keep the same lease");
    }

    #[test]
    fn allocate_gives_distinct_ips_and_skips_reserved() {
        let mut pool = IpPool::new(&pool_config("10.0.0.0/24")).unwrap();
        let a = pool.allocate("a").unwrap();
        let b = pool.allocate("b").unwrap();
        assert_ne!(a, b);
        // network (.0), gateway (.1) and broadcast (.255) are never handed out
        for ip in [a, b] {
            assert_ne!(ip, "10.0.0.0".parse::<Ipv4Addr>().unwrap());
            assert_ne!(ip, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
            assert_ne!(ip, "10.0.0.255".parse::<Ipv4Addr>().unwrap());
        }
    }

    #[test]
    fn release_frees_the_ip_for_reuse() {
        // /29 → usable .2 .3 .4 .5 .6 (network .0, gateway .1, broadcast .7 excluded)
        let mut pool = IpPool::new(&pool_config("10.0.0.0/29")).unwrap();
        let a = pool.allocate("a").unwrap();
        pool.release("a");
        // a brand-new user can now get that freed address back
        let reused = pool.allocate("c").unwrap();
        assert_eq!(a, reused);
    }

    #[test]
    fn pool_exhaustion_returns_none() {
        // /29 yields exactly 5 usable addresses
        let mut pool = IpPool::new(&pool_config("10.0.0.0/29")).unwrap();
        let mut seen = std::collections::HashSet::new();
        for i in 0..5 {
            let ip = pool.allocate(&format!("u{i}")).expect("address available");
            assert!(seen.insert(ip), "duplicate IP handed out: {ip}");
        }
        assert!(
            pool.allocate("overflow").is_none(),
            "pool must be exhausted"
        );
    }

    #[test]
    fn static_reservation_is_honored() {
        let mut cfg = pool_config("10.0.0.0/24");
        cfg.static_reservations
            .insert("bob".into(), "10.0.0.50".into());
        let mut pool = IpPool::new(&cfg).unwrap();
        assert_eq!(
            pool.allocate("bob").unwrap(),
            "10.0.0.50".parse::<Ipv4Addr>().unwrap()
        );
        // the reserved address is excluded from the dynamic range
        let other = pool.allocate("alice").unwrap();
        assert_ne!(other, "10.0.0.50".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn too_small_subnet_is_rejected() {
        assert!(IpPool::new(&pool_config("10.0.0.0/31")).is_err());
    }
}
