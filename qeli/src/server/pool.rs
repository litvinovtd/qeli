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
    static_reservations: Vec<(String, u32)>,
    /// `pool.reservation.<user>` addresses: skipped by dynamic allocation, but assignable
    /// by `allocate_fixed` to the user they belong to (see IpPool::new).
    reserved: HashSet<u32>,
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
            match ip_str.parse::<Ipv4Addr>() {
                Ok(ip) => {
                    excluded.insert(u32_from_ip(ip));
                }
                // Silently dropping a typo'd entry means the address the admin meant to
                // keep free stays allocatable, with nothing anywhere to say why.
                Err(_) => log::warn!(
                    "pool.exclude: '{}' is not a valid IPv4 address — entry ignored",
                    ip_str
                ),
            }
        }

        excluded.insert(network | 1);

        // Reserved addresses go in their OWN set, NOT in `excluded`. They must be kept out
        // of DYNAMIC allocation (nobody else may be handed them), but `allocate_fixed` has
        // to be able to assign them to their owner. Putting them in `excluded` made
        // allocate_fixed refuse the very address it was reserving, so every
        // `pool.reservation.<user>` silently fell back to a dynamic address.
        let mut reserved = HashSet::new();
        let mut static_reservations: Vec<(String, u32)> = Vec::new();
        for (username, ip_str) in &config.static_reservations {
            let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
                log::warn!(
                    "pool.reservation.{} = '{}' is not a valid IPv4 address — reservation \
                     ignored; this user will get a dynamic address",
                    username,
                    ip_str
                );
                continue;
            };
            let ip_val = u32_from_ip(ip);
            // Diagnose the unusable cases HERE, at startup, where the operator can act on
            // them. A reservation that is out of range or excluded otherwise surfaces only
            // as a per-connect "static IP … outside profile pool" warning, and a duplicate
            // surfaces not at all — the two users just evict each other's address on every
            // reconnect. The reservation is still recorded either way: `allocate_fixed`
            // applies the same range/excluded rules and the caller falls back to dynamic.
            if (ip_val as u64) < start_ip as u64 || (ip_val as u64) > end_ip as u64 {
                log::warn!(
                    "pool.reservation.{} = {} is outside the pool range {}–{} — it can never \
                     be assigned; this user will get a dynamic address",
                    username,
                    ip,
                    ip_from_u32(start_ip),
                    ip_from_u32(end_ip)
                );
            } else if excluded.contains(&ip_val) {
                log::warn!(
                    "pool.reservation.{} = {} is an excluded address (network / gateway / \
                     broadcast / pool.exclude) — it can never be assigned; this user will \
                     get a dynamic address",
                    username,
                    ip
                );
            }
            if let Some((other, _)) = static_reservations.iter().find(|(_, v)| *v == ip_val) {
                log::warn!(
                    "pool.reservation.{} = {} collides with pool.reservation.{} — two users \
                     cannot hold the same address, so they will evict each other on every \
                     reconnect. Give each user a distinct address.",
                    username,
                    ip,
                    other
                );
            }
            reserved.insert(ip_val);
            static_reservations.push((username.clone(), ip_val));
        }

        Ok(IpPool {
            gateway: ip_from_u32(network | 1),
            subnet_mask,
            start_ip,
            end_ip,
            excluded,
            reserved,
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
            if !self.excluded.contains(&ip_val)
                && !self.reserved.contains(&ip_val)
                && !self.allocated.contains(&ip_val)
            {
                self.allocated.insert(ip_val);
                self.user_allocations.insert(username.to_string(), ip_val);
                return Some(ip_from_u32(ip_val));
            }
        }
        while self.cursor <= self.end_ip as u64 {
            let ip_val = self.cursor as u32;
            self.cursor += 1;
            if !self.excluded.contains(&ip_val)
                && !self.reserved.contains(&ip_val)
                && !self.allocated.contains(&ip_val)
            {
                self.allocated.insert(ip_val);
                self.user_allocations.insert(username.to_string(), ip_val);
                return Some(ip_from_u32(ip_val));
            }
        }
        None
    }

    /// Assign a SPECIFIC in-range address to `key`, stealing it from any current holder
    /// (variant-b static IP: a user's fixed address always wins — the caller evicts the
    /// holder's session, then this reassigns the address). Idempotent for the same key.
    /// Returns None when `ip` is outside the usable pool range or is an excluded address
    /// (network / gateway / broadcast / an admin `pool.exclude`), so the caller can fall
    /// back to dynamic allocation with a warning. A `pool.reservation.<user>` address is
    /// NOT excluded and is assignable here — that is the whole point of reserving it.
    pub fn allocate_fixed(&mut self, key: &str, ip: Ipv4Addr) -> Option<Ipv4Addr> {
        let ip_val = u32_from_ip(ip);
        if (ip_val as u64) < self.start_ip as u64
            || (ip_val as u64) > self.end_ip as u64
            || self.excluded.contains(&ip_val)
        {
            return None;
        }
        // Release this key's previous (different) address back to the pool.
        if let Some(&prev) = self.user_allocations.get(key) {
            if prev == ip_val {
                return Some(ip_from_u32(ip_val)); // already ours — idempotent
            }
            self.allocated.remove(&prev);
            self.freed.push(prev);
        }
        // Steal the address from any OTHER holder (its session is evicted by the caller).
        self.user_allocations
            .retain(|k, v| !(*v == ip_val && k != key));
        self.allocated.insert(ip_val);
        self.user_allocations.insert(key.to_string(), ip_val);
        Some(ip_from_u32(ip_val))
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
    // Validate BEFORE the shift: `32 - prefix` underflows (u8) for prefix > 32, which
    // panics in debug and produces a wrong mask in release on a config typo like /40.
    if prefix > 32 {
        anyhow::bail!("invalid CIDR prefix (>32): {}", cidr);
    }
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
            static_reservations: HashMap::new(),
        }
    }

    /// `pool.reservation.<user>` must be ASSIGNABLE to its owner. Regression guard: the
    /// reserved address used to be inserted into `excluded`, and `allocate_fixed` rejects
    /// everything in `excluded` — so it refused the very address it was reserving, the
    /// handler fell back to a dynamic one, and the reservation silently did nothing.
    #[test]
    fn reserved_address_is_assignable_but_never_handed_out_dynamically() {
        let mut cfg = pool_config("10.0.0.0/24");
        cfg.static_reservations
            .insert("bob".into(), "10.0.0.77".into());
        let mut pool = IpPool::new(&cfg).unwrap();

        // The owner gets exactly the reserved address (this is what the handler does:
        // resolve_static_ip -> allocate_fixed, keyed by the device key, not the username).
        let want: Ipv4Addr = "10.0.0.77".parse().unwrap();
        assert_eq!(pool.allocate_fixed("bob|device1", want), Some(want));

        // ...and nobody else ever gets it from dynamic allocation.
        for i in 0..50 {
            if let Some(ip) = pool.allocate(&format!("other{i}")) {
                assert_ne!(ip, want, "dynamic allocation handed out a reserved address");
            }
        }
    }

    #[test]
    fn hard_excluded_addresses_are_still_refused_by_allocate_fixed() {
        let mut cfg = pool_config("10.0.0.0/24");
        cfg.exclude.push("10.0.0.50".into());
        let mut pool = IpPool::new(&cfg).unwrap();
        // admin pool.exclude, gateway and out-of-range all stay refused
        assert_eq!(pool.allocate_fixed("k", "10.0.0.50".parse().unwrap()), None);
        assert_eq!(pool.allocate_fixed("k", "10.0.0.1".parse().unwrap()), None);
        assert_eq!(pool.allocate_fixed("k", "10.9.9.9".parse().unwrap()), None);
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

    #[test]
    fn allocate_fixed_steals_and_is_idempotent() {
        let mut pool = IpPool::new(&pool_config("10.0.0.0/24")).unwrap();
        let fixed = "10.0.0.50".parse::<Ipv4Addr>().unwrap();
        // Force a dynamic user onto the target address (cursor starts at .2, so .50 is the
        // 49th handout — allocate up to it).
        let mut holder = String::new();
        for i in 0..300 {
            let name = format!("u{i}");
            if pool.allocate(&name).unwrap() == fixed {
                holder = name;
                break;
            }
        }
        assert!(!holder.is_empty(), "someone should hold .50");
        // The static-IP owner takes it — stolen from the holder, assigned to "owner".
        assert_eq!(pool.allocate_fixed("owner", fixed).unwrap(), fixed);
        // The previous holder no longer has it; a fresh allocate gives a different address.
        let reassigned = pool.allocate(&holder).unwrap();
        assert_ne!(reassigned, fixed);
        // Idempotent for the owner across reconnects.
        assert_eq!(pool.allocate_fixed("owner", fixed).unwrap(), fixed);
        // Switching an owner from a dynamic address to a fixed one frees the old one.
        let dyn_ip = pool.allocate("owner2").unwrap();
        let want = "10.0.0.200".parse::<Ipv4Addr>().unwrap();
        assert_eq!(pool.allocate_fixed("owner2", want).unwrap(), want);
        assert_ne!(dyn_ip, want);
    }

    #[test]
    fn allocate_fixed_rejects_out_of_range_or_excluded() {
        let mut cfg = pool_config("10.0.0.0/24");
        cfg.exclude.push("10.0.0.9".into());
        let mut pool = IpPool::new(&cfg).unwrap();
        // Out of the /24 → None (caller falls back to dynamic).
        assert!(pool
            .allocate_fixed("x", "10.0.5.5".parse().unwrap())
            .is_none());
        // Network / gateway / broadcast are outside start..end → None.
        assert!(pool
            .allocate_fixed("x", "10.0.0.1".parse().unwrap())
            .is_none());
        // Admin-excluded address → None (respected, not stolen).
        assert!(pool
            .allocate_fixed("x", "10.0.0.9".parse().unwrap())
            .is_none());
    }
}
