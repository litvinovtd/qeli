//! Flat-INI mapping for the server config (and the inline / standalone user
//! database), the server-side counterpart to [`crate::config::client`].
//!
//! Layout:
//! ```ini
//! [auth]
//! users_file = /etc/qeli/users.conf
//! require_client_key_proof = true
//! brute_force.max_attempts = 5
//!
//! [web]
//! enabled = true
//! bind = 127.0.0.1
//! port = 8080
//!
//! [logging]
//! level = info
//!
//! [profile:tcp]
//! bind.address = 0.0.0.0
//! bind.port = 443
//! bind.transport = tcp
//! tun.name = vpn0
//! tun.address = 10.0.0.1
//! pool.cidr = 10.0.0.0/24
//! pool.exclude = 10.0.0.1, 10.0.0.5
//! pool.reservation.bob = 10.0.0.100
//! routing.nat.enabled = true
//! routing.nat.interface = eth0
//! route = 10.20.0.0/16 gateway=10.0.0.1 metric=100
//! obf.mode = fake-tls
//! obf.padding.min_bytes = 32
//! ...
//!
//! [user:alice]          ; optional inline users (else use users_file)
//! password_hash = $argon2id$...
//! profiles = tcp, udp
//!
//! [group:staff]
//! bandwidth_limit_mbps = 100
//! ```
//!
//! Nested structs are flattened to dotted keys (`bind.port`); the only
//! arrays-of-objects (advertised routes, inline users/groups, per-user routes)
//! get dedicated repeated keys or `[kind:instance]` sections. Reads default
//! every missing key to its serde default, so a sparse hand-written file still
//! yields a fully-valid config.

use crate::config::format::{IniDoc, Section};
use crate::config::server::*;
use crate::config::users::{BandwidthLimit, GroupTemplate, UserEntry, UserRoute, UsersDb};
use std::collections::HashMap;

// ---------- serde baselines (real defaults live in #[serde(default)] fns) ----

/// A `ProfileConfig` with every per-field serde default applied (nested objects
/// spelled out so serde runs the `default_*` functions rather than the derived
/// `Default`, which would give "" / 0 / false).
fn baseline_profile() -> ProfileConfig {
    const SKELETON: &str = r#"{
        "bind":{},"tun":{},"pool":{},
        "routing":{"nat":{}},
        "dns":{},"dhcp":{},
        "obfuscation":{"padding":{},"fragmentation":{},"heartbeat":{},
            "tls":{"reality_proxy":{}},"http2_masking":{},
            "traffic_normalization":{},"anti_fingerprinting":{},"quic":{}},
        "performance":{"tcp":{},"tun":{},"connection":{}}
    }"#;
    serde_json::from_str(SKELETON).expect("baseline profile skeleton is valid")
}

fn baseline_auth() -> AuthConfig {
    serde_json::from_str(r#"{"brute_force":{}}"#).expect("baseline auth skeleton is valid")
}

// ---------------------------- small put helpers ------------------------------

fn put_str(sec: &mut Section, key: &str, val: &str) {
    sec.set(key, val);
}
fn put<T: ToString>(sec: &mut Section, key: &str, val: T) {
    sec.set(key, val.to_string());
}
/// Always emit the key (even for an empty list) so that an empty array is
/// explicit on the wire and survives a round-trip — `from_ini` then reads the
/// exact list when the key is present, and only falls back to the serde default
/// when the key is entirely absent (sparse hand-written file).
fn put_list(sec: &mut Section, key: &str, vals: &[String]) {
    sec.set(key, vals.join(", "));
}

// ================================ ServerConfig ===============================

impl ServerConfig {
    /// Parse a server config from the flat-INI format.
    pub fn from_ini(doc: &IniDoc) -> anyhow::Result<ServerConfig> {
        let mut cfg = ServerConfig {
            auth: doc
                .section("auth")
                .map(auth_from)
                .unwrap_or_else(baseline_auth),
            ..Default::default()
        };
        // inline [user:*] / [group:*] override auth.users / auth.groups
        let users: Vec<UserEntry> = doc.sections_of("user").map(user_from).collect();
        if !users.is_empty() {
            cfg.auth.users = users;
        }
        for g in doc.sections_of("group") {
            if let Some(name) = &g.instance {
                cfg.auth.groups.insert(name.clone(), group_from(g));
            }
        }

        if let Some(w) = doc.section("web") {
            cfg.web = web_from(w);
        }
        if let Some(l) = doc.section("logging") {
            cfg.logging = logging_from(l);
        }

        cfg.profiles = doc.sections_of("profile").map(profile_from).collect();
        if cfg.profiles.is_empty() {
            anyhow::bail!("server config: at least one [profile:<name>] section is required");
        }
        Ok(cfg)
    }

    /// Serialize to flat-INI text (the canonical on-disk format; used by the web
    /// "save config" path). Lossless except for advertised-route `description`,
    /// which is cosmetic and dropped.
    pub fn to_ini_string(&self) -> String {
        let mut doc = IniDoc::new();
        doc.push(auth_to(&self.auth));
        for u in &self.auth.users {
            doc.push(user_to(u));
        }
        for (name, g) in &self.auth.groups {
            doc.push(group_to(name, g));
        }
        doc.push(web_to(&self.web));
        doc.push(logging_to(&self.logging));
        for p in &self.profiles {
            doc.push(profile_to(p));
        }
        doc.to_string()
    }
}

// -------------------------------- auth --------------------------------------

fn auth_to(a: &AuthConfig) -> Section {
    let mut s = Section::new("auth", None);
    put_str(&mut s, "users_file", &a.users_file);
    put_str(&mut s, "password_hash", &a.password_hash);
    put(&mut s, "token_ttl_secs", a.token_ttl_secs);
    put(
        &mut s,
        "require_client_key_proof",
        a.require_client_key_proof,
    );
    put(
        &mut s,
        "brute_force.max_attempts",
        a.brute_force.max_attempts,
    );
    put(&mut s, "brute_force.window_secs", a.brute_force.window_secs);
    put(
        &mut s,
        "brute_force.lockout_secs",
        a.brute_force.lockout_secs,
    );
    s
}

fn auth_from(s: &Section) -> AuthConfig {
    let base = baseline_auth();
    let mut a = base.clone();
    a.users_file = s.str_or("users_file", &base.users_file).to_string();
    a.password_hash = s.str_or("password_hash", &base.password_hash).to_string();
    a.token_ttl_secs = s.parse_or("token_ttl_secs", base.token_ttl_secs);
    a.require_client_key_proof =
        s.bool_or("require_client_key_proof", base.require_client_key_proof);
    a.brute_force.max_attempts =
        s.parse_or("brute_force.max_attempts", base.brute_force.max_attempts);
    a.brute_force.window_secs = s.parse_or("brute_force.window_secs", base.brute_force.window_secs);
    a.brute_force.lockout_secs =
        s.parse_or("brute_force.lockout_secs", base.brute_force.lockout_secs);
    // users/groups are filled from [user:*]/[group:*] sections by the caller
    a.users = Vec::new();
    a.groups = HashMap::new();
    a
}

// --------------------------------- web --------------------------------------

fn web_to(w: &WebConfig) -> Section {
    let mut s = Section::new("web", None);
    put(&mut s, "enabled", w.enabled);
    put_str(&mut s, "bind", &w.bind);
    put(&mut s, "port", w.port);
    put_str(&mut s, "username", &w.username);
    if !w.password_hash.is_empty() {
        put_str(&mut s, "password_hash", &w.password_hash);
    }
    if w.secure_cookie {
        put(&mut s, "secure_cookie", true);
    }
    s
}

fn web_from(s: &Section) -> WebConfig {
    let base: WebConfig = serde_json::from_str("{}").unwrap();
    let mut w = base.clone();
    w.enabled = s.bool_or("enabled", base.enabled);
    w.bind = s.str_or("bind", &base.bind).to_string();
    w.port = s.parse_or("port", base.port);
    w.username = s.str_or("username", &base.username).to_string();
    w.password_hash = s.str_or("password_hash", &base.password_hash).to_string();
    w.secure_cookie = s.bool_or("secure_cookie", base.secure_cookie);
    w
}

// ------------------------------- logging ------------------------------------

fn logging_to(l: &crate::config::LoggingConfig) -> Section {
    let mut s = Section::new("logging", None);
    put_str(&mut s, "level", &l.level);
    if let Some(f) = &l.file {
        put_str(&mut s, "file", f);
    }
    put_str(&mut s, "format", &l.format);
    s
}

fn logging_from(s: &Section) -> crate::config::LoggingConfig {
    let base: crate::config::LoggingConfig = serde_json::from_str("{}").unwrap();
    let mut l = base.clone();
    l.level = s.str_or("level", &base.level).to_string();
    l.file = s.get("file").filter(|f| !f.is_empty()).map(str::to_string);
    l.format = s.str_or("format", &base.format).to_string();
    l
}

// ------------------------------- profile ------------------------------------

fn profile_to(p: &ProfileConfig) -> Section {
    let mut s = Section::new("profile", Some(p.name.clone()));
    put(&mut s, "enabled", p.enabled);
    if let Some(k) = &p.identity_key {
        put_str(&mut s, "identity_key", k);
    }
    // bind
    put_str(&mut s, "bind.address", &p.bind.address);
    put(&mut s, "bind.port", p.bind.port);
    put_str(&mut s, "bind.transport", &p.bind.transport);
    // tun
    put_str(&mut s, "tun.name", &p.tun.name);
    put_str(&mut s, "tun.address", &p.tun.address);
    put_str(&mut s, "tun.netmask", &p.tun.netmask);
    put(&mut s, "tun.mtu", p.tun.mtu);
    put(&mut s, "tun.tx_queue_len", p.tun.tx_queue_len);
    put_str(&mut s, "tun.device_type", &p.tun.device_type);
    put(&mut s, "tun.queues", p.tun.queues);
    // pool
    put_str(&mut s, "pool.cidr", &p.pool.cidr);
    put_list(&mut s, "pool.exclude", &p.pool.exclude);
    put(&mut s, "pool.lease_time_secs", p.pool.lease_time_secs);
    for (name, ip) in &p.pool.static_reservations {
        put_str(&mut s, &format!("pool.reservation.{}", name), ip);
    }
    // routing
    put(
        &mut s,
        "routing.client_to_client",
        p.routing.client_to_client,
    );
    put(&mut s, "routing.forward_private", p.routing.forward_private);
    put(&mut s, "routing.nat.enabled", p.routing.nat.enabled);
    put_str(&mut s, "routing.nat.interface", &p.routing.nat.interface);
    for r in &p.routing.advertised_routes {
        let mut line = r.cidr.clone();
        if let Some(gw) = &r.gateway {
            line.push_str(&format!(" gateway={}", gw));
        }
        if let Some(m) = r.metric {
            line.push_str(&format!(" metric={}", m));
        }
        put_str(&mut s, "route", &line);
    }
    // dns
    put(&mut s, "dns.enabled", p.dns.enabled);
    put_str(&mut s, "dns.listen", &p.dns.listen);
    put(&mut s, "dns.port", p.dns.port);
    put_list(&mut s, "dns.upstream", &p.dns.upstream);
    put_str(&mut s, "dns.upstream_protocol", &p.dns.upstream_protocol);
    put(&mut s, "dns.cache_size", p.dns.cache_size);
    put(&mut s, "dns.timeout_secs", p.dns.timeout_secs);
    put_list(&mut s, "dns.blocklist", &p.dns.blocklist);
    // dhcp
    put(&mut s, "dhcp.enabled", p.dhcp.enabled);
    put_str(&mut s, "dhcp.listen", &p.dhcp.listen);
    if let Some(v) = &p.dhcp.pool_start {
        put_str(&mut s, "dhcp.pool_start", v);
    }
    if let Some(v) = &p.dhcp.pool_end {
        put_str(&mut s, "dhcp.pool_end", v);
    }
    put(&mut s, "dhcp.lease_time_secs", p.dhcp.lease_time_secs);
    put_str(&mut s, "dhcp.domain_name", &p.dhcp.domain_name);
    // obfuscation
    let o = &p.obfuscation;
    put_str(&mut s, "obf.cipher", &o.cipher);
    put_str(&mut s, "obf.mode", &o.mode);
    if !o.obfs_key.is_empty() {
        put_str(&mut s, "obf.obfs_key", &o.obfs_key);
    }
    put_str(&mut s, "obf.obfs_fronting", &o.fronting);
    put_str(&mut s, "obf.tls.server_name", &o.tls.server_name);
    put_list(&mut s, "obf.tls.server_names", &o.tls.server_names);
    put(&mut s, "obf.tls.session_id", o.tls.session_id);
    put_list(&mut s, "obf.tls.supported_groups", &o.tls.supported_groups);
    put(
        &mut s,
        "obf.tls.key_share_entropy_bytes",
        o.tls.key_share_entropy_bytes,
    );
    put(
        &mut s,
        "obf.tls.reality_proxy.enabled",
        o.tls.reality_proxy.enabled,
    );
    put_str(
        &mut s,
        "obf.tls.reality_proxy.target",
        &o.tls.reality_proxy.target,
    );
    put(
        &mut s,
        "obf.tls.reality_proxy.target_port",
        o.tls.reality_proxy.target_port,
    );
    if !o.tls.reality_proxy.short_ids.is_empty() {
        put_list(
            &mut s,
            "obf.tls.reality_proxy.short_ids",
            &o.tls.reality_proxy.short_ids,
        );
    }
    put(
        &mut s,
        "obf.tls.reality_proxy.real_tls",
        o.tls.reality_proxy.real_tls,
    );
    put(
        &mut s,
        "obf.tls.reality_proxy.handrolled",
        o.tls.reality_proxy.handrolled,
    );
    put(&mut s, "obf.padding.enabled", o.padding.enabled);
    put(&mut s, "obf.padding.min_bytes", o.padding.min_bytes);
    put(&mut s, "obf.padding.max_bytes", o.padding.max_bytes);
    put(&mut s, "obf.padding.randomize", o.padding.randomize);
    put(&mut s, "obf.padding.probability", o.padding.probability);
    put(&mut s, "obf.fragmentation.enabled", o.fragmentation.enabled);
    put(
        &mut s,
        "obf.fragmentation.min_chunk_size",
        o.fragmentation.min_chunk_size,
    );
    put(
        &mut s,
        "obf.fragmentation.max_chunk_size",
        o.fragmentation.max_chunk_size,
    );
    put(
        &mut s,
        "obf.fragmentation.max_fragments_per_packet",
        o.fragmentation.max_fragments_per_packet,
    );
    put(&mut s, "obf.heartbeat.enabled", o.heartbeat.enabled);
    put(&mut s, "obf.heartbeat.interval_ms", o.heartbeat.interval_ms);
    put(
        &mut s,
        "obf.heartbeat.data_size_bytes",
        o.heartbeat.data_size_bytes,
    );
    put(&mut s, "obf.heartbeat.jitter_ms", o.heartbeat.jitter_ms);
    put(&mut s, "obf.http2_masking.enabled", o.http2_masking.enabled);
    put(&mut s, "obf.http2_masking.ratio", o.http2_masking.ratio);
    put(
        &mut s,
        "obf.traffic_normalization.enabled",
        o.traffic_normalization.enabled,
    );
    put_list(
        &mut s,
        "obf.traffic_normalization.round_sizes",
        &o.traffic_normalization
            .round_sizes
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>(),
    );
    put(
        &mut s,
        "obf.traffic_normalization.randomize_sequence",
        o.traffic_normalization.randomize_sequence,
    );
    put(
        &mut s,
        "obf.anti_fingerprinting.enabled",
        o.anti_fingerprinting.enabled,
    );
    put(
        &mut s,
        "obf.anti_fingerprinting.rotate_ciphers_every",
        o.anti_fingerprinting.rotate_ciphers_every,
    );
    put(
        &mut s,
        "obf.anti_fingerprinting.add_jitter_to_handshake",
        o.anti_fingerprinting.add_jitter_to_handshake,
    );
    put(&mut s, "obf.quic.enabled", o.quic.enabled);
    put(&mut s, "obf.quic.cid_length", o.quic.cid_length);
    put(&mut s, "obf.quic.version", o.quic.version);
    // performance
    let pf = &p.performance;
    put(&mut s, "perf.tcp.nodelay", pf.tcp.nodelay);
    put(&mut s, "perf.tcp.keepalive_secs", pf.tcp.keepalive_secs);
    put(&mut s, "perf.tcp.send_buffer_size", pf.tcp.send_buffer_size);
    put(&mut s, "perf.tcp.recv_buffer_size", pf.tcp.recv_buffer_size);
    put(&mut s, "perf.tun.read_buffer_size", pf.tun.read_buffer_size);
    put(
        &mut s,
        "perf.tun.write_buffer_size",
        pf.tun.write_buffer_size,
    );
    put(&mut s, "perf.tun.read_timeout_ms", pf.tun.read_timeout_ms);
    put(
        &mut s,
        "perf.tun.max_pending_packets",
        pf.tun.max_pending_packets,
    );
    put(
        &mut s,
        "perf.connection.max_clients",
        pf.connection.max_clients,
    );
    put(
        &mut s,
        "perf.connection.handshake_timeout_secs",
        pf.connection.handshake_timeout_secs,
    );
    put(
        &mut s,
        "perf.connection.idle_timeout_secs",
        pf.connection.idle_timeout_secs,
    );
    put(
        &mut s,
        "perf.connection.rate_limit_packets_per_sec",
        pf.connection.rate_limit_packets_per_sec,
    );
    s
}

fn profile_from(s: &Section) -> ProfileConfig {
    let base = baseline_profile();
    let mut p = base.clone();
    p.name = s.instance.clone().unwrap_or_else(|| "default".to_string());
    p.enabled = s.bool_or("enabled", true);
    p.identity_key = s
        .get("identity_key")
        .filter(|k| !k.is_empty())
        .map(str::to_string);
    // bind
    p.bind.address = s.str_or("bind.address", &base.bind.address).to_string();
    p.bind.port = s.parse_or("bind.port", base.bind.port);
    p.bind.transport = s.str_or("bind.transport", &base.bind.transport).to_string();
    // tun
    p.tun.name = s.str_or("tun.name", &base.tun.name).to_string();
    p.tun.address = s.str_or("tun.address", &base.tun.address).to_string();
    p.tun.netmask = s.str_or("tun.netmask", &base.tun.netmask).to_string();
    p.tun.mtu = s.parse_or("tun.mtu", base.tun.mtu);
    p.tun.tx_queue_len = s.parse_or("tun.tx_queue_len", base.tun.tx_queue_len);
    p.tun.device_type = s
        .str_or("tun.device_type", &base.tun.device_type)
        .to_string();
    p.tun.queues = s.parse_or("tun.queues", base.tun.queues);
    // pool
    p.pool.cidr = s.str_or("pool.cidr", &base.pool.cidr).to_string();
    if s.get("pool.exclude").is_some() {
        p.pool.exclude = s.list("pool.exclude");
    }
    p.pool.lease_time_secs = s.parse_or("pool.lease_time_secs", base.pool.lease_time_secs);
    p.pool.static_reservations = HashMap::new();
    for (k, v) in &s.entries {
        if let Some(name) = k.strip_prefix("pool.reservation.") {
            p.pool
                .static_reservations
                .insert(name.to_string(), v.clone());
        }
    }
    // routing
    p.routing.client_to_client =
        s.bool_or("routing.client_to_client", base.routing.client_to_client);
    p.routing.forward_private = s.bool_or("routing.forward_private", base.routing.forward_private);
    p.routing.nat.enabled = s.bool_or("routing.nat.enabled", base.routing.nat.enabled);
    p.routing.nat.interface = s
        .str_or("routing.nat.interface", &base.routing.nat.interface)
        .to_string();
    p.routing.advertised_routes = s.all("route").iter().map(|l| parse_route(l)).collect();
    // dns
    p.dns.enabled = s.bool_or("dns.enabled", base.dns.enabled);
    p.dns.listen = s.str_or("dns.listen", &base.dns.listen).to_string();
    p.dns.port = s.parse_or("dns.port", base.dns.port);
    if s.get("dns.upstream").is_some() {
        p.dns.upstream = s.list("dns.upstream");
    }
    p.dns.upstream_protocol = s
        .str_or("dns.upstream_protocol", &base.dns.upstream_protocol)
        .to_string();
    p.dns.cache_size = s.parse_or("dns.cache_size", base.dns.cache_size);
    p.dns.timeout_secs = s.parse_or("dns.timeout_secs", base.dns.timeout_secs);
    if s.get("dns.blocklist").is_some() {
        p.dns.blocklist = s.list("dns.blocklist");
    }
    // dhcp
    p.dhcp.enabled = s.bool_or("dhcp.enabled", base.dhcp.enabled);
    p.dhcp.listen = s.str_or("dhcp.listen", &base.dhcp.listen).to_string();
    p.dhcp.pool_start = s
        .get("dhcp.pool_start")
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    p.dhcp.pool_end = s
        .get("dhcp.pool_end")
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    p.dhcp.lease_time_secs = s.parse_or("dhcp.lease_time_secs", base.dhcp.lease_time_secs);
    p.dhcp.domain_name = s
        .str_or("dhcp.domain_name", &base.dhcp.domain_name)
        .to_string();
    // obfuscation
    let bo = &base.obfuscation;
    let o = &mut p.obfuscation;
    o.cipher = s.str_or("obf.cipher", &bo.cipher).to_string();
    o.mode = s.str_or("obf.mode", &bo.mode).to_string();
    o.obfs_key = s.str_or("obf.obfs_key", &bo.obfs_key).to_string();
    o.fronting = s.str_or("obf.obfs_fronting", &bo.fronting).to_string();
    o.tls.server_name = s
        .str_or("obf.tls.server_name", &bo.tls.server_name)
        .to_string();
    if s.get("obf.tls.server_names").is_some() {
        o.tls.server_names = s.list("obf.tls.server_names");
    }
    o.tls.session_id = s.bool_or("obf.tls.session_id", bo.tls.session_id);
    if s.get("obf.tls.supported_groups").is_some() {
        o.tls.supported_groups = s.list("obf.tls.supported_groups");
    }
    o.tls.key_share_entropy_bytes = s.parse_or(
        "obf.tls.key_share_entropy_bytes",
        bo.tls.key_share_entropy_bytes,
    );
    o.tls.reality_proxy.enabled = s.bool_or(
        "obf.tls.reality_proxy.enabled",
        bo.tls.reality_proxy.enabled,
    );
    o.tls.reality_proxy.target = s
        .str_or("obf.tls.reality_proxy.target", &bo.tls.reality_proxy.target)
        .to_string();
    o.tls.reality_proxy.target_port = s.parse_or(
        "obf.tls.reality_proxy.target_port",
        bo.tls.reality_proxy.target_port,
    );
    if s.get("obf.tls.reality_proxy.short_ids").is_some() {
        o.tls.reality_proxy.short_ids = s.list("obf.tls.reality_proxy.short_ids");
    }
    o.tls.reality_proxy.real_tls = s.bool_or(
        "obf.tls.reality_proxy.real_tls",
        bo.tls.reality_proxy.real_tls,
    );
    o.tls.reality_proxy.handrolled = s.bool_or(
        "obf.tls.reality_proxy.handrolled",
        bo.tls.reality_proxy.handrolled,
    );
    o.padding.enabled = s.bool_or("obf.padding.enabled", bo.padding.enabled);
    o.padding.min_bytes = s.parse_or("obf.padding.min_bytes", bo.padding.min_bytes);
    o.padding.max_bytes = s.parse_or("obf.padding.max_bytes", bo.padding.max_bytes);
    o.padding.randomize = s.bool_or("obf.padding.randomize", bo.padding.randomize);
    o.padding.probability = s.parse_or("obf.padding.probability", bo.padding.probability);
    o.fragmentation.enabled = s.bool_or("obf.fragmentation.enabled", bo.fragmentation.enabled);
    o.fragmentation.min_chunk_size = s.parse_or(
        "obf.fragmentation.min_chunk_size",
        bo.fragmentation.min_chunk_size,
    );
    o.fragmentation.max_chunk_size = s.parse_or(
        "obf.fragmentation.max_chunk_size",
        bo.fragmentation.max_chunk_size,
    );
    o.fragmentation.max_fragments_per_packet = s.parse_or(
        "obf.fragmentation.max_fragments_per_packet",
        bo.fragmentation.max_fragments_per_packet,
    );
    o.heartbeat.enabled = s.bool_or("obf.heartbeat.enabled", bo.heartbeat.enabled);
    o.heartbeat.interval_ms = s.parse_or("obf.heartbeat.interval_ms", bo.heartbeat.interval_ms);
    o.heartbeat.data_size_bytes = s.parse_or(
        "obf.heartbeat.data_size_bytes",
        bo.heartbeat.data_size_bytes,
    );
    o.heartbeat.jitter_ms = s.parse_or("obf.heartbeat.jitter_ms", bo.heartbeat.jitter_ms);
    o.http2_masking.enabled = s.bool_or("obf.http2_masking.enabled", bo.http2_masking.enabled);
    o.http2_masking.ratio = s.parse_or("obf.http2_masking.ratio", bo.http2_masking.ratio);
    o.traffic_normalization.enabled = s.bool_or(
        "obf.traffic_normalization.enabled",
        bo.traffic_normalization.enabled,
    );
    if s.get("obf.traffic_normalization.round_sizes").is_some() {
        o.traffic_normalization.round_sizes = s
            .list("obf.traffic_normalization.round_sizes")
            .iter()
            .filter_map(|x| x.parse().ok())
            .collect();
    }
    o.traffic_normalization.randomize_sequence = s.bool_or(
        "obf.traffic_normalization.randomize_sequence",
        bo.traffic_normalization.randomize_sequence,
    );
    o.anti_fingerprinting.enabled = s.bool_or(
        "obf.anti_fingerprinting.enabled",
        bo.anti_fingerprinting.enabled,
    );
    o.anti_fingerprinting.rotate_ciphers_every = s.parse_or(
        "obf.anti_fingerprinting.rotate_ciphers_every",
        bo.anti_fingerprinting.rotate_ciphers_every,
    );
    o.anti_fingerprinting.add_jitter_to_handshake = s.bool_or(
        "obf.anti_fingerprinting.add_jitter_to_handshake",
        bo.anti_fingerprinting.add_jitter_to_handshake,
    );
    o.quic.enabled = s.bool_or("obf.quic.enabled", bo.quic.enabled);
    o.quic.cid_length = s.parse_or("obf.quic.cid_length", bo.quic.cid_length);
    o.quic.version = s.parse_or("obf.quic.version", bo.quic.version);
    // performance
    let bp = &base.performance;
    let pf = &mut p.performance;
    pf.tcp.nodelay = s.bool_or("perf.tcp.nodelay", bp.tcp.nodelay);
    pf.tcp.keepalive_secs = s.parse_or("perf.tcp.keepalive_secs", bp.tcp.keepalive_secs);
    pf.tcp.send_buffer_size = s.parse_or("perf.tcp.send_buffer_size", bp.tcp.send_buffer_size);
    pf.tcp.recv_buffer_size = s.parse_or("perf.tcp.recv_buffer_size", bp.tcp.recv_buffer_size);
    pf.tun.read_buffer_size = s.parse_or("perf.tun.read_buffer_size", bp.tun.read_buffer_size);
    pf.tun.write_buffer_size = s.parse_or("perf.tun.write_buffer_size", bp.tun.write_buffer_size);
    pf.tun.read_timeout_ms = s.parse_or("perf.tun.read_timeout_ms", bp.tun.read_timeout_ms);
    pf.tun.max_pending_packets =
        s.parse_or("perf.tun.max_pending_packets", bp.tun.max_pending_packets);
    pf.connection.max_clients =
        s.parse_or("perf.connection.max_clients", bp.connection.max_clients);
    pf.connection.handshake_timeout_secs = s.parse_or(
        "perf.connection.handshake_timeout_secs",
        bp.connection.handshake_timeout_secs,
    );
    pf.connection.idle_timeout_secs = s.parse_or(
        "perf.connection.idle_timeout_secs",
        bp.connection.idle_timeout_secs,
    );
    pf.connection.rate_limit_packets_per_sec = s.parse_or(
        "perf.connection.rate_limit_packets_per_sec",
        bp.connection.rate_limit_packets_per_sec,
    );
    p
}

/// Parse a `route` line: `<cidr> [gateway=<ip>] [metric=<n>]`.
fn parse_route(line: &str) -> PushedRoute {
    let mut r = PushedRoute::default();
    for (i, tok) in line.split_whitespace().enumerate() {
        if i == 0 && !tok.contains('=') {
            r.cidr = tok.to_string();
        } else if let Some(v) = tok.strip_prefix("cidr=") {
            r.cidr = v.to_string();
        } else if let Some(v) = tok.strip_prefix("gateway=") {
            r.gateway = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("metric=") {
            r.metric = v.parse().ok();
        }
    }
    r
}

// =============================== UsersDb (file) ==============================

impl UsersDb {
    /// Parse the standalone user database from flat INI (`[user:*]`/`[group:*]`).
    pub fn from_ini(doc: &IniDoc) -> UsersDb {
        let mut db = UsersDb {
            users: doc.sections_of("user").map(user_from).collect(),
            ..Default::default()
        };
        for g in doc.sections_of("group") {
            if let Some(name) = &g.instance {
                db.groups.insert(name.clone(), group_from(g));
            }
        }
        db
    }

    pub fn to_ini_string(&self) -> String {
        let mut doc = IniDoc::new();
        for u in &self.users {
            doc.push(user_to(u));
        }
        for (name, g) in &self.groups {
            doc.push(group_to(name, g));
        }
        doc.to_string()
    }
}

fn user_to(u: &UserEntry) -> Section {
    let mut s = Section::new("user", Some(u.username.clone()));
    put_str(&mut s, "password_hash", &u.password_hash);
    if let Some(ip) = &u.static_ip {
        put_str(&mut s, "static_ip", ip);
    }
    put(&mut s, "enabled", u.enabled);
    put_list(&mut s, "allowed_networks", &u.allowed_networks);
    if let Some(g) = &u.group {
        put_str(&mut s, "group", g);
    }
    if u.max_sessions > 0 {
        put(&mut s, "max_sessions", u.max_sessions);
    }
    put_list(&mut s, "profiles", &u.profiles);
    if u.bandwidth.limit_mbps > 0 || u.bandwidth.burst_mbps > 0 {
        put(&mut s, "bandwidth.limit_mbps", u.bandwidth.limit_mbps);
        put(&mut s, "bandwidth.burst_mbps", u.bandwidth.burst_mbps);
    }
    for (k, v) in &u.metadata {
        put_str(&mut s, &format!("metadata.{}", k), v);
    }
    for r in &u.routes {
        let mut line = r.cidr.clone();
        if let Some(gw) = &r.gateway {
            line.push_str(&format!(" gateway={}", gw));
        }
        if let Some(m) = r.metric {
            line.push_str(&format!(" metric={}", m));
        }
        put_str(&mut s, "route", &line);
    }
    s
}

fn user_from(s: &Section) -> UserEntry {
    let mut metadata = HashMap::new();
    for (k, v) in &s.entries {
        if let Some(name) = k.strip_prefix("metadata.") {
            metadata.insert(name.to_string(), v.clone());
        }
    }
    let routes = s
        .all("route")
        .iter()
        .map(|l| {
            let r = parse_route(l);
            UserRoute {
                cidr: r.cidr,
                gateway: r.gateway,
                metric: r.metric,
            }
        })
        .collect();
    UserEntry {
        username: s.instance.clone().unwrap_or_default(),
        password_hash: s.str_or("password_hash", "").to_string(),
        static_ip: s
            .get("static_ip")
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        enabled: s.bool_or("enabled", true),
        allowed_networks: s.list("allowed_networks"),
        group: s.get("group").filter(|v| !v.is_empty()).map(str::to_string),
        max_sessions: s.parse_or("max_sessions", 0),
        profiles: s.list("profiles"),
        bandwidth: BandwidthLimit {
            limit_mbps: s.parse_or("bandwidth.limit_mbps", 0),
            burst_mbps: s.parse_or("bandwidth.burst_mbps", 0),
        },
        metadata,
        routes,
    }
}

fn group_to(name: &str, g: &GroupTemplate) -> Section {
    let mut s = Section::new("group", Some(name.to_string()));
    if let Some(v) = g.bandwidth_limit_mbps {
        put(&mut s, "bandwidth_limit_mbps", v);
    }
    if let Some(v) = g.max_sessions {
        put(&mut s, "max_sessions", v);
    }
    if let Some(v) = &g.allowed_networks {
        put_list(&mut s, "allowed_networks", v);
    }
    s
}

fn group_from(s: &Section) -> GroupTemplate {
    GroupTemplate {
        bandwidth_limit_mbps: s.get("bandwidth_limit_mbps").and_then(|v| v.parse().ok()),
        max_sessions: s.get("max_sessions").and_then(|v| v.parse().ok()),
        allowed_networks: if s.get("allowed_networks").is_some() {
            Some(s.list("allowed_networks"))
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_round_trip_preserves_fields() {
        // Parse a custom-values INI config, then serialize → re-parse and assert
        // the two are structurally identical (lossless round-trip).
        let ini_src = r#"
            [auth]
            require_client_key_proof = true

            [profile:edge]
            bind.address = 192.168.1.1
            bind.port = 8443
            bind.transport = udp
            tun.name = tun1
            tun.address = 10.1.0.1
            tun.netmask = 255.255.0.0
            tun.mtu = 1400
            pool.cidr = 10.1.0.0/16
            pool.exclude = 10.1.0.1
            pool.reservation.bob = 10.1.0.100
            dns.enabled = true
            dns.upstream = 9.9.9.9
            dns.blocklist = ads.com
            routing.nat.enabled = true
            routing.nat.interface = eth1
            route = 10.20.0.0/16 gateway=10.1.0.1 metric=50
            obf.cipher = aes-256-gcm
            obf.mode = obfs
            obf.obfs_key = shared-secret
            obf.padding.min_bytes = 64
            obf.padding.max_bytes = 1024
            perf.tcp.keepalive_secs = 120

            [logging]
            level = debug
        "#;
        let orig = crate::config::parse_server_config(ini_src).unwrap();
        let ini = orig.to_ini_string();
        let doc = IniDoc::parse(&ini).unwrap();
        let back = ServerConfig::from_ini(&doc).unwrap();

        // Lossless round-trip: orig and back must be structurally identical.
        // (Comparing serde_json::Value covers every field at once and is
        // map-order independent. The only intentionally-dropped field is an
        // advertised-route `description`, which the fixture doesn't set.)
        let a = serde_json::to_value(&orig).unwrap();
        let b = serde_json::to_value(&back).unwrap();
        assert_eq!(a, b, "INI round-trip changed the config");

        // Spot-check a representative set of explicitly-set values.
        let p = &back.profiles[0];
        assert_eq!(p.name, "edge");
        assert_eq!(p.bind.port, 8443);
        assert_eq!(p.bind.transport, "udp");
        assert_eq!(p.tun.netmask, "255.255.0.0");
        assert_eq!(p.pool.static_reservations.get("bob").unwrap(), "10.1.0.100");
        assert_eq!(p.dns.upstream, vec!["9.9.9.9"]);
        assert!(p.routing.nat.enabled);
        assert_eq!(
            p.routing.advertised_routes[0].gateway.as_deref(),
            Some("10.1.0.1")
        );
        assert_eq!(p.routing.advertised_routes[0].metric, Some(50));
        assert_eq!(p.obfuscation.mode, "obfs");
        // obfs fronting defaults to "websocket" and survives the INI round-trip.
        assert_eq!(p.obfuscation.fronting, "websocket");
        assert_eq!(p.obfuscation.padding.max_bytes, 1024);
        assert_eq!(p.performance.tcp.keepalive_secs, 120);
        assert!(back.auth.require_client_key_proof);
        assert_eq!(back.logging.level, "debug");
    }

    #[test]
    fn inline_users_and_groups_round_trip() {
        let src = "\
[auth]
require_client_key_proof = true

[profile:tcp]
bind.port = 443

[user:alice]
password_hash = $argon2id$v=19$m=16384,t=2,p=1$abc$def
profiles = tcp, udp
max_sessions = 3
bandwidth.limit_mbps = 50
route = 10.20.0.0/16 gateway=10.0.0.1 metric=100

[group:staff]
bandwidth_limit_mbps = 100
max_sessions = 5
";
        let doc = IniDoc::parse(src).unwrap();
        let cfg = ServerConfig::from_ini(&doc).unwrap();
        assert_eq!(cfg.auth.users.len(), 1);
        let u = &cfg.auth.users[0];
        assert_eq!(u.username, "alice");
        assert_eq!(u.profiles, vec!["tcp", "udp"]);
        assert_eq!(u.max_sessions, 3);
        assert_eq!(u.bandwidth.limit_mbps, 50);
        assert_eq!(u.routes.len(), 1);
        assert_eq!(u.routes[0].cidr, "10.20.0.0/16");
        assert_eq!(u.routes[0].gateway.as_deref(), Some("10.0.0.1"));
        assert_eq!(u.routes[0].metric, Some(100));
        assert_eq!(cfg.auth.groups["staff"].bandwidth_limit_mbps, Some(100));
        assert_eq!(cfg.auth.groups["staff"].max_sessions, Some(5));

        // standalone users-db round-trip via the same section codec
        let db = UsersDb::from_ini(&doc);
        assert_eq!(db.users.len(), 1);
        let out = db.to_ini_string();
        let db2 = UsersDb::from_ini(&IniDoc::parse(&out).unwrap());
        assert_eq!(db2.users[0].username, "alice");
        assert_eq!(db2.users[0].bandwidth.limit_mbps, 50);
    }
}
