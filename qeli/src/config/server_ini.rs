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
//! tun.address = 10.9.0.1
//! pool.cidr = 10.9.0.0/24
//! pool.exclude = 10.9.0.1, 10.9.0.5
//! pool.reservation.bob = 10.9.0.100
//! routing.nat.enabled = true
//! routing.nat.interface = eth0
//! route = 10.20.0.0/16 gateway=10.9.0.1 metric=100
//! obf.mode = fake-tls
//! obf.padding.min_bytes = 32
//! ...
//!
//! [user:alice]          ; optional inline users (else use users_file)
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

/// A `ProfileConfig` with every per-field serde default applied. Single source
/// of truth lives in [`ProfileConfig::baseline`] (also served to the web UI via
/// `/api/config/defaults`), so the INI codec and the panel never drift.
fn baseline_profile() -> ProfileConfig {
    ProfileConfig::baseline()
}

fn baseline_auth() -> AuthConfig {
    serde_json::from_str(r#"{"brute_force":{}}"#).expect("baseline auth skeleton is valid")
}

/// The serde-default WebConfig, used when the file has no `[web]` section. The DERIVED
/// `Default` gives `csrf=false` / `persist_session_key=false` / `session_ttl_secs=0` —
/// the fail-OPEN opposite of the serde defaults (`csrf=true`, …). It is only latent today
/// because `enabled` is false either way, but a fail-open value one refactor from being
/// live is not worth leaving. Mirrors baseline_auth. (L6)
fn baseline_web() -> WebConfig {
    serde_json::from_str("{}").expect("baseline web skeleton is valid")
}

fn baseline_logging() -> crate::config::LoggingConfig {
    serde_json::from_str("{}").expect("baseline logging skeleton is valid")
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
        // Repeatable section instances are executable/configuration identities, not display
        // labels. Validate file-authored names at the same boundary as panel-authored names;
        // otherwise a manual `[profile:]` is silently normalised/dropped and an overlong
        // profile reaches iptables comments that cannot represent it.
        for kind in ["profile", "user", "group"] {
            for section in doc.sections_of(kind) {
                let name = section.instance.as_deref().unwrap_or("");
                if !crate::util::is_valid_ident(name) {
                    anyhow::bail!(
                        "server config: invalid [{kind}:<name>] instance {name:?} (must be 1..=128 bytes, without edge whitespace or control characters)"
                    );
                }
            }
        }
        let mut cfg = ServerConfig {
            auth: doc
                .section("auth")
                .map(auth_from)
                .unwrap_or_else(baseline_auth),
            // serde-baseline (not derived Default) when the section is absent — see
            // baseline_web/baseline_logging for why the derived default is fail-open. (L6)
            web: doc
                .section("web")
                .map(web_from)
                .unwrap_or_else(baseline_web),
            logging: doc
                .section("logging")
                .map(logging_from)
                .unwrap_or_else(baseline_logging),
            ..Default::default()
        };
        // inline [user:*] / [group:*] override auth.users / auth.groups
        //
        // De-duplicate by username, first-wins — the SAME rule `UsersDb::from_ini` applies
        // (L7). This path did not, and the asymmetry was a security bug rather than a
        // cosmetic one: `find_user` returns the first entry that matches AND is enabled, so
        // a stale `[user:alice]` left above a newly added `[user:alice] enabled = false`
        // meant the admin disabled the account, saw it listed as disabled, and the shadow
        // copy went on authenticating. Reachable through the panel too — `put_config`
        // validates each username with `is_valid_ident` but never checks uniqueness, and
        // `to_ini_string` faithfully writes both sections back out.
        // (Audit 2026-07-27, C7.)
        let mut seen_users = std::collections::HashSet::new();
        let users: Vec<UserEntry> = doc
            .sections_of("user")
            .map(user_from)
            .filter(|u| !u.username.is_empty())
            .filter(|u| {
                if seen_users.insert(u.username.clone()) {
                    true
                } else {
                    log::warn!(
                        "config: duplicate inline [user:{}] — keeping the first block and \
                         ignoring the later one (the lookup only ever saw the first)",
                        u.username
                    );
                    false
                }
            })
            .collect();
        if !users.is_empty() {
            // Inline users win over an explicitly-set users_file — warn so it isn't a
            // silent surprise (users_file has a non-empty default, so only flag an
            // *explicit* key, not the default). (audit 1.9)
            let explicit_users_file = doc
                .section("auth")
                .and_then(|s| s.get("users_file"))
                .is_some();
            if explicit_users_file {
                log::warn!(
                    "config: both inline [user:*] blocks and an explicit auth.users_file \
                     are set — inline users take precedence; users_file is ignored"
                );
            }
            cfg.auth.users = users;
        }
        for g in doc.sections_of("group") {
            if let Some(name) = &g.instance {
                cfg.auth.groups.insert(name.clone(), group_from(g));
            }
        }
        UsersDb {
            users: cfg.auth.users.clone(),
            groups: cfg.auth.groups.clone(),
        }
        .validate_network_fields()?;
        // [web] / [logging] are populated in the struct-init above (with a serde baseline
        // when absent) — no separate override block needed.

        cfg.profiles = doc.sections_of("profile").map(profile_from).collect();
        if cfg.profiles.is_empty() {
            anyhow::bail!("server config: at least one [profile:<name>] section is required");
        }
        Ok(cfg)
    }

    /// Serialize to flat-INI text (the canonical on-disk format; used by the web
    /// "save config" path). Lossless — including an advertised-route `description`,
    /// which is emitted as a trailing `desc=` taking the rest of the line.
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
    // Emit `users_file` XOR inline `[user:*]`, never both. The separate users file is the
    // default; the web panel manages users through it (users_db → users.save(users_file)),
    // so a file-mode config carries no inline users (`a.users` is empty) and we write the
    // path. Only a config that was hand-written with inline `[user:*]` has `a.users`
    // populated — there `users_file` is dead weight (inline wins) and, if emitted, would
    // trip the both-sources warning on reload; so we omit it and keep the inline blocks
    // (written by `to_ini_string`). This keeps every serialized config single-source.
    if a.users.is_empty() {
        put_str(&mut s, "users_file", &a.users_file);
    }
    put(
        &mut s,
        "require_client_key_proof",
        a.require_client_key_proof,
    );
    put(&mut s, "bind_static_to_session", a.bind_static_to_session);
    put(&mut s, "brute_force.enabled", a.brute_force.enabled);
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
    a.require_client_key_proof =
        s.bool_or("require_client_key_proof", base.require_client_key_proof);
    a.bind_static_to_session = s.bool_or("bind_static_to_session", base.bind_static_to_session);
    a.brute_force.enabled = s.bool_or("brute_force.enabled", base.brute_force.enabled);
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
    if w.insecure_no_auth {
        put(&mut s, "insecure_no_auth", true);
    }
    if w.secure_cookie {
        put(&mut s, "secure_cookie", true);
    }
    // Default ON — emit only the opt-out so default configs stay clean.
    if !w.persist_session_key {
        put(&mut s, "persist_session_key", false);
    }
    if w.tls {
        put(&mut s, "tls", true);
    }
    if !w.tls_cert.is_empty() {
        put_str(&mut s, "tls_cert", &w.tls_cert);
    }
    if !w.tls_key.is_empty() {
        put_str(&mut s, "tls_key", &w.tls_key);
    }
    put_list(&mut s, "allowed_ips", &w.allowed_ips);
    if !w.public_host.is_empty() {
        put_str(&mut s, "public_host", &w.public_host);
    }
    put_list(&mut s, "allowed_origins", &w.allowed_origins);
    put_list(&mut s, "trusted_proxies", &w.trusted_proxies);
    if !w.base_path.is_empty() {
        put_str(&mut s, "base_path", &w.base_path);
    }
    if !w.csrf {
        put(&mut s, "csrf", false);
    }
    if w.update_check {
        put(&mut s, "update_check", true);
    }
    if w.session_ttl_secs != 86_400 {
        put(&mut s, "session_ttl_secs", w.session_ttl_secs);
    }
    // Panel-login brute-force policy (independent of `[auth] brute_force`).
    put(&mut s, "brute_force.enabled", w.brute_force.enabled);
    put(
        &mut s,
        "brute_force.max_attempts",
        w.brute_force.max_attempts,
    );
    put(&mut s, "brute_force.window_secs", w.brute_force.window_secs);
    put(
        &mut s,
        "brute_force.lockout_secs",
        w.brute_force.lockout_secs,
    );
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
    w.insecure_no_auth = s.bool_or("insecure_no_auth", base.insecure_no_auth);
    w.persist_session_key = s.bool_or("persist_session_key", base.persist_session_key);
    w.tls = s.bool_or("tls", base.tls);
    w.tls_cert = s.str_or("tls_cert", &base.tls_cert).to_string();
    w.tls_key = s.str_or("tls_key", &base.tls_key).to_string();
    if s.get("allowed_ips").is_some() {
        w.allowed_ips = s.list("allowed_ips");
    }
    w.public_host = s.str_or("public_host", &base.public_host).to_string();
    if s.get("allowed_origins").is_some() {
        w.allowed_origins = s.list("allowed_origins");
    }
    if s.get("trusted_proxies").is_some() {
        w.trusted_proxies = s.list("trusted_proxies");
    }
    w.base_path = s.str_or("base_path", &base.base_path).to_string();
    w.csrf = s.bool_or("csrf", base.csrf);
    w.update_check = s.bool_or("update_check", base.update_check);
    w.session_ttl_secs = s.parse_or("session_ttl_secs", base.session_ttl_secs);
    w.brute_force.enabled = s.bool_or("brute_force.enabled", base.brute_force.enabled);
    w.brute_force.max_attempts =
        s.parse_or("brute_force.max_attempts", base.brute_force.max_attempts);
    w.brute_force.window_secs = s.parse_or("brute_force.window_secs", base.brute_force.window_secs);
    w.brute_force.lockout_secs =
        s.parse_or("brute_force.lockout_secs", base.brute_force.lockout_secs);
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
    // Must be written, not just parsed: the panel round-trips the whole config
    // through this writer, so omitting the key here silently resets a user's
    // choice to the default on the next "Save to Disk".
    put_str(&mut s, "time_format", &l.time_format);
    s
}

fn logging_from(s: &Section) -> crate::config::LoggingConfig {
    let base: crate::config::LoggingConfig = serde_json::from_str("{}").unwrap();
    let mut l = base.clone();
    l.level = s.str_or("level", &base.level).to_string();
    l.file = s.get("file").filter(|f| !f.is_empty()).map(str::to_string);
    l.format = s.str_or("format", &base.format).to_string();
    l.time_format = s.str_or("time_format", &base.time_format).to_string();
    l
}

// ------------------------------- profile ------------------------------------

fn profile_to(p: &ProfileConfig) -> Section {
    let mut s = Section::new("profile", Some(p.name.clone()));
    // Emit EVERY key, including those that do nothing on this profile's transport.
    //
    // This used to emit transport-specific keys conditionally, to keep a generated config
    // tidy — but the parser accepts them all, so serialization was lossy in one direction
    // and the panel's Save silently deleted whatever the operator had written for the
    // other transport. Tidiness is not worth a save that loses data.
    // (Audit 2026-07-27, P5.)
    put(&mut s, "enabled", p.enabled);
    if let Some(k) = &p.identity_key {
        put_str(&mut s, "identity_key", k);
    }
    // bind
    put_str(&mut s, "bind.address", &p.bind.address);
    put(&mut s, "bind.port", p.bind.port);
    put_str(&mut s, "bind.transport", &p.bind.transport);
    for l in &p.bind.listen {
        put_str(&mut s, "listen", l);
    }
    // tun
    put(&mut s, "tun.ip_mode", p.tun.ip_mode);
    put_str(&mut s, "tun.name", &p.tun.name);
    put_str(&mut s, "tun.address", &p.tun.address);
    if let Some(address) = &p.tun.ipv6_address {
        put_str(&mut s, "tun.ipv6_address", address);
    }
    put(&mut s, "tun.mtu", p.tun.mtu);
    put(&mut s, "tun.tx_queue_len", p.tun.tx_queue_len);
    put_str(&mut s, "tun.device_type", &p.tun.device_type);
    put(&mut s, "tun.queues", p.tun.queues);
    // pool
    put_str(&mut s, "pool.cidr", &p.pool.cidr);
    put_list(&mut s, "pool.exclude", &p.pool.exclude);
    for (name, ip) in &p.pool.static_reservations {
        put_str(&mut s, &format!("pool.reservation.{}", name), ip);
    }
    if !p.pool.ipv6.cidr.is_empty() {
        put_str(&mut s, "pool.ipv6.cidr", &p.pool.ipv6.cidr);
    }
    put_list(&mut s, "pool.ipv6.exclude", &p.pool.ipv6.exclude);
    for (name, ip) in &p.pool.ipv6.static_reservations {
        put_str(&mut s, &format!("pool.ipv6.reservation.{}", name), ip);
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
    put(&mut s, "routing.ipv6.mode", p.routing.ipv6.mode);
    if !p.routing.ipv6.interface.is_empty() {
        put_str(&mut s, "routing.ipv6.interface", &p.routing.ipv6.interface);
    }
    if !p.routing.post_up.is_empty() {
        put_str(&mut s, "routing.post_up", &p.routing.post_up);
    }
    if !p.routing.post_down.is_empty() {
        put_str(&mut s, "routing.post_down", &p.routing.post_down);
    }
    for r in &p.routing.advertised_routes {
        let mut line = r.cidr.clone();
        if let Some(gw) = &r.gateway {
            line.push_str(&format!(" gateway={}", gw));
        }
        if let Some(m) = r.metric {
            line.push_str(&format!(" metric={}", m));
        }
        // `desc=` goes LAST and swallows the rest of the line — a description is free
        // text with spaces, so it cannot be a whitespace-delimited token like the keys
        // above. It used to be dropped here, so ANY structured save silently destroyed
        // a hand-written description; the round-trip is now lossless.
        if let Some(d) = r
            .description
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
        {
            line.push_str(&format!(" desc={}", d));
        }
        put_str(&mut s, "route", &line);
    }
    // dns
    put(&mut s, "dns.enabled", p.dns.enabled);
    put_str(&mut s, "dns.listen", &p.dns.listen);
    if let Some(address) = &p.dns.listen_ipv6 {
        put_str(&mut s, "dns.listen_ipv6", address);
    }
    put(&mut s, "dns.port", p.dns.port);
    put_list(&mut s, "dns.upstream", &p.dns.upstream);
    put_str(&mut s, "dns.upstream_protocol", &p.dns.upstream_protocol);
    put(&mut s, "dns.cache_size", p.dns.cache_size);
    put(&mut s, "dns.timeout_secs", p.dns.timeout_secs);
    put_list(&mut s, "dns.blocklist", &p.dns.blocklist);
    put_list(&mut s, "dns.push_servers", &p.dns.push_servers);
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
    put_str(&mut s, "obf.mode", &o.mode);
    if !o.obfs_key.is_empty() {
        put_str(&mut s, "obf.obfs_key", &o.obfs_key);
    }
    put_str(&mut s, "obf.obfs_fronting", &o.fronting);
    put_str(&mut s, "obf.tls.server_name", &o.tls.server_name);
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
    put(
        &mut s,
        "obf.tls.reality_proxy.peek_timeout_ms",
        o.tls.reality_proxy.peek_timeout_ms,
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
        "obf.traffic_shaping.enabled",
        o.traffic_shaping.enabled,
    );
    put(
        &mut s,
        "obf.traffic_shaping.idle_gap_mean_ms",
        o.traffic_shaping.idle_gap_mean_ms,
    );
    put(
        &mut s,
        "obf.traffic_shaping.idle_gap_min_ms",
        o.traffic_shaping.idle_gap_min_ms,
    );
    put(
        &mut s,
        "obf.traffic_shaping.idle_gap_max_ms",
        o.traffic_shaping.idle_gap_max_ms,
    );
    put(
        &mut s,
        "obf.traffic_shaping.budget_bytes_per_sec",
        o.traffic_shaping.budget_bytes_per_sec,
    );
    put(
        &mut s,
        "obf.traffic_shaping.min_size",
        o.traffic_shaping.min_size,
    );
    put(
        &mut s,
        "obf.traffic_shaping.max_size",
        o.traffic_shaping.max_size,
    );
    put(
        &mut s,
        "obf.traffic_shaping.stealth",
        o.traffic_shaping.stealth,
    );
    put(
        &mut s,
        "obf.traffic_shaping.stealth_rate_mbps",
        o.traffic_shaping.stealth_rate_mbps,
    );
    put(
        &mut s,
        "obf.anti_fingerprinting.enabled",
        o.anti_fingerprinting.enabled,
    );
    put(
        &mut s,
        "obf.anti_fingerprinting.add_jitter_to_handshake",
        o.anti_fingerprinting.add_jitter_to_handshake,
    );
    // QUIC masking is a UDP-only disguise; multipath stream-bonding is TCP-only — but BOTH
    // are emitted regardless of the current transport.
    //
    // They used to be written conditionally while the PARSER reads them unconditionally,
    // which made every save lossy: a UDP profile with hand-written `obf.multipath.*` (or
    // `perf.tcp.*` below) lost those lines the first time anyone pressed Save in the
    // panel, and the loss was invisible until the operator later switched
    // `bind.transport = tcp` and the profile came up on defaults instead of the tuning
    // they had written. The round-trip test did not catch it because its fixture only
    // carries keys matching its own transport. Writing everything costs a few lines in the
    // file and makes save idempotent for any input the parser accepts.
    // (Audit 2026-07-27, P5.)
    put(&mut s, "obf.quic.enabled", o.quic.enabled);
    put(&mut s, "obf.multipath.enabled", o.multipath.enabled);
    put(&mut s, "obf.multipath.max_streams", o.multipath.max_streams);
    put(&mut s, "obf.multipath.adaptive", o.multipath.adaptive);
    put(&mut s, "obf.awg.enabled", o.awg.enabled);
    put(&mut s, "obf.awg.jc", o.awg.jc);
    put(&mut s, "obf.awg.jmin", o.awg.jmin);
    put(&mut s, "obf.awg.jmax", o.awg.jmax);
    // performance
    let pf = &p.performance;
    // TCP socket tuning only applies to a TCP transport, but is emitted regardless — see
    // the note on obf.quic/obf.multipath above. (Audit 2026-07-27, P5.)
    put(&mut s, "perf.tcp.nodelay", pf.tcp.nodelay);
    put(&mut s, "perf.tcp.keepalive_secs", pf.tcp.keepalive_secs);
    put(&mut s, "perf.tcp.send_buffer_size", pf.tcp.send_buffer_size);
    put(&mut s, "perf.tcp.recv_buffer_size", pf.tcp.recv_buffer_size);
    put(&mut s, "perf.udp.send_buffer_size", pf.udp.send_buffer_size);
    if !pf.udp.recv_buffer_auto {
        put(&mut s, "perf.udp.recv_buffer_size", pf.udp.recv_buffer_size);
    }
    put(&mut s, "perf.tun.read_buffer_size", pf.tun.read_buffer_size);
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
        "perf.connection.new_session_rate_max",
        pf.connection.new_session_rate_max,
    );
    put(
        &mut s,
        "perf.connection.new_session_rate_window_secs",
        pf.connection.new_session_rate_window_secs,
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
    // Extra listeners (#12): each `listen` line is one address:port [transport] spec.
    p.bind.listen = s.all("listen").iter().map(|l| l.to_string()).collect();
    // tun
    p.tun.ip_mode = s.parse_or("tun.ip_mode", base.tun.ip_mode);
    p.tun.name = s.str_or("tun.name", &base.tun.name).to_string();
    p.tun.address = s.str_or("tun.address", &base.tun.address).to_string();
    p.tun.ipv6_address = s
        .get("tun.ipv6_address")
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    if let Some(legacy_netmask) = s.get("tun.netmask") {
        log::warn!(
            "profile '{}': legacy tun.netmask = '{}' is ignored; pool.cidr is the single \
             source of the server and client subnet prefix. Remove tun.netmask from the config.",
            p.name,
            legacy_netmask
        );
    }
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
    p.pool.static_reservations = HashMap::new();
    for (name, v) in s.entries_with_prefix("pool.reservation.") {
        if name.is_empty() {
            log::warn!(
                "config: skipping reservation with empty username ('pool.reservation. = {v}')"
            );
            continue;
        }
        p.pool
            .static_reservations
            .insert(name.to_string(), v.to_string());
    }
    p.pool.ipv6.cidr = s
        .get("pool.ipv6.cidr")
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if s.get("pool.ipv6.exclude").is_some() {
        p.pool.ipv6.exclude = s.list("pool.ipv6.exclude");
    }
    p.pool.ipv6.static_reservations = HashMap::new();
    for (name, v) in s.entries_with_prefix("pool.ipv6.reservation.") {
        if name.is_empty() {
            log::warn!(
                "config: skipping IPv6 reservation with empty username ('pool.ipv6.reservation. = {v}')"
            );
            continue;
        }
        p.pool
            .ipv6
            .static_reservations
            .insert(name.to_string(), v.to_string());
    }
    // routing
    p.routing.client_to_client =
        s.bool_or("routing.client_to_client", base.routing.client_to_client);
    p.routing.forward_private = s.bool_or("routing.forward_private", base.routing.forward_private);
    p.routing.nat.enabled = s.bool_or("routing.nat.enabled", base.routing.nat.enabled);
    p.routing.nat.interface = s
        .str_or("routing.nat.interface", &base.routing.nat.interface)
        .to_string();
    p.routing.ipv6.mode = s.parse_or("routing.ipv6.mode", base.routing.ipv6.mode);
    p.routing.ipv6.interface = s
        .str_or("routing.ipv6.interface", &base.routing.ipv6.interface)
        .to_string();
    p.routing.post_up = s
        .str_or("routing.post_up", &base.routing.post_up)
        .to_string();
    p.routing.post_down = s
        .str_or("routing.post_down", &base.routing.post_down)
        .to_string();
    p.routing.advertised_routes = s
        .all("route")
        .iter()
        .filter_map(|l| parse_route_checked(l))
        .collect();
    // dns
    p.dns.enabled = s.bool_or("dns.enabled", base.dns.enabled);
    p.dns.listen = s.str_or("dns.listen", &base.dns.listen).to_string();
    p.dns.listen_ipv6 = s
        .get("dns.listen_ipv6")
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
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
    if s.get("dns.push_servers").is_some() {
        p.dns.push_servers = s.list("dns.push_servers");
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
    o.mode = s.str_or("obf.mode", &bo.mode).to_string();
    o.obfs_key = s.str_or("obf.obfs_key", &bo.obfs_key).to_string();
    o.fronting = s.str_or("obf.obfs_fronting", &bo.fronting).to_string();
    o.tls.server_name = s
        .str_or("obf.tls.server_name", &bo.tls.server_name)
        .to_string();
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
    o.tls.reality_proxy.peek_timeout_ms = s.parse_or(
        "obf.tls.reality_proxy.peek_timeout_ms",
        bo.tls.reality_proxy.peek_timeout_ms,
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
    o.traffic_shaping.enabled =
        s.bool_or("obf.traffic_shaping.enabled", bo.traffic_shaping.enabled);
    o.traffic_shaping.idle_gap_mean_ms = s.parse_or(
        "obf.traffic_shaping.idle_gap_mean_ms",
        bo.traffic_shaping.idle_gap_mean_ms,
    );
    o.traffic_shaping.idle_gap_min_ms = s.parse_or(
        "obf.traffic_shaping.idle_gap_min_ms",
        bo.traffic_shaping.idle_gap_min_ms,
    );
    o.traffic_shaping.idle_gap_max_ms = s.parse_or(
        "obf.traffic_shaping.idle_gap_max_ms",
        bo.traffic_shaping.idle_gap_max_ms,
    );
    o.traffic_shaping.budget_bytes_per_sec = s.parse_or(
        "obf.traffic_shaping.budget_bytes_per_sec",
        bo.traffic_shaping.budget_bytes_per_sec,
    );
    o.traffic_shaping.min_size =
        s.parse_or("obf.traffic_shaping.min_size", bo.traffic_shaping.min_size);
    o.traffic_shaping.max_size =
        s.parse_or("obf.traffic_shaping.max_size", bo.traffic_shaping.max_size);
    o.traffic_shaping.stealth =
        s.bool_or("obf.traffic_shaping.stealth", bo.traffic_shaping.stealth);
    o.traffic_shaping.stealth_rate_mbps = s.parse_or(
        "obf.traffic_shaping.stealth_rate_mbps",
        bo.traffic_shaping.stealth_rate_mbps,
    );
    o.anti_fingerprinting.enabled = s.bool_or(
        "obf.anti_fingerprinting.enabled",
        bo.anti_fingerprinting.enabled,
    );
    o.anti_fingerprinting.add_jitter_to_handshake = s.bool_or(
        "obf.anti_fingerprinting.add_jitter_to_handshake",
        bo.anti_fingerprinting.add_jitter_to_handshake,
    );
    o.quic.enabled = s.bool_or("obf.quic.enabled", bo.quic.enabled);
    o.multipath.enabled = s.bool_or("obf.multipath.enabled", bo.multipath.enabled);
    o.multipath.max_streams = s.parse_or("obf.multipath.max_streams", bo.multipath.max_streams);
    o.multipath.adaptive = s.bool_or("obf.multipath.adaptive", bo.multipath.adaptive);
    o.awg.enabled = s.bool_or("obf.awg.enabled", bo.awg.enabled);
    o.awg.jc = s.parse_or("obf.awg.jc", bo.awg.jc);
    o.awg.jmin = s.parse_or("obf.awg.jmin", bo.awg.jmin);
    o.awg.jmax = s.parse_or("obf.awg.jmax", bo.awg.jmax);
    o.awg.sanitize(&format!("profile '{}' obf.awg", p.name));
    // performance
    let bp = &base.performance;
    let pf = &mut p.performance;
    pf.tcp.nodelay = s.bool_or("perf.tcp.nodelay", bp.tcp.nodelay);
    pf.tcp.keepalive_secs = s.parse_or("perf.tcp.keepalive_secs", bp.tcp.keepalive_secs);
    pf.tcp.send_buffer_size = s.parse_or("perf.tcp.send_buffer_size", bp.tcp.send_buffer_size);
    pf.tcp.recv_buffer_size = s.parse_or("perf.tcp.recv_buffer_size", bp.tcp.recv_buffer_size);
    pf.udp.send_buffer_size = s.parse_or("perf.udp.send_buffer_size", bp.udp.send_buffer_size);
    pf.udp.recv_buffer_auto = s.get("perf.udp.recv_buffer_size").is_none();
    pf.udp.recv_buffer_size = s.parse_or("perf.udp.recv_buffer_size", bp.udp.recv_buffer_size);
    pf.tun.read_buffer_size = s.parse_or("perf.tun.read_buffer_size", bp.tun.read_buffer_size);
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
    pf.connection.new_session_rate_max = s.parse_or(
        "perf.connection.new_session_rate_max",
        bp.connection.new_session_rate_max,
    );
    pf.connection.new_session_rate_window_secs = s.parse_or(
        "perf.connection.new_session_rate_window_secs",
        bp.connection.new_session_rate_window_secs,
    );
    p
}

#[cfg(test)]
mod route_line_tests {
    use super::parse_route_checked;

    #[test]
    fn good_lines_parse() {
        let r = parse_route_checked("172.16.20.0/24").unwrap();
        assert_eq!(r.cidr, "172.16.20.0/24");
        assert_eq!(r.gateway, None);
        assert_eq!(r.metric, None);

        let r = parse_route_checked("10.20.0.0/16 gateway=10.0.0.1 metric=50").unwrap();
        assert_eq!(r.cidr, "10.20.0.0/16");
        assert_eq!(r.gateway.as_deref(), Some("10.0.0.1"));
        assert_eq!(r.metric, Some(50));

        // explicit `cidr=` form
        assert_eq!(
            parse_route_checked("cidr=192.168.7.0/24").unwrap().cidr,
            "192.168.7.0/24"
        );
    }

    /// The exact line the panel emitted when the CIDR field was left empty and the
    /// subnet typed into `gateway` — it used to parse to an empty-cidr route and get
    /// pushed to clients, which silently dropped it. Now it is refused at load.
    #[test]
    fn empty_cidr_from_subnet_in_gateway_is_rejected() {
        assert!(parse_route_checked(" gateway=172.16.20.0/24 metric=100").is_none());
    }

    #[test]
    fn malformed_lines_are_rejected() {
        assert!(parse_route_checked("").is_none());
        assert!(parse_route_checked("172.16.20.0").is_none()); // no prefix
        assert!(parse_route_checked("172.16.20.0/33").is_none()); // bad prefix
        assert!(parse_route_checked("nonsense").is_none());
        // gateway must be a next-hop IP, never a subnet
        assert!(parse_route_checked("10.20.0.0/16 gateway=172.16.20.0/24").is_none());
        // Route and next-hop must use the same address family.
        assert!(parse_route_checked("2001:db8::/64 gateway=10.0.0.1").is_none());
        assert!(parse_route_checked("10.0.0.0/8 gateway=fd00::1").is_none());
    }
}

/// Parse AND validate a `route` line, dropping — with a loud warning — anything
/// whose CIDR or gateway is missing/malformed, so a typo can never reach clients
/// as a bogus pushed route.
///
/// The classic mistake (what the panel emits when the CIDR field is left empty)
/// is putting the subnet into `gateway=`:
/// ```text
/// route = " gateway=172.16.20.0/24 metric=100"   # WRONG: cidr empty, quoted
/// route = 172.16.20.0/24 gateway=10.0.0.1        # right: cidr first, gw = next hop
/// ```
/// Before 0.7.12 such a line parsed to an empty-cidr route and was pushed to
/// clients verbatim; they dropped it, and nothing was logged on either side.
fn parse_route_checked(line: &str) -> Option<PushedRoute> {
    let r = parse_route(line);
    if !crate::util::is_valid_cidr(&r.cidr) {
        log::warn!(
            "config: ignoring route {:?} — its CIDR is missing or invalid ({:?}). \
             Expected `route = <cidr> [gateway=<ip>] [metric=<n>]`, e.g. `route = 172.16.20.0/24` \
             (the CIDR comes FIRST; `gateway=` takes a next-hop IP, not a subnet).",
            line,
            r.cidr
        );
        return None;
    }
    if let Some(gw) = &r.gateway {
        if !crate::util::is_valid_gateway(gw) {
            log::warn!(
                "config: ignoring route {:?} — gateway {:?} is not a bare IP address \
                 (it is the next hop, not a subnet).",
                line,
                gw
            );
            return None;
        }
        let route_family = r
            .cidr
            .split_once('/')
            .and_then(|(address, _)| address.trim().parse::<std::net::IpAddr>().ok());
        let gateway_family = gw.trim().parse::<std::net::IpAddr>().ok();
        if !matches!(
            (route_family, gateway_family),
            (Some(std::net::IpAddr::V4(_)), Some(std::net::IpAddr::V4(_)))
                | (Some(std::net::IpAddr::V6(_)), Some(std::net::IpAddr::V6(_)))
        ) {
            log::warn!(
                "config: ignoring route {:?} — route CIDR and gateway use different address families",
                line
            );
            return None;
        }
    }
    Some(r)
}

/// Parse a `route` line: `<cidr> [gateway=<ip>] [metric=<n>]`.
fn parse_route(line: &str) -> PushedRoute {
    let mut r = PushedRoute::default();
    // Split `desc=` off FIRST: it is the last key and takes the whole remainder of the
    // line (a description contains spaces, so it can't be whitespace-tokenized like
    // cidr/gateway/metric). Everything before it is parsed as before.
    let head = match line.find("desc=") {
        Some(i) => {
            let d = line[i + "desc=".len()..].trim();
            if !d.is_empty() {
                r.description = Some(d.to_string());
            }
            &line[..i]
        }
        None => line,
    };
    for (i, tok) in head.split_whitespace().enumerate() {
        if i == 0 && !tok.contains('=') {
            r.cidr = tok.to_string();
        } else if let Some(v) = tok.strip_prefix("cidr=") {
            r.cidr = v.to_string();
        } else if let Some(v) = tok.strip_prefix("gateway=") {
            r.gateway = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("metric=") {
            match v.parse() {
                Ok(m) => r.metric = Some(m),
                Err(_) => log::warn!("config: ignoring invalid route metric {v:?} in {line:?}"),
            }
        }
    }
    r
}

// =============================== UsersDb (file) ==============================

impl UsersDb {
    /// Parse the standalone user database from flat INI (`[user:*]`/`[group:*]`).
    pub fn from_ini(doc: &IniDoc) -> UsersDb {
        // De-duplicate by username, keeping the FIRST occurrence (which is what find_user /
        // auth already select). A hand-edited file with two `[user:alice]` blocks otherwise
        // kept a shadow entry that re-emitted on save and lingered indefinitely. First-wins
        // matches the lookup semantics, so this only drops the never-consulted copy. (L7)
        let mut seen = std::collections::HashSet::new();
        let mut db = UsersDb {
            users: doc
                .sections_of("user")
                .map(user_from)
                .filter(|u| !u.username.is_empty())
                .filter(|u| seen.insert(u.username.clone()))
                .collect(),
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
    if let Some(e) = &u.password_enc {
        put_str(&mut s, "password_enc", e);
    }
    if let Some(ip) = &u.static_ip {
        put_str(&mut s, "static_ip", ip);
    }
    if let Some(ip) = &u.static_ipv6 {
        put_str(&mut s, "static_ipv6", ip);
    }
    put(&mut s, "enabled", u.enabled);
    put_list(&mut s, "allowed_networks", &u.allowed_networks);
    if let Some(g) = &u.group {
        put_str(&mut s, "group", g);
    }
    if u.max_sessions > 0 {
        put(&mut s, "max_sessions", u.max_sessions);
    }
    if u.data_limit_gb > 0 {
        put(&mut s, "data_limit_gb", u.data_limit_gb);
    }
    if let Some(exp) = u.expire_at {
        put(&mut s, "expire_at", exp);
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
    put_list(&mut s, "client_subnet", &u.client_subnets);
    s
}

fn user_from(s: &Section) -> UserEntry {
    let mut metadata = HashMap::new();
    for (name, v) in s.entries_with_prefix("metadata.") {
        metadata.insert(name.to_string(), v.to_string());
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
        password_enc: s
            .get("password_enc")
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        static_ip: s
            .get("static_ip")
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        static_ipv6: s
            .get("static_ipv6")
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        enabled: s.bool_or("enabled", true),
        allowed_networks: s.list("allowed_networks"),
        group: s.get("group").filter(|v| !v.is_empty()).map(str::to_string),
        max_sessions: s.parse_or("max_sessions", 0),
        data_limit_gb: s.parse_or("data_limit_gb", 0),
        // opt_parse warns on an unparseable value instead of silently treating a typo'd
        // date as "never expires" (the old silent .parse().ok()).
        expire_at: opt_parse(s, "expire_at"),
        profiles: s.list("profiles"),
        bandwidth: BandwidthLimit {
            limit_mbps: s.parse_or("bandwidth.limit_mbps", 0),
            burst_mbps: s.parse_or("bandwidth.burst_mbps", 0),
        },
        metadata,
        routes,
        client_subnets: s.list("client_subnet"),
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

/// Parse an optional numeric key, warning (not silently dropping) on a bad value —
/// consistent with `parse_or`, which also logs. (audit 1.5)
fn opt_parse<T: std::str::FromStr>(s: &Section, key: &str) -> Option<T> {
    let v = s.get(key)?;
    match v.parse() {
        Ok(x) => Some(x),
        Err(_) => {
            log::warn!("config: ignoring unparseable value {v:?} for '{key}'");
            // Record it like parse_or/bool_or so `check-config` fails on it. `opt_parse`
            // reads `expire_at` (account expiry) and group limits — a bad value here is
            // fail-open ("never expires" / "unlimited"), and without this it went unseen
            // by check-config, defeating the S-15 mechanism for exactly the fields where
            // fail-open matters most. (M5)
            s.record_bad_value(format!(
                "key '{key}' has an unparsable value {v:?} — the default was used (this may be \
                 fail-open, e.g. no expiry / no limit)"
            ));
            None
        }
    }
}

fn group_from(s: &Section) -> GroupTemplate {
    GroupTemplate {
        bandwidth_limit_mbps: opt_parse(s, "bandwidth_limit_mbps"),
        max_sessions: opt_parse(s, "max_sessions"),
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
    fn ipv6_flat_ini_round_trips_without_becoming_a_json_config() {
        let source = r#"
[profile:v6]
tun.ip_mode = dual
tun.address = 10.9.0.1
tun.ipv6_address = fd71:e1:1234:1::1
tun.mtu = 1400
pool.cidr = 10.9.0.0/24
pool.ipv6.cidr = fd71:e1:1234:1::/64
pool.ipv6.exclude = fd71:e1:1234:1::10
pool.ipv6.reservation.alice = fd71:e1:1234:1::50
routing.ipv6.mode = nat66
routing.ipv6.interface = eth0
dns.listen_ipv6 = fd71:e1:1234:1::1
dns.push_servers = 10.9.0.1, fd71:e1:1234:1::1
dns.upstream = 1.1.1.1, 2606:4700:4700::1111
route = 2001:db8:100::/48 gateway=fd71:e1:1234:1::1 metric=10

[user:alice]
password_hash = x
static_ip = 10.9.0.50
static_ipv6 = fd71:e1:1234:1::50
allowed_networks = 10.0.0.0/8, 2001:db8:200::/48
client_subnet = 192.168.50.0/24, 2001:db8:300::/56
route = 2001:db8:400::/48 gateway=fd71:e1:1234:1::1 metric=20
"#;
        let original = crate::config::parse_server_config(source).unwrap();
        let profile = &original.profiles[0];
        assert_eq!(profile.tun.ip_mode, IpMode::Dual);
        assert_eq!(
            profile.tun.ipv6_address.as_deref(),
            Some("fd71:e1:1234:1::1")
        );
        assert_eq!(profile.routing.ipv6.mode, Ipv6RoutingMode::Nat66);
        assert_eq!(profile.routing.advertised_routes.len(), 1);
        assert_eq!(
            original.auth.users[0].static_ipv6.as_deref(),
            Some("fd71:e1:1234:1::50")
        );

        let serialized = original.to_ini_string();
        assert!(serialized.contains("tun.ip_mode = dual"));
        assert!(serialized.contains("pool.ipv6.cidr = fd71:e1:1234:1::/64"));
        assert!(serialized.contains("static_ipv6 = fd71:e1:1234:1::50"));
        let reparsed = crate::config::parse_server_config(&serialized).unwrap();
        assert_eq!(
            serde_json::to_value(&original).unwrap(),
            serde_json::to_value(&reparsed).unwrap()
        );
    }

    #[test]
    fn invalid_ipv6_mode_is_reported_instead_of_falling_back_silently() {
        let (_, findings) = crate::config::parse_server_config_reporting(
            "[profile:x]\ntun.ip_mode = duall\nrouting.ipv6.mode = nat6\n",
        )
        .unwrap();
        let all = findings.join("\n");
        assert!(all.contains("tun.ip_mode"), "{all}");
        assert!(all.contains("routing.ipv6.mode"), "{all}");
    }

    /// An advertised-route `description` must survive parse → serialize → parse. It
    /// used to be DROPPED by the serializer, so any structured save from the panel
    /// silently destroyed a hand-written note. `desc=` is last and takes the rest of
    /// the line, so multi-word descriptions (and `=` inside them) round-trip too.
    #[test]
    fn route_description_round_trips() {
        let r = parse_route("10.0.0.0/8 gateway=10.0.0.1 metric=50 desc=office LAN (a=b)");
        assert_eq!(r.cidr, "10.0.0.0/8");
        assert_eq!(r.gateway.as_deref(), Some("10.0.0.1"));
        assert_eq!(r.metric, Some(50));
        assert_eq!(r.description.as_deref(), Some("office LAN (a=b)"));

        // A route with no description stays clean (no stray `desc=`).
        let plain = parse_route("192.168.0.0/24");
        assert_eq!(plain.cidr, "192.168.0.0/24");
        assert!(plain.description.is_none());
    }

    #[test]
    fn server_round_trip_preserves_fields() {
        // Parse a custom-values INI config, then serialize → re-parse and assert
        // the two are structurally identical (lossless round-trip).
        let ini_src = r#"
            [auth]
            require_client_key_proof = true
            bind_static_to_session = false

            [profile:edge]
            bind.address = 192.168.1.1
            bind.port = 8443
            bind.transport = udp
            tun.name = tun1
            tun.address = 10.1.0.1
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

            [logging]
            level = debug
            time_format = rfc3339
        "#;
        let orig = crate::config::parse_server_config(ini_src).unwrap();
        let ini = orig.to_ini_string();
        assert!(
            !ini.contains("tun.netmask"),
            "legacy tun.netmask must not be serialized again"
        );
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
        assert_eq!(p.pool.cidr, "10.1.0.0/16");
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
        assert!(back.auth.require_client_key_proof);
        // H-1 flag must survive the INI round-trip (regression guard: the flat-INI
        // auth codec must read AND write bind_static_to_session, not just the serde
        // default — a non-default `false` has to be honored, not silently forced on).
        assert!(!back.auth.bind_static_to_session);
        assert_eq!(back.logging.level, "debug");
        // Same class of bug as bind_static_to_session above: the codec must WRITE
        // time_format, not only read it. Without logging_to emitting the key, a
        // panel "Save to Disk" would silently reset the user's choice to datetime.
        assert_eq!(back.logging.time_format, "rfc3339");
    }

    #[test]
    fn legacy_tun_netmask_is_read_but_ignored_and_not_written() {
        let src = "\
[profile:legacy]\n\
tun.address = 10.20.0.1\n\
tun.netmask = 255.255.255.0\n\
pool.cidr = 10.20.0.0/16\n";
        let cfg = crate::config::parse_server_config(src).expect("legacy key must still parse");
        let profile = &cfg.profiles[0];
        assert_eq!(profile.pool.cidr, "10.20.0.0/16");
        assert_eq!(pool_subnet(&profile.pool.cidr).unwrap().prefix, 16);

        let json = serde_json::to_value(profile).unwrap();
        assert!(json["tun"].get("netmask").is_none());
        assert!(!cfg.to_ini_string().contains("tun.netmask"));
    }

    /// Saving must not drop keys that belong to the OTHER transport.
    ///
    /// The serializer emitted `obf.multipath.*` / `perf.tcp.*` only for TCP and
    /// `obf.quic.*` only for UDP, while the parser reads all of them unconditionally — so
    /// a UDP profile carrying hand-written multipath/TCP tuning lost it on the first panel
    /// save, and nobody noticed until the transport was switched later.
    /// (Audit 2026-07-27, P5.)
    #[test]
    fn saving_preserves_keys_of_the_other_transport() {
        let src = "\
[profile:udpone]
bind.transport = udp
obf.multipath.max_streams = 6
obf.multipath.enabled = true
perf.tcp.keepalive_secs = 77
obf.quic.enabled = true
";
        let cfg = crate::config::parse_server_config(src).expect("parses");
        let p = &cfg.profiles[0];
        assert_eq!(p.obfuscation.multipath.max_streams, 6);
        assert_eq!(p.performance.tcp.keepalive_secs, 77);

        // Round-trip through the serializer the panel uses.
        let out = cfg.to_ini_string();
        for token in [
            "obf.multipath.max_streams = 6",
            "perf.tcp.keepalive_secs = 77",
            "obf.quic.enabled = true",
        ] {
            assert!(
                out.contains(token),
                "save dropped {token:?} on a UDP profile\n--- out ---\n{out}"
            );
        }
        let back = crate::config::parse_server_config(&out).expect("re-parses");
        let bp = &back.profiles[0];
        assert_eq!(bp.obfuscation.multipath.max_streams, 6);
        assert_eq!(bp.performance.tcp.keepalive_secs, 77);
        assert!(bp.obfuscation.quic.enabled);
    }

    /// A duplicate inline `[user:*]` must collapse to the FIRST block, exactly as
    /// `UsersDb::from_ini` already did — otherwise disabling an account does nothing.
    ///
    /// `find_user` returns the first entry that matches AND is enabled, so a stale block
    /// above a newly-disabled one kept authenticating while the panel showed the account
    /// as disabled. (Audit 2026-07-27, C7.)
    #[test]
    fn duplicate_inline_user_keeps_only_the_first_block() {
        let src = "\
[profile:main]
bind.transport = tcp

[user:alice]
password_hash = $argon2id$first
enabled = true

[user:alice]
password_hash = $argon2id$second
enabled = false

[user:bob]
password_hash = $argon2id$bob
";
        let cfg = crate::config::parse_server_config(src).expect("parses");
        let alices: Vec<_> = cfg
            .auth
            .users
            .iter()
            .filter(|u| u.username == "alice")
            .collect();
        assert_eq!(alices.len(), 1, "the shadow copy must be dropped");
        assert_eq!(
            alices[0].password_hash, "$argon2id$first",
            "first block wins, matching find_user"
        );
        assert!(cfg.auth.users.iter().any(|u| u.username == "bob"));
        assert_eq!(cfg.auth.users.len(), 2);
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

    #[test]
    fn serializes_users_file_xor_inline_users() {
        // File mode (the default): no inline users → `users_file` is written, no [user:*].
        let file_mode =
            "[auth]\nusers_file = /etc/qeli/custom-users.conf\n\n[profile:tcp]\nbind.port = 443\n";
        let cfg = ServerConfig::from_ini(&IniDoc::parse(file_mode).unwrap()).unwrap();
        let out = cfg.to_ini_string();
        assert!(out.contains("users_file = /etc/qeli/custom-users.conf"));
        assert!(
            !out.contains("[user:"),
            "file-mode config must not gain inline users"
        );

        // Inline mode: inline users present → [user:*] written, NO `users_file` (it would be
        // dead weight — inline wins — and would trip the both-sources warning on reload).
        let inline_mode = "[auth]\nusers_file = /etc/qeli/custom-users.conf\n\n[profile:tcp]\nbind.port = 443\n\n[user:alice]\npassword_hash = $argon2id$v=19$m=16384,t=2,p=1$abc$def\n";
        let cfg2 = ServerConfig::from_ini(&IniDoc::parse(inline_mode).unwrap()).unwrap();
        let out2 = cfg2.to_ini_string();
        assert!(out2.contains("[user:alice]"));
        assert!(
            !out2.contains("users_file"),
            "inline-mode config must not also emit users_file (single-source)"
        );
    }

    #[test]
    fn udp_receive_buffer_mode_survives_server_ini_round_trip() {
        let automatic = crate::config::parse_server_config(
            "[profile:p]\nbind.port = 443\nbind.transport = udp\n",
        )
        .unwrap();
        assert!(automatic.profiles[0].performance.udp.recv_buffer_auto);
        assert!(
            !automatic
                .to_ini_string()
                .contains("perf.udp.recv_buffer_size"),
            "an omitted size must remain the implicit automatic policy"
        );

        let fixed = crate::config::parse_server_config(
            "[profile:p]\nbind.port = 443\nbind.transport = udp\n\
             perf.udp.recv_buffer_size = 4194304\n",
        )
        .unwrap();
        assert!(!fixed.profiles[0].performance.udp.recv_buffer_auto);
        let text = fixed.to_ini_string();
        assert!(text.contains("perf.udp.recv_buffer_size = 4194304"));
        let back = crate::config::parse_server_config(&text).unwrap();
        assert!(!back.profiles[0].performance.udp.recv_buffer_auto);
    }

    /// The structured panel performs INI -> JSON -> ServerConfig -> INI.  The automatic/fixed
    /// distinction is semantic even when the numeric value happens to equal the 4 MiB default,
    /// so it must survive that complete path rather than only a direct INI round-trip.
    #[test]
    fn udp_receive_buffer_mode_survives_structured_json_round_trip() {
        let fixed = crate::config::parse_server_config(
            "[profile:p]\nbind.port = 443\nbind.transport = udp\n\
             perf.udp.recv_buffer_size = 4194304\n",
        )
        .unwrap();
        let json = serde_json::to_value(&fixed).unwrap();
        assert_eq!(
            json["profiles"][0]["performance"]["udp"]["recv_buffer_auto"],
            serde_json::Value::Bool(false),
            "the structured API must carry the fixed/automatic policy bit"
        );
        let decoded: ServerConfig = serde_json::from_value(json).unwrap();
        let text = decoded.to_ini_string();
        assert!(text.contains("perf.udp.recv_buffer_size = 4194304"));
        let back = crate::config::parse_server_config(&text).unwrap();
        assert!(!back.profiles[0].performance.udp.recv_buffer_auto);
    }

    /// EXHAUSTIVE round-trip: every key server_ini.rs reads is set to a
    /// non-default value here (coverage proven mechanically by
    /// scripts/gen_roundtrip_fixture.py), then parse -> to_ini_string -> parse
    /// must reproduce the config byte-identically at the struct level. This is
    /// the read-AND-persist guard for the WHOLE server config surface: any key
    /// the codec reads but forgets to write (the logging_to/time_format bug
    /// class) flips its field back to default on the second parse and trips the
    /// serde_json equality below.
    #[test]
    fn exhaustive_round_trip_every_server_key() {
        let ini_src = r####"
[auth]
require_client_key_proof = true
bind_static_to_session = false
brute_force.enabled = false
brute_force.max_attempts = 9
brute_force.window_secs = 120
brute_force.lockout_secs = 600

[logging]
level = debug
file = /tmp/qeli-rt.log
format = json
time_format = rfc3339

[web]
enabled = true
bind = 0.0.0.0
port = 9091
username = root2
password_hash = $argon2id$v=19$m=16384,t=2,p=1$c2FsdHNhbHQ$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
insecure_no_auth = true
secure_cookie = true
persist_session_key = false
tls = true
tls_cert = /tmp/c.pem
tls_key = /tmp/k.pem
allowed_ips = 10.0.0.0/8
public_host = vpn.example.com
allowed_origins = https://a.example
trusted_proxies = 10.1.1.1
base_path = /panel
csrf = false
update_check = true
session_ttl_secs = 3600
brute_force.enabled = true
brute_force.max_attempts = 4
brute_force.window_secs = 90
brute_force.lockout_secs = 300

[user:carol]
password_hash = $argon2id$v=19$m=16384,t=2,p=1$c2FsdHNhbHQ$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
password_enc = ENCVAL123
static_ip = 10.5.0.77
enabled = false
allowed_networks = 10.0.0.0/8,172.16.0.0/12
group = staff
max_sessions = 3
data_limit_gb = 50
expire_at = 4102444800
profiles = tcpx,udpx
bandwidth.limit_mbps = 100
bandwidth.burst_mbps = 150
client_subnet = 192.168.88.0/24
route = 10.77.0.0/16 gateway=10.5.0.1 metric=7

[group:staff]
bandwidth_limit_mbps = 200
max_sessions = 10
allowed_networks = 10.0.0.0/8

[profile:tcpx]
enabled = false
identity_key = /tmp/id-t.key
bind.address = 192.168.5.5
bind.port = 8501
bind.transport = tcp
tun.name = tunat
tun.address = 10.5.0.1
tun.mtu = 1380
tun.tx_queue_len = 2000
tun.device_type = tap
tun.queues = 2
pool.cidr = 10.5.0.0/16
pool.exclude = 10.5.0.2
pool.reservation.alice = 10.5.0.50
routing.client_to_client = true
routing.forward_private = false
routing.nat.enabled = true
routing.nat.interface = eth7
routing.post_up = echo up
routing.post_down = echo down
route = 10.5.9.0/24 gateway=10.5.0.1 metric=42 desc=lan seg
dns.enabled = false
dns.listen = 10.5.0.1
dns.port = 5353
dns.upstream = 9.9.9.9
dns.upstream_protocol = tcp
dns.cache_size = 256
dns.timeout_secs = 7
dns.blocklist = ads.example
dns.push_servers = 1.0.0.1
dhcp.enabled = true
dhcp.listen = 10.5.0.1
dhcp.pool_start = 10.5.0.100
dhcp.pool_end = 10.5.0.200
dhcp.lease_time_secs = 7200
dhcp.domain_name = lan.local
obf.mode = obfs
obf.obfs_key = shared-secret-t
obf.obfs_fronting = none
obf.tls.server_name = www.bing.com
obf.tls.reality_proxy.enabled = true
obf.tls.reality_proxy.target = www.apple.com
obf.tls.reality_proxy.target_port = 8443
obf.tls.reality_proxy.short_ids = deadbeef
obf.tls.reality_proxy.real_tls = true
obf.tls.reality_proxy.handrolled = false
obf.tls.reality_proxy.peek_timeout_ms = 900
obf.padding.enabled = false
obf.padding.min_bytes = 48
obf.padding.max_bytes = 900
obf.padding.randomize = false
obf.padding.probability = 0.5
obf.fragmentation.enabled = false
obf.fragmentation.min_chunk_size = 100
obf.fragmentation.max_chunk_size = 900
obf.fragmentation.max_fragments_per_packet = 8
obf.heartbeat.enabled = false
obf.heartbeat.interval_ms = 9000
obf.heartbeat.data_size_bytes = 24
obf.heartbeat.jitter_ms = 300
obf.traffic_normalization.enabled = true
obf.traffic_normalization.round_sizes = 100,200
obf.traffic_shaping.enabled = true
obf.traffic_shaping.idle_gap_mean_ms = 500
obf.traffic_shaping.idle_gap_min_ms = 30
obf.traffic_shaping.idle_gap_max_ms = 5000
obf.traffic_shaping.budget_bytes_per_sec = 8192
obf.traffic_shaping.min_size = 50
obf.traffic_shaping.max_size = 900
obf.traffic_shaping.stealth = true
obf.traffic_shaping.stealth_rate_mbps = 5
obf.anti_fingerprinting.enabled = true
obf.anti_fingerprinting.add_jitter_to_handshake = false
obf.awg.enabled = true
obf.awg.jc = 5
obf.awg.jmin = 30
obf.awg.jmax = 150
obf.multipath.enabled = true
obf.multipath.max_streams = 6
obf.multipath.adaptive = true
perf.tcp.nodelay = false
perf.tcp.keepalive_secs = 45
perf.tcp.send_buffer_size = 131072
perf.tcp.recv_buffer_size = 131072
perf.tun.read_buffer_size = 32768
perf.connection.max_clients = 64
perf.connection.handshake_timeout_secs = 8
perf.connection.idle_timeout_secs = 300
perf.connection.new_session_rate_max = 20
perf.connection.new_session_rate_window_secs = 11

[profile:udpx]
enabled = false
identity_key = /tmp/id-u.key
bind.address = 192.168.5.5
bind.port = 8502
bind.transport = udp
tun.name = tunau
tun.address = 10.6.0.1
tun.mtu = 1380
tun.tx_queue_len = 2000
tun.device_type = tap
tun.queues = 2
pool.cidr = 10.6.0.0/16
pool.exclude = 10.6.0.2
pool.reservation.alice = 10.6.0.50
routing.client_to_client = true
routing.forward_private = false
routing.nat.enabled = true
routing.nat.interface = eth7
routing.post_up = echo up
routing.post_down = echo down
route = 10.6.9.0/24 gateway=10.6.0.1 metric=42 desc=lan seg
dns.enabled = false
dns.listen = 10.6.0.1
dns.port = 5353
dns.upstream = 9.9.9.9
dns.upstream_protocol = tcp
dns.cache_size = 256
dns.timeout_secs = 7
dns.blocklist = ads.example
dns.push_servers = 1.0.0.1
dhcp.enabled = true
dhcp.listen = 10.6.0.1
dhcp.pool_start = 10.6.0.100
dhcp.pool_end = 10.6.0.200
dhcp.lease_time_secs = 7200
dhcp.domain_name = lan.local
obf.mode = obfs
obf.obfs_key = shared-secret-u
obf.obfs_fronting = none
obf.tls.server_name = www.bing.com
obf.tls.reality_proxy.enabled = true
obf.tls.reality_proxy.target = www.apple.com
obf.tls.reality_proxy.target_port = 8443
obf.tls.reality_proxy.short_ids = deadbeef
obf.tls.reality_proxy.real_tls = true
obf.tls.reality_proxy.handrolled = false
obf.tls.reality_proxy.peek_timeout_ms = 900
obf.padding.enabled = false
obf.padding.min_bytes = 48
obf.padding.max_bytes = 900
obf.padding.randomize = false
obf.padding.probability = 0.5
obf.fragmentation.enabled = false
obf.fragmentation.min_chunk_size = 100
obf.fragmentation.max_chunk_size = 900
obf.fragmentation.max_fragments_per_packet = 8
obf.heartbeat.enabled = false
obf.heartbeat.interval_ms = 9000
obf.heartbeat.data_size_bytes = 24
obf.heartbeat.jitter_ms = 300
obf.traffic_normalization.enabled = true
obf.traffic_normalization.round_sizes = 100,200
obf.traffic_shaping.enabled = true
obf.traffic_shaping.idle_gap_mean_ms = 500
obf.traffic_shaping.idle_gap_min_ms = 30
obf.traffic_shaping.idle_gap_max_ms = 5000
obf.traffic_shaping.budget_bytes_per_sec = 8192
obf.traffic_shaping.min_size = 50
obf.traffic_shaping.max_size = 900
obf.traffic_shaping.stealth = true
obf.traffic_shaping.stealth_rate_mbps = 5
obf.anti_fingerprinting.enabled = true
obf.anti_fingerprinting.add_jitter_to_handshake = false
obf.awg.enabled = true
obf.awg.jc = 5
obf.awg.jmin = 30
obf.awg.jmax = 150
obf.quic.enabled = true
perf.tun.read_buffer_size = 32768
perf.connection.max_clients = 64
perf.connection.handshake_timeout_secs = 8
perf.connection.idle_timeout_secs = 300
perf.connection.new_session_rate_max = 20
perf.connection.new_session_rate_window_secs = 11

"####;
        let orig = crate::config::parse_server_config(ini_src).unwrap();
        let ini = orig.to_ini_string();
        let doc = IniDoc::parse(&ini).unwrap();
        let back = ServerConfig::from_ini(&doc).unwrap();
        let a = serde_json::to_value(&orig).unwrap();
        let b = serde_json::to_value(&back).unwrap();
        assert_eq!(a, b, "server INI round-trip dropped or altered a field");

        // Spot-checks on the long tail so a failure names the offender.
        let tcp = back.profiles.iter().find(|p| p.name == "tcpx").unwrap();
        let udp = back.profiles.iter().find(|p| p.name == "udpx").unwrap();
        assert_eq!(tcp.tun.device_type, "tap");
        assert_eq!(tcp.tun.queues, 2);
        assert_eq!(tcp.obfuscation.multipath.max_streams, 6);
        assert!(tcp.obfuscation.traffic_shaping.stealth);
        assert_eq!(tcp.obfuscation.traffic_shaping.stealth_rate_mbps, 5);
        assert!(tcp.obfuscation.anti_fingerprinting.enabled);
        assert!(!tcp.performance.tcp.nodelay);
        assert_eq!(tcp.dns.upstream_protocol, "tcp");
        assert!(udp.obfuscation.quic.enabled);
        assert!(back.web.enabled);
        assert_eq!(back.web.session_ttl_secs, 3600);
        assert!(back.web.tls);
        assert_eq!(back.web.brute_force.max_attempts, 4);
        assert_eq!(back.auth.brute_force.max_attempts, 9);
        assert_eq!(back.logging.time_format, "rfc3339");
    }
}
