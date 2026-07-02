pub mod client_manager;
pub mod control;
pub mod dhcp;
pub mod dns;
pub mod handler;
pub mod metrics;
pub mod nat;
pub mod notify;
pub mod pool;
pub mod reality;
pub mod udp_handler;
pub mod update;
pub mod usage;
pub mod web;

use crate::config::server::{ProfileConfig, ServerConfig};
use crate::config::users::UsersDb;
use crate::crypto::StaticKeypair;
use crate::server::handler::SessionShared;
use crate::transport::tcp::set_tcp_keepalive;
use crate::transport::TransportProtocol;
use crate::tun::iface::TunInterface;
use crate::tun::prepend_ethernet_header;
use crate::tun::strip_ethernet_header;
use crate::tun::DeviceType;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex, RwLock};

/// Lock a Mutex, recovering the inner value if a prior holder panicked.
/// Logs a warning on poisoning so silent corruption is at least observable.
pub fn lock_or_recover<'a, T>(
    m: &'a std::sync::Mutex<T>,
    where_: &'static str,
) -> std::sync::MutexGuard<'a, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            log::warn!("mutex poisoned in {} — recovering", where_);
            poisoned.into_inner()
        }
    }
}

/// Hard cap on the number of distinct source IPs tracked at once. A spoofed UDP
/// flood can present a unique forged source IP per packet; without a bound the
/// `attempts` map would grow one small entry per IP until the 300s cleanup
/// interval elapses. When the map exceeds this cap we run [`cleanup`] eagerly
/// (reclaiming any expired entries) and, if it is *still* over the cap (a live
/// flood of unique IPs all inside the window), clear the map entirely. Dropping
/// the table is safe: the entries are transient per-IP counters, and the real
/// pre-auth flood defenses (`MAX_PENDING_HANDSHAKES` + the pre-auth semaphore)
/// are unaffected. The cap is far above any plausible count of legitimate
/// distinct clients within the window.
const MAX_TRACKED_IPS: usize = 100_000;

pub struct RateLimiter {
    attempts: HashMap<IpAddr, VecDeque<Instant>>,
    max_attempts: usize,
    window: Duration,
    last_cleanup: Instant,
    cleanup_interval: Duration,
}

impl RateLimiter {
    pub fn new(max_attempts: usize, window_secs: u64) -> Self {
        RateLimiter {
            attempts: HashMap::new(),
            max_attempts,
            window: Duration::from_secs(window_secs),
            last_cleanup: Instant::now(),
            cleanup_interval: Duration::from_secs(300),
        }
    }

    pub fn check_and_record(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) > self.cleanup_interval
            || self.attempts.len() > MAX_TRACKED_IPS
        {
            self.cleanup();
            // A live spoofed flood can present unique forged source IPs faster
            // than the window expires them, so cleanup alone may not shrink the
            // map. If it is still over the cap, drop the table wholesale to keep
            // memory bounded — these are transient per-IP counters and the real
            // flood defenses live elsewhere (see MAX_TRACKED_IPS).
            if self.attempts.len() > MAX_TRACKED_IPS {
                self.attempts.clear();
            }
            self.last_cleanup = now;
        }
        let window = self.window;
        let entry = self.attempts.entry(ip).or_default();
        while entry
            .front()
            .map(|t| now.duration_since(*t) > window)
            .unwrap_or(false)
        {
            entry.pop_front();
        }
        if entry.len() >= self.max_attempts {
            return false;
        }
        entry.push_back(now);
        true
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        let window = self.window;
        self.attempts.retain(|_, timestamps| {
            timestamps.retain(|t| now.duration_since(*t) <= window);
            !timestamps.is_empty()
        });
    }
}

/// Anti-replay guard for REALITY `session_id` tokens.
///
/// A censor can capture a genuine ClientHello off the wire and replay it verbatim
/// while the embedded timestamp is still inside the acceptance window. Without a
/// memory of what we have already accepted, the replay re-authenticates and the
/// server unmasks itself: it terminates TLS (serving a ServerHello that does not
/// match `dest`) where a real host would simply relay the target. This guard
/// remembers every accepted token for a TTL and reports a second sighting as a
/// replay, so the caller bridges it to `dest` like any unauthenticated peer.
///
/// Honest clients never trigger a false positive: each connection seals a fresh
/// X25519 ephemeral into the token, so two genuine ClientHellos differ even with
/// the same short_id in the same second. Only a byte-for-byte replay repeats one.
///
/// The TTL is twice the acceptance window (`reality::REALITY_WINDOW_SECS`): a
/// token stays timestamp-valid for up to ±window around its embedded time — a
/// 2×window span — so 2×window retention guarantees we never forget a token that
/// could still be accepted. Expired entries are evicted FIFO on every call, so
/// memory is bounded by the number of distinct tokens accepted within the window.
pub struct ReplayGuard {
    seen: HashSet<[u8; 32]>,
    fifo: VecDeque<(Instant, [u8; 32])>,
    ttl: Duration,
}

impl ReplayGuard {
    pub fn new(ttl: Duration) -> Self {
        ReplayGuard {
            seen: HashSet::new(),
            fifo: VecDeque::new(),
            ttl,
        }
    }

    /// Record `sid` and report whether it is fresh: `true` the first time a token
    /// is seen within the TTL, `false` on replay.
    pub fn observe(&mut self, sid: &[u8; 32]) -> bool {
        self.observe_at(sid, Instant::now())
    }

    /// `observe` with an explicit clock, for deterministic tests.
    fn observe_at(&mut self, sid: &[u8; 32], now: Instant) -> bool {
        // Evict everything older than the window (oldest at the front).
        while let Some(&(t, id)) = self.fifo.front() {
            if now.saturating_duration_since(t) < self.ttl {
                break;
            }
            self.fifo.pop_front();
            self.seen.remove(&id);
        }
        if !self.seen.insert(*sid) {
            return false; // already accepted within the window → replay
        }
        self.fifo.push_back((now, *sid));
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.seen.len()
    }
}

pub struct SessionMap {
    /// Tunnel IP → session. With multipath a session aggregates several bonded
    /// connections (streams) behind this one IP.
    pub by_ip: HashMap<std::net::Ipv4Addr, Arc<SessionShared>>,
    /// Join token → tunnel IP, for attaching secondary bonded streams.
    pub by_token: HashMap<[u8; crate::server::handler::JOIN_TOKEN_LEN], std::net::Ipv4Addr>,
}

/// Per-profile runtime state (pool, sessions, rate limiter).
pub struct ProfileRuntime {
    pub name: String,
    pub config: ProfileConfig,
    pub pool: Arc<Mutex<pool::IpPool>>,
    pub sessions: Arc<RwLock<SessionMap>>,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    /// This profile's own server identity (static X25519) keypair — distinct
    /// per interface, so a client pins the key of the interface it uses.
    pub static_keypair: Arc<StaticKeypair>,
    /// Cached rustls server config for REALITY real-TLS termination, built once
    /// at profile start when `reality_proxy.real_tls` is set — avoids generating
    /// a certificate per connection. `None` when real-TLS is off.
    pub reality_tls_config: Option<Arc<rustls::ServerConfig>>,
    /// Anti-replay memory for accepted REALITY session_id tokens — rejects a
    /// captured ClientHello replayed within the acceptance window.
    pub reality_replay: Arc<Mutex<ReplayGuard>>,
    /// TLS-shape to mirror in the hand-rolled ServerHello, probed once from the
    /// REALITY target at profile start. `Some` only when `real_tls + handrolled`.
    /// Borrowed REALITY state (target ServerHello shape + its real cert chain) behind
    /// a lock so a periodic refresh task tracks the target's TLS rotation. `Some` only
    /// for real_tls + handrolled. Hand-rolled terminator presents the borrowed chain;
    /// `None` falls back to a dummy cert.
    pub reality_borrow:
        Option<Arc<std::sync::RwLock<crate::protocol::realtls::server::BorrowState>>>,
}

/// Failed-auth tracker.
///
/// Source IPs get a *hard lockout* after too many failures — a single abusive
/// IP is cut off. Usernames, by contrast, are **never hard-locked**: doing so
/// would let anyone deny a known account service simply by spending its
/// attempts (the classic account-lockout DoS). Instead a username under active
/// guessing incurs an adaptive, capped **tarpit** (delay) that throttles
/// distributed brute-force just as effectively as a lockout — it bounds
/// guesses/second — while a correct password is always still accepted. The
/// caller sleeps `user_tarpit()` before verifying credentials.
pub struct FailedAuthTracker {
    /// Per-username recent-failure timestamps (drives the tarpit). No lockout
    /// instant: a username is never hard-blocked, so it cannot be DoS'd.
    by_user: HashMap<String, VecDeque<Instant>>,
    by_ip: HashMap<IpAddr, (VecDeque<Instant>, Option<Instant>)>,
    max_attempts: u32,
    window: Duration,
    lockout: Duration,
    /// Tarpit unit delay (applied once recent failures reach `max_attempts`,
    /// then doubled per extra failure) and its hard cap so a legitimate user
    /// authenticating during an attack waits at most `tarpit_max`.
    tarpit_base: Duration,
    tarpit_max: Duration,
    /// Opportunistic-sweep gate: mirrors [`RateLimiter`] so the by_user / by_ip
    /// maps cannot grow without bound (each distinct attacker username / IP would
    /// otherwise leave a permanent, if tiny, entry).
    last_cleanup: Instant,
    cleanup_interval: Duration,
}

/// Longest username key we keep in the tarpit map. A caller may pass an
/// arbitrarily long attacker-controlled username; without this cap each distinct
/// oversized string would be stored verbatim, letting a peer pin megabytes of
/// keys. 64 bytes comfortably covers any legitimate account name.
const MAX_TRACKED_USERNAME_LEN: usize = 64;

impl FailedAuthTracker {
    pub fn new(max_attempts: u32, window_secs: u64, lockout_secs: u64) -> Self {
        FailedAuthTracker {
            by_user: HashMap::new(),
            by_ip: HashMap::new(),
            max_attempts,
            window: Duration::from_secs(window_secs),
            lockout: Duration::from_secs(lockout_secs),
            tarpit_base: Duration::from_millis(200),
            tarpit_max: Duration::from_secs(3),
            last_cleanup: Instant::now(),
            cleanup_interval: Duration::from_secs(300),
        }
    }

    /// Drop entries that no longer hold any live state: a username whose recent
    /// failures have all aged out of the window, and an IP whose failures aged
    /// out AND whose lockout (if any) has expired. Gated by `last_cleanup` /
    /// `cleanup_interval` so it runs at most every 5 minutes, mirroring
    /// [`RateLimiter::cleanup`].
    fn cleanup(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) <= self.cleanup_interval {
            return;
        }
        self.last_cleanup = now;
        let window = self.window;
        self.by_user.retain(|_, q| {
            q.retain(|t| now.duration_since(*t) < window);
            !q.is_empty()
        });
        self.by_ip.retain(|_, (fails, until)| {
            fails.retain(|t| now.duration_since(*t) < window);
            let locked = until.map(|u| now < u).unwrap_or(false);
            !fails.is_empty() || locked
        });
    }

    /// Current `(max_attempts, window, lockout)` — lets a SIGHUP reload decide
    /// whether the brute-force policy actually changed, so live lockouts can be
    /// preserved when it did not.
    pub fn thresholds(&self) -> (u32, Duration, Duration) {
        (self.max_attempts, self.window, self.lockout)
    }

    /// Hard lockout check — source IP only. A username is never hard-locked
    /// (see [`Self::user_tarpit`]), so a flood of failures for a victim's
    /// username can never deny that victim service.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), String> {
        let now = Instant::now();
        if let Some((_, Some(until))) = self.by_ip.get(&ip) {
            if now < *until {
                let secs = until.duration_since(now).as_secs();
                return Err(format!(
                    "source IP locked for {}s after too many failed attempts",
                    secs
                ));
            }
        }
        Ok(())
    }

    /// Adaptive throttle for `username`: [`Duration::ZERO`] in steady state, a
    /// capped exponential delay once recent failures exceed `max_attempts`. The
    /// caller sleeps this long before the Argon2 verify, so distributed guessing
    /// of one account is rate-limited while a correct credential still passes.
    pub fn user_tarpit(&self, username: &str) -> Duration {
        let now = Instant::now();
        let recent = self
            .by_user
            .get(username)
            .map(|q| {
                q.iter()
                    .filter(|t| now.duration_since(**t) < self.window)
                    .count() as u32
            })
            .unwrap_or(0);
        if recent < self.max_attempts {
            return Duration::ZERO;
        }
        // Exponent capped so the Duration multiply can never overflow; the
        // result is in any case clamped to `tarpit_max`.
        let over = (recent - self.max_attempts + 1).min(16);
        (self.tarpit_base * 2u32.saturating_pow(over)).min(self.tarpit_max)
    }

    /// Record a failure against the source IP only. Used for pre-credential
    /// rejections (e.g. a missing server-key proof): a scanner that never
    /// presented a real username must not be able to drive any username's
    /// tarpit — only its own IP gets locked.
    /// Returns `true` if this failure leaves the source IP in a locked state (so the
    /// caller can fire an "IP lockout" notification).
    pub fn record_ip_failure(&mut self, ip: IpAddr) -> bool {
        self.cleanup();
        let now = Instant::now();
        let window = self.window;
        let max = self.max_attempts as usize;
        let lockout = self.lockout;
        let ip_entry = self.by_ip.entry(ip).or_default();
        ip_entry.0.retain(|t| now.duration_since(*t) < window);
        ip_entry.0.push_back(now);
        if ip_entry.0.len() >= max {
            ip_entry.1 = Some(now + lockout);
            log::warn!(
                "AUTH LOCKOUT (ip): {} locked for {}s after {} failed attempts",
                ip,
                lockout.as_secs(),
                self.max_attempts
            );
            true
        } else {
            false
        }
    }

    /// Record a credential failure (wrong password / unknown user): counts
    /// against both the username tarpit and the source-IP hard lockout. Returns
    /// `true` if the source IP is now locked (for lockout notifications).
    pub fn record_failure(&mut self, username: &str, ip: IpAddr) -> bool {
        let now = Instant::now();
        // Skip storing pathologically long attacker-controlled usernames so the
        // tarpit map can't be inflated with megabyte keys. The IP hard-lock
        // below still fires, so an oversized-username sprayer is not privileged.
        if username.len() <= MAX_TRACKED_USERNAME_LEN {
            let window = self.window;
            let user_entry = self.by_user.entry(username.to_string()).or_default();
            user_entry.retain(|t| now.duration_since(*t) < window);
            user_entry.push_back(now);
        }
        self.record_ip_failure(ip)
    }

    /// Clear failure history for this username on successful auth. The IP
    /// bucket is intentionally not cleared — one good login does not absolve
    /// an IP that has been spraying.
    pub fn record_success(&mut self, username: &str) {
        self.by_user.remove(username);
    }

    /// List IPs currently hard-locked by brute-force protection: for each, the
    /// number of recent failures and how many seconds remain until it unblocks.
    /// Read-only; the caller holds the tracker lock.
    pub fn list_blocked_ips(&self) -> Vec<(IpAddr, u32, u64)> {
        let now = Instant::now();
        self.by_ip
            .iter()
            .filter_map(|(ip, (fails, until))| {
                let until = (*until)?; // only currently-locked IPs
                if until <= now {
                    return None; // lockout already expired
                }
                let count = fails
                    .iter()
                    .filter(|t| now.duration_since(**t) < self.window)
                    .count() as u32;
                Some((*ip, count, until.saturating_duration_since(now).as_secs()))
            })
            .collect()
    }

    /// Manually unblock ONE IP: clears its lockout and failure history.
    /// Returns true if the IP had any tracked state.
    pub fn unblock_ip(&mut self, ip: IpAddr) -> bool {
        let existed = self.by_ip.remove(&ip).is_some();
        if existed {
            log::info!("AUTH UNBLOCK (manual): {} cleared", ip);
        }
        existed
    }

    /// Clear ALL per-IP lockout / failure state. Returns how many IPs were tracked.
    pub fn clear_all_ips(&mut self) -> usize {
        let n = self.by_ip.len();
        self.by_ip.clear();
        if n > 0 {
            log::warn!("AUTH UNBLOCK (manual): all {} tracked IP(s) cleared", n);
        }
        n
    }
}

/// Command the web panel (in the supervisor) sends to the supervisor loop to
/// act on the data-plane worker child process.
#[derive(Debug, Clone, Copy)]
pub enum WorkerCmd {
    /// Restart the worker (SIGTERM + respawn) — applies profile/config changes.
    Restart,
    /// SIGHUP the worker to hot-reload users / brute-force thresholds.
    ReloadUsers,
}

/// Shared server state (auth, users, identity key, profile registry).
///
/// Used in two roles: the **worker** process (full data-plane: profiles +
/// control socket, `worker_tx = None`) and the **supervisor** process (web
/// panel only; `profiles` stays empty and it reaches live data over the control
/// socket; `worker_tx = Some` to drive the worker child).
pub struct ServerState {
    pub config: ServerConfig,
    pub users_db: Arc<RwLock<UsersDb>>,
    pub config_path: Mutex<Option<String>>,
    pub profiles: Arc<RwLock<HashMap<String, Arc<ProfileRuntime>>>>,
    pub failed_auth: Arc<Mutex<FailedAuthTracker>>,
    /// Supervisor → worker control channel. `Some` only in the supervisor.
    pub worker_tx: Option<tokio::sync::mpsc::Sender<WorkerCmd>>,
    /// Outbound client tunnels the web panel can dial to other servers (lives in
    /// the supervisor, which serves the panel and has CAP_NET_ADMIN for the TUN).
    pub client_manager: Arc<client_manager::ClientManager>,
    /// Host + tunnel metrics for the dashboard (1 Hz sampler, supervisor-only).
    pub metrics: Arc<metrics::MetricsState>,
    /// Per-user lifetime traffic + quota bookkeeping (Tier-2). The worker accrues
    /// and enforces it; the supervisor's copy is reloaded for panel reads.
    pub usage: Arc<usage::UsageStore>,
    /// Live, hot-reloadable copy of the `[web]` panel settings the SUPERVISOR
    /// authenticates the panel with (admin password/username, IP allowlist, CSRF
    /// origins, public host). `config.web` is the frozen startup snapshot; the
    /// panel reads THIS instead, so a web-settings change applies without a full
    /// process restart. Socket-bound fields (bind/port/tls/enabled) still need a
    /// restart and are read from `config.web`.
    pub live_web: Arc<RwLock<crate::config::server::WebConfig>>,
}

impl ServerState {
    /// Refresh the supervisor's live `[web]` settings from the on-disk config, so
    /// a panel change to the admin password / IP allowlist / CSRF origins /
    /// public host takes effect immediately, without a full process restart.
    /// Called after the panel writes the config file. Bind/port/TLS/enabled are
    /// bound at startup and are NOT swapped here (they still require a restart).
    pub async fn reload_web_settings(&self) {
        let path = match self.config_path.lock().await.clone() {
            Some(p) => p,
            None => return,
        };
        let new_web = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| crate::config::parse_server_config(&s).ok())
            .map(|c| c.web);
        if let Some(web) = new_web {
            *self.live_web.write().await = web;
            log::info!(
                "panel: live web settings reloaded (admin password / allowlist / CSRF origins)"
            );
        }
    }
}

/// Directory holding per-profile server identity keys.
pub const IDENTITY_DIR: &str = "/etc/qeli/identity";

/// Filesystem path of a profile's server identity (private) key. Defaults to
/// `/etc/qeli/identity/<name>.key`; overridable per profile via `identity_key`.
pub fn profile_identity_path(pcfg: &ProfileConfig) -> String {
    pcfg.identity_key
        .clone()
        .unwrap_or_else(|| format!("{}/{}.key", IDENTITY_DIR, pcfg.name))
}

/// Load a profile's identity key, or generate+persist a fresh one on first use.
/// Each profile (interface) has its own identity so clients pin a key specific
/// to the interface they connect to.
pub fn load_or_generate_profile_key(pcfg: &ProfileConfig) -> anyhow::Result<StaticKeypair> {
    let path = profile_identity_path(pcfg);
    if std::path::Path::new(&path).exists() {
        let bytes = std::fs::read(&path)?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "invalid identity key length in {}: {}",
                path,
                bytes.len()
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        log::info!("Profile '{}': loaded identity key from {}", pcfg.name, path);
        Ok(StaticKeypair::from_private_bytes(key))
    } else {
        generate_profile_key(pcfg)
    }
}

/// Generate a fresh identity key for a profile and persist it (0600), creating
/// the identity directory (0700) if needed. Overwrites any existing key.
pub fn generate_profile_key(pcfg: &ProfileConfig) -> anyhow::Result<StaticKeypair> {
    let path = profile_identity_path(pcfg);
    let kp = StaticKeypair::generate();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    crate::util::write_atomic(&path, &kp.private_bytes()[..])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    log::info!(
        "Profile '{}': generated new identity key at {}",
        pcfg.name,
        path
    );
    Ok(kp)
}

/// Validate profiles before bringing up any listeners. Pure (no IO) so it is
/// unit-testable. Checks, in order: unique non-empty names; the classic
/// "missing [performance] section" footgun (serde fills an absent section with
/// type-zero, not per-field defaults → handshake_timeout=0 instant-timeouts and
/// max_clients=0 rejects everyone — fail loud instead); and the plain-is-TCP-only
/// invariant (a raw datagram stream has no framing to delimit records and is a
/// high-entropy "fully encrypted traffic" DPI red-flag, so it is refused on UDP).
fn validate_profiles(config: &ServerConfig) -> anyhow::Result<()> {
    let mut seen = std::collections::HashSet::new();
    for p in &config.profiles {
        // Disabled profiles are not bound/served, so their config is not validated
        // here — this lets an operator turn off a profile that would otherwise fail
        // validation (e.g. a half-edited one) without blocking startup.
        if !p.enabled {
            continue;
        }
        if p.name.is_empty() {
            anyhow::bail!("profile has an empty name");
        }
        if !seen.insert(&p.name) {
            anyhow::bail!("duplicate profile name: '{}'", p.name);
        }
        // Reject unknown bind.transport / obf.mode outright. Both are plain
        // Strings compared verbatim elsewhere: an unrecognised transport parses
        // via `.unwrap_or(Tcp)` (a typo silently binds TCP) and an unrecognised
        // mode falls through the plain/obfs branches to the fake-tls default —
        // so `obf.mode = "realty-tls"` would silently run fake-tls. Fail loud.
        // Accepted transports: tcp, udp (TransportProtocol::from_str).
        if !matches!(p.bind.transport.as_str(), "tcp" | "udp") {
            anyhow::bail!(
                "profile '{}': unknown bind.transport '{}' — expected 'tcp' or 'udp'",
                p.name,
                p.bind.transport
            );
        }
        // Accepted server wire modes: plain, obfs, fake-tls (matched in
        // handler.rs / udp_handler.rs); reality-tls is honoured as a fake-tls
        // profile driven by obf.tls.reality_proxy (see server-multiprofile.conf).
        if !matches!(
            p.obfuscation.mode.as_str(),
            "plain" | "obfs" | "fake-tls" | "reality-tls"
        ) {
            anyhow::bail!(
                "profile '{}': unknown obf.mode '{}' — expected 'fake-tls', 'obfs', \
                 'plain' or 'reality-tls'",
                p.name,
                p.obfuscation.mode
            );
        }
        let perf = &p.performance.connection;
        if perf.handshake_timeout_secs == 0 || perf.max_clients == 0 {
            anyhow::bail!(
                "profile '{}': performance.connection.handshake_timeout_secs and max_clients \
                 must be > 0. The [profiles.performance] section is likely missing — add it \
                 (see qeli/config/server.conf). Omitting a whole section yields zeros, not defaults.",
                p.name
            );
        }
        if p.obfuscation.mode == "plain" && p.bind.transport == "udp" {
            anyhow::bail!(
                "profile '{}': plain (raw) wire mode is TCP-only — set bind.transport = tcp",
                p.name
            );
        }
        // An empty obfs_key would derive a publicly-computable constant key
        // (SHA256("qeli-obfs-key-v1"‖"")) on TCP, and silently disable obfuscation
        // on UDP — either way the obfs wire mode gives zero DPI resistance while
        // looking configured. Refuse to start so the operator notices.
        if p.obfuscation.mode == "obfs" && p.obfuscation.obfs_key.trim().is_empty() {
            anyhow::bail!(
                "profile '{}': obfs wire mode requires a non-empty obfuscation.obfs_key \
                 (an empty key is publicly derivable → no DPI resistance)",
                p.name
            );
        }
        // REALITY proper requires at least one short_id: with an empty list the
        // server falls back to the legacy "no ALPN" heuristic (reality.rs), which an
        // active prober trivially defeats — it would receive the qeli handshake
        // instead of being transparently bridged to `dest`, unmasking the server.
        // Fail loud rather than start a REALITY profile with no crypto token. (An
        // all-blank list — e.g. `short_ids = [""]` — counts as empty.)
        let rp = &p.obfuscation.tls.reality_proxy;
        if rp.enabled && rp.short_ids.iter().all(|s| s.trim().is_empty()) {
            anyhow::bail!(
                "profile '{}': reality_proxy.enabled requires at least one non-empty \
                 obf.tls.reality_proxy.short_ids entry — an empty list falls back to the \
                 trivially-probeable ALPN-absence heuristic (no active-probe resistance)",
                p.name
            );
        }
        // REALITY camouflages as a real TLS site (mimicking its cert + ServerHello by
        // SNI); a bare-IP target can't present a matching hostname, weakening the
        // disguise. Warn (don't fail — an operator may have a reason).
        if rp.enabled && rp.target.parse::<IpAddr>().is_ok() {
            log::warn!(
                "profile '{}': reality_proxy.target '{}' is a bare IP — REALITY mimics a real \
                 TLS site, so a hostname (e.g. www.microsoft.com) is recommended for camouflage",
                p.name,
                rp.target
            );
        }
        // fake-tls as the OUTER wire mode emits a plaintext Certificate/Finished right
        // after ServerHello, where real TLS 1.3 would send encrypted application_data —
        // a TLS-state-machine DPI distinguishes it. It is fine only as the INNER
        // handshake wrapped in real TLS (reality_proxy.real_tls). Warn otherwise so an
        // operator on a hostile network picks reality-tls or obfs instead.
        if p.obfuscation.mode == "fake-tls" && !(rp.enabled && rp.real_tls) {
            log::warn!(
                "profile '{}': wire mode 'fake-tls' has LOW DPI resistance (plaintext TLS \
                 handshake records on the wire). Prefer reality-tls \
                 (obf.tls.reality_proxy.real_tls=true + handrolled=true) or obfs on hostile \
                 networks.",
                p.name
            );
        }
    }
    Ok(())
}

/// Data-plane worker: control socket + all VPN profiles. Runs as the child
/// process `qeli _worker`; the web panel lives in the supervisor (`run_supervisor`).
/// Load the users database the data plane authenticates against, from BOTH the
/// users file AND any inline `[user:*]` / `[group:*]` sections in the server
/// config.
///
/// The users file (written by the web panel and the `add-client` CLI) is the
/// authoritative dynamic store; inline entries are a static config convenience.
/// We take the UNION, with the **file taking precedence** for a duplicate
/// username / group. Without this, a config that carried inline users made every
/// panel / `add-client` change a silent no-op: the worker kept (re)loading the
/// inline copy and ignored the file the panel writes to, so edits never applied.
///
/// Returns `Err` only when the users file can't be read/parsed AND there are no
/// inline entries to fall back to — so callers keep their existing behaviour
/// (start empty at boot, keep current users on a transient SIGHUP-reload error).
pub fn load_users_db(config: &ServerConfig) -> anyhow::Result<UsersDb> {
    let has_inline = !config.auth.users.is_empty() || !config.auth.groups.is_empty();
    let mut db = match UsersDb::load(&config.auth.users_file) {
        Ok(db) => db,
        Err(e) => {
            if !has_inline {
                return Err(e);
            }
            UsersDb::default()
        }
    };
    if !has_inline {
        return Ok(db);
    }

    // Merge inline entries the file doesn't already define (file wins on a clash).
    let have: std::collections::HashSet<String> =
        db.users.iter().map(|u| u.username.clone()).collect();
    let mut shadowed = Vec::new();
    for u in &config.auth.users {
        if have.contains(&u.username) {
            shadowed.push(u.username.clone());
        } else {
            db.users.push(u.clone());
        }
    }
    for (name, g) in &config.auth.groups {
        db.groups.entry(name.clone()).or_insert_with(|| g.clone());
    }
    if !shadowed.is_empty() {
        log::warn!(
            "users: {} inline [user:*] entry(ies) also exist in the users file '{}'; \
             the FILE copy wins ({:?}) — remove them from the config to avoid confusion",
            shadowed.len(),
            config.auth.users_file,
            shadowed
        );
    }
    Ok(db)
}

pub async fn run_worker(cfg_path: &str) -> anyhow::Result<()> {
    let config_content = std::fs::read_to_string(cfg_path)?;
    let config: ServerConfig = crate::config::parse_server_config(&config_content)?;

    if config.profiles.is_empty() {
        anyhow::bail!("no profiles defined in server config");
    }
    if !config.profiles.iter().any(|p| p.enabled) {
        anyhow::bail!("all profiles are disabled (enabled = false) — enable at least one");
    }

    validate_profiles(&config)?;

    let users_db = load_users_db(&config).unwrap_or_else(|_| {
        log::warn!("users file not found, creating empty");
        UsersDb::default()
    });
    log::info!(
        "Loaded {} user(s) ({} inline in config, rest from '{}')",
        users_db.users.len(),
        config.auth.users.len(),
        config.auth.users_file
    );
    let users_db = Arc::new(RwLock::new(users_db));

    // Identity keys are per-profile now (loaded in run_profile), so there is no
    // single server-wide key here.
    let bf_cfg = &config.auth.brute_force;
    let failed_auth = Arc::new(Mutex::new(FailedAuthTracker::new(
        bf_cfg.max_attempts,
        bf_cfg.window_secs,
        bf_cfg.lockout_secs,
    )));

    let live_web = Arc::new(RwLock::new(config.web.clone()));
    let state = Arc::new(ServerState {
        config,
        users_db,
        config_path: Mutex::new(Some(cfg_path.to_string())),
        profiles: Arc::new(RwLock::new(HashMap::new())),
        failed_auth,
        worker_tx: None,
        client_manager: Arc::new(client_manager::ClientManager::new()),
        metrics: Arc::new(metrics::MetricsState::new()),
        usage: Arc::new(usage::UsageStore::load(usage::USAGE_PATH)),
        live_web,
    });

    // Control socket (shared across profiles) — the supervisor's panel reaches
    // live client data (list/kick/bandwidth) through this.
    {
        let ctrl_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = control::run_control_server(ctrl_state).await {
                log::error!("Control server error: {}", e);
            }
        });
    }

    // (The web panel runs in the supervisor process, not here.)

    // Tier-2 usage sweep: accrue per-user traffic + enforce data caps / expiry.
    {
        let usage_state = state.clone();
        tokio::spawn(async move {
            usage_sweep(usage_state).await;
        });
    }

    // Clear any leaked NAT rules from a previous run whose profile has since been
    // REMOVED from the config (its per-profile cleanup never runs again). Active
    // profiles re-install their own rules in run_profile right below.
    nat::cleanup_all();

    // Start each profile
    let mut profile_handles = Vec::new();
    for pcfg in &state.config.profiles {
        if !pcfg.enabled {
            log::info!(
                "Profile '{}' is disabled (enabled = false) — not binding",
                pcfg.name
            );
            continue;
        }
        let state = state.clone();
        let pcfg = pcfg.clone();
        let pname = pcfg.name.clone();
        let handle = tokio::spawn(async move {
            let pname = pcfg.name.clone();
            if let Err(e) = run_profile(state, pcfg).await {
                log::error!("Profile '{}' error: {}", pname, e);
            }
        });
        profile_handles.push((pname, handle));
    }

    // Wait for all profiles. SIGINT (ctrl-c) and SIGTERM (how the supervisor and
    // systemd stop us) both shut down gracefully so we can tear down host NAT;
    // SIGHUP hot-reloads users.
    use tokio::signal::unix::{signal, SignalKind};
    let mut sighup = signal(SignalKind::hangup())
        .map_err(|e| anyhow::anyhow!("failed to install SIGHUP handler: {}", e))?;
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| anyhow::anyhow!("failed to install SIGTERM handler: {}", e))?;

    let profiles_done = async {
        for (pname, h) in profile_handles {
            // A profile task ending on its own is unexpected while the worker is
            // still meant to be serving — surface it instead of swallowing it.
            // Log only (no auto-restart): respawning here could loop forever.
            match h.await {
                Ok(()) => log::warn!("Profile '{}' task ended unexpectedly", pname),
                Err(e) => log::warn!("Profile '{}' task ended unexpectedly: {}", pname, e),
            }
        }
    };
    tokio::pin!(profiles_done);

    let mut via_signal = false;
    loop {
        tokio::select! {
            _ = &mut profiles_done => break,
            _ = tokio::signal::ctrl_c() => {
                log::info!("Received SIGINT, stopping server...");
                via_signal = true;
                break;
            }
            _ = sigterm.recv() => {
                log::info!("Received SIGTERM, stopping server...");
                via_signal = true;
                break;
            }
            _ = sighup.recv() => {
                log::info!("SIGHUP received — reloading configuration");
                reload_on_sighup(&state).await;
            }
        }
    }

    // Tear down the host NAT rules we installed (the next start also cleans stale
    // rules, so a SIGKILL that skips this is recovered then) and run post_down.
    let hooks_ok = {
        let p = state.config_path.lock().await.clone();
        p.as_deref()
            .map(|p| crate::hooks::config_is_trusted(p).is_ok())
            .unwrap_or(false)
    };
    for pcfg in &state.config.profiles {
        if pcfg.routing.nat.enabled {
            nat::cleanup(&pcfg.name);
        }
        if hooks_ok && !pcfg.routing.post_down.is_empty() {
            crate::hooks::run(
                &format!("post_down:{}", pcfg.name),
                &pcfg.routing.post_down,
                &[
                    ("QELI_PROFILE", pcfg.name.clone()),
                    ("QELI_TUN", pcfg.tun.name.clone()),
                    ("QELI_POOL", pcfg.pool.cidr.clone()),
                ],
            )
            .await;
        }
    }

    log::info!("Server shutdown complete");
    // On a signal-driven stop, exit the process directly. The data plane spawns
    // blocking TUN reader threads; a graceful runtime drop joins them and would hang
    // (they block in read()), making `systemctl stop` time out and the unit go
    // "failed". The kernel reclaims the TUN devices / fds on exit, and NAT was already
    // torn down above.
    if via_signal {
        std::process::exit(0);
    }
    Ok(())
}

/// Supervisor (`qeli server`): serves the web panel — the always-up control
/// plane — and runs the data-plane as a child process (`qeli _worker`). Applying
/// a config change restarts only the worker (clean OS teardown of TUN/sockets),
/// so the panel never goes down. Live client data is read over the control
/// socket; user edits write the users file and SIGHUP the worker to hot-reload.
/// Tier-2 usage sweep (worker). Every few seconds: fold each live session's byte
/// counters into the per-user lifetime total, persist the `usage.json` sidecar,
/// and disconnect any user over their data cap or past expiry. Runs off the data
/// path (O(sessions) per tick, reusing counters the data plane already maintains)
/// so it adds zero per-packet cost — tunnel throughput is unaffected.
async fn usage_sweep(state: Arc<ServerState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;

        // Per-user caps snapshot from the (hot-reloadable) users DB.
        let (limit_gb, expire): (HashMap<String, u64>, HashMap<String, Option<i64>>) = {
            let db = state.users_db.read().await;
            let mut l = HashMap::new();
            let mut e = HashMap::new();
            for u in &db.users {
                l.insert(u.username.clone(), u.data_limit_gb);
                e.insert(u.username.clone(), u.expire_at);
            }
            (l, e)
        };
        let now = usage::now_unix();

        let mut live: HashSet<u64> = HashSet::new();
        let mut to_kick: Vec<(String, std::net::Ipv4Addr, u64)> = Vec::new();
        {
            let profiles = state.profiles.read().await;
            for (pname, profile) in profiles.iter() {
                let sessions = profile.sessions.read().await;
                for (ip, s) in sessions.by_ip.iter() {
                    let cur = s.bytes_sent.load(std::sync::atomic::Ordering::Relaxed)
                        + s.bytes_recv.load(std::sync::atomic::Ordering::Relaxed);
                    state.usage.fold(s.session_id, &s.username, cur);
                    live.insert(s.session_id);

                    let gb = limit_gb.get(&s.username).copied().unwrap_or(0);
                    let over = gb > 0
                        && state.usage.used_bytes(&s.username) >= gb.saturating_mul(1_000_000_000);
                    let expired = expire
                        .get(&s.username)
                        .copied()
                        .flatten()
                        .map(|x| now >= x)
                        .unwrap_or(false);
                    if over || expired {
                        // Notify (Tier-3) — throttled to once/hour per user so a
                        // client that keeps reconnecting over quota can't spam.
                        let key = format!("quota:{}", s.username);
                        let detail = format!(
                            "user '{}' on profile '{}' — {}",
                            s.username,
                            pname,
                            if over {
                                "over data quota"
                            } else {
                                "subscription expired"
                            }
                        );
                        tokio::spawn(async move {
                            notify::fire_throttled(&key, 3600, notify::Event::QuotaBreach, &detail)
                                .await;
                        });
                        to_kick.push((pname.clone(), *ip, s.session_id));
                    }
                }
            }
        }

        state.usage.prune(&live);
        state.usage.flush();

        for (pname, ip, session_id) in to_kick {
            let profiles = state.profiles.read().await;
            if let Some(profile) = profiles.get(&pname) {
                let mut sessions = profile.sessions.write().await;
                // Guard on session_id: between the read-lock snapshot above and this
                // write lock the flagged session may have disconnected and a DIFFERENT
                // device reconnected onto the same pool IP. Only evict if it's still
                // the same session (mirrors the handler's own session-cleanup).
                let still_same = sessions
                    .by_ip
                    .get(&ip)
                    .map(|s| s.session_id == session_id)
                    .unwrap_or(false);
                if still_same {
                    if let Some(s) = sessions.by_ip.remove(&ip) {
                        sessions.by_token.remove(&s.token);
                        drop(sessions);
                        profile.pool.lock().await.release(&s.device_key);
                        log::info!(
                            "usage: disconnected '{}' on profile '{}' — over quota / expired",
                            s.username,
                            pname
                        );
                    }
                }
            }
        }
    }
}

pub async fn run_supervisor(cfg_path: &str) -> anyhow::Result<()> {
    // Validate the config parses and has at least one profile before starting.
    let config_content = std::fs::read_to_string(cfg_path)?;
    let config: ServerConfig = crate::config::parse_server_config(&config_content)?;
    if config.profiles.is_empty() {
        anyhow::bail!("no profiles defined in server config");
    }

    // Users DB for the panel (display + create/update/delete). The worker holds
    // its own copy and hot-reloads it on SIGHUP after the panel edits the file.
    // Same union-load (file + inline, file wins) the worker uses, so the panel
    // shows exactly what the data plane authenticates against.
    let users_db = Arc::new(RwLock::new(load_users_db(&config).unwrap_or_default()));

    let bf = &config.auth.brute_force;
    let failed_auth = Arc::new(Mutex::new(FailedAuthTracker::new(
        bf.max_attempts,
        bf.window_secs,
        bf.lockout_secs,
    )));

    let (worker_tx, mut worker_rx) = tokio::sync::mpsc::channel::<WorkerCmd>(8);

    let live_web = Arc::new(RwLock::new(config.web.clone()));
    let state = Arc::new(ServerState {
        config,
        users_db,
        config_path: Mutex::new(Some(cfg_path.to_string())),
        profiles: Arc::new(RwLock::new(HashMap::new())),
        failed_auth,
        worker_tx: Some(worker_tx),
        client_manager: Arc::new(client_manager::ClientManager::new()),
        metrics: Arc::new(metrics::MetricsState::new()),
        usage: Arc::new(usage::UsageStore::load(usage::USAGE_PATH)),
        live_web,
    });

    // Web panel — the always-up control plane.
    if state.config.web.enabled {
        let web_state = state.clone();
        tokio::spawn(async move {
            web::start(web_state).await;
        });
    } else {
        log::warn!("web.enabled is false — the supervisor has no panel to serve");
    }

    // Dashboard metrics sampler (host /proc + tunnel aggregate, 1 Hz). Only useful
    // with the panel up, so gate it on web.enabled like the panel itself.
    if state.config.web.enabled {
        let m = state.metrics.clone();
        tokio::spawn(async move {
            metrics::run_sampler(m).await;
        });
    }

    // Notify (Tier-3): announce that the control plane is up (no-op if disabled).
    tokio::spawn(async {
        notify::fire(
            notify::Event::ServerStart,
            &format!("qeli {} control plane is up", env!("CARGO_PKG_VERSION")),
        )
        .await;
    });

    // Auto-connect any client profiles flagged `autostart = true` (set in the panel's
    // Client tab or directly in the file). A client tunnel dials a REMOTE server, so it
    // is independent of the local worker — bring them up as soon as the supervisor is.
    {
        let cm = state.client_manager.clone();
        tokio::spawn(async move {
            cm.start_autostart().await;
        });
    }

    // Supervise the data-plane worker child process.
    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("cannot resolve current_exe for worker: {}", e))?;
    let spawn_worker = || {
        tokio::process::Command::new(&exe)
            .arg("_worker")
            .arg("-c")
            .arg(cfg_path)
            .kill_on_drop(true) // safety net: don't orphan the worker if we drop it
            .spawn()
    };

    // systemd stops/restarts us with SIGTERM (not SIGINT), so handle both — else
    // the worker child would be orphaned and clash with the next supervisor's worker.
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| anyhow::anyhow!("failed to install SIGTERM handler: {}", e))?;

    let mut stopping = false;
    // Exponential backoff (capped) for a crash-looping worker, so a worker that
    // dies instantly on every start can't thrash iptables/TUN once per second.
    // Reset once an instance has run long enough to look healthy (see exit arm).
    let mut backoff_secs = 1u64;
    'supervise: loop {
        let mut child = match spawn_worker() {
            Ok(c) => c,
            Err(e) => {
                log::error!("supervisor: failed to spawn worker: {e} — retry in 2s");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue 'supervise;
            }
        };
        let pid = child.id().map(|p| p as i32).unwrap_or(0);
        state
            .metrics
            .worker_pid
            .store(pid, std::sync::atomic::Ordering::Relaxed);
        log::info!("supervisor: data-plane worker started (pid {pid})");
        let started = std::time::Instant::now();

        // Watch for the worker's exit without borrowing `child` in the select.
        let (exit_tx, mut exit_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = exit_tx.send(child.wait().await);
        });

        loop {
            tokio::select! {
                _ = &mut exit_rx => {
                    if stopping {
                        break 'supervise;
                    }
                    // A worker that ran long enough is healthy — reset the backoff so
                    // an ordinary restart doesn't inherit an escalated delay. A worker
                    // that died fast keeps escalating (capped) to avoid a respawn storm.
                    let ran = started.elapsed();
                    if ran >= Duration::from_secs(30) {
                        backoff_secs = 1;
                    }
                    log::warn!(
                        "supervisor: worker exited after {}s — respawning in {}s",
                        ran.as_secs(),
                        backoff_secs
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(30);
                    continue 'supervise;
                }
                cmd = worker_rx.recv() => match cmd {
                    Some(WorkerCmd::Restart) => {
                        log::info!("supervisor: restarting worker (apply config)");
                        signal_pid(pid, libc::SIGTERM);
                        // The exit watcher will fire and respawn a fresh worker.
                    }
                    Some(WorkerCmd::ReloadUsers) => {
                        log::info!("supervisor: SIGHUP worker (reload users)");
                        signal_pid(pid, libc::SIGHUP); // same worker keeps running
                    }
                    None => {
                        stopping = true;
                        signal_pid(pid, libc::SIGTERM);
                    }
                },
                _ = tokio::signal::ctrl_c() => {
                    log::info!("supervisor: SIGINT — stopping worker");
                    stopping = true;
                    signal_pid(pid, libc::SIGTERM);
                }
                _ = sigterm.recv() => {
                    log::info!("supervisor: SIGTERM — stopping worker");
                    stopping = true;
                    signal_pid(pid, libc::SIGTERM);
                }
            }
        }
    }

    // Tear down any panel-managed outbound client tunnels (SIGTERM each so it
    // restores DNS/routes before exit).
    state.client_manager.shutdown_all().await;

    log::info!("Supervisor shutdown complete");
    Ok(())
}

/// Best-effort `kill(pid, sig)` — used by the supervisor to drive the worker.
fn signal_pid(pid: i32, sig: i32) {
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

/// Handle SIGHUP: re-read the config file from disk and hot-reload everything
/// that can be swapped without dropping live tunnels — the users database and
/// the brute-force thresholds. Changes to profiles (bind/tun/transport) require
/// a full restart and are reported, not silently ignored.
async fn reload_on_sighup(state: &Arc<ServerState>) {
    let cfg_path = {
        let guard = state.config_path.lock().await;
        match guard.clone() {
            Some(p) => p,
            None => {
                log::warn!("SIGHUP: no config path recorded, cannot reload");
                return;
            }
        }
    };

    let new_config: ServerConfig = match std::fs::read_to_string(&cfg_path)
        .map_err(|e| anyhow::anyhow!("{}", e))
        .and_then(|s| crate::config::parse_server_config(&s))
    {
        Ok(c) => c,
        Err(e) => {
            log::error!(
                "SIGHUP: failed to re-read config '{}': {} — keeping current config",
                cfg_path,
                e
            );
            return;
        }
    };

    // 1. Reload the users database (add/disable users, change routes/limits/
    //    allowed-profiles). Union of the users file (what the panel/add-client
    //    write) and inline [user:*], file wins — so a panel edit always applies
    //    even when the config also carries inline users.
    match load_users_db(&new_config) {
        Ok(db) => {
            let count = db.users.len();
            *state.users_db.write().await = db;
            log::info!("SIGHUP: reloaded users database ({} users)", count);
        }
        Err(e) => {
            log::error!(
                "SIGHUP: failed to reload users from '{}': {} — keeping current users",
                new_config.auth.users_file,
                e
            );
        }
    }

    // 2. Rebuild the brute-force tracker ONLY when the thresholds actually change.
    //    Rebuilding wipes every in-flight IP lockout, and the panel SIGHUPs the
    //    worker on ordinary user edits too — so an unconditional reset would let an
    //    attacker clear their own lockout by triggering/timing a reload. Preserve
    //    live lockouts when the policy is unchanged.
    let new_bf = &new_config.auth.brute_force;
    let want = (
        new_bf.max_attempts,
        Duration::from_secs(new_bf.window_secs),
        Duration::from_secs(new_bf.lockout_secs),
    );
    {
        let mut tracker = state.failed_auth.lock().await;
        if tracker.thresholds() != want {
            *tracker = FailedAuthTracker::new(
                new_bf.max_attempts,
                new_bf.window_secs,
                new_bf.lockout_secs,
            );
            log::info!(
                "SIGHUP: brute-force thresholds changed (max_attempts={}, window={}s, lockout={}s) — tracker reset",
                new_bf.max_attempts,
                new_bf.window_secs,
                new_bf.lockout_secs
            );
        } else {
            log::info!("SIGHUP: brute-force thresholds unchanged — live lockouts preserved");
        }
    }

    // 3. Profile-level changes are not hot-reloadable (each owns a TUN device,
    //    socket and runtime task). Warn if the profile set changed on disk.
    let live: std::collections::HashSet<String> =
        state.profiles.read().await.keys().cloned().collect();
    let on_disk: std::collections::HashSet<String> =
        new_config.profiles.iter().map(|p| p.name.clone()).collect();
    if live != on_disk {
        log::warn!(
            "SIGHUP: profile set changed on disk (live: {:?}, config: {:?}) — \
            restart qeli to apply profile/bind/tun changes",
            live,
            on_disk
        );
    }
}

async fn run_profile(state: Arc<ServerState>, pcfg: ProfileConfig) -> anyhow::Result<()> {
    let name = pcfg.name.clone();
    log::info!(
        "Starting profile '{}' ({}://{}:{})",
        name,
        pcfg.bind.transport,
        pcfg.bind.address,
        pcfg.bind.port
    );

    // Setup TUN interface(s). With tun.queues>1 we open several IFF_MULTI_QUEUE fds
    // attached to ONE device; the kernel RSS-spreads packets across them so the data
    // plane reads/writes the interface — and runs the per-queue encrypt — on multiple
    // cores instead of funnelling everything through one reader/writer/forwarder.
    TunInterface::delete(&pcfg.tun.name).ok();
    let dev_type = match pcfg.tun.device_type.to_lowercase().as_str() {
        "tap" => DeviceType::Tap,
        _ => DeviceType::Tun,
    };
    let nq = {
        let auto = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let n = if pcfg.tun.queues == 0 {
            auto
        } else {
            pcfg.tun.queues
        };
        // Ceiling = the kernel's tun multi-queue limit (MAX_TAP_QUEUES = 256); this
        // never reduces auto=nproc for real core counts. More queues than cores is
        // pointless (idle pollers), but explicit values are honoured up to the limit.
        n.clamp(1, 256)
    };
    let queues = TunInterface::create_multiqueue(&pcfg.tun.name, pcfg.tun.mtu, dev_type, nq)?;
    TunInterface::set_address(&pcfg.tun.name, &pcfg.tun.address, &pcfg.tun.netmask)?;
    TunInterface::set_up(&pcfg.tun.name, pcfg.tun.mtu)?;
    TunInterface::set_queue_len(&pcfg.tun.name, pcfg.tun.tx_queue_len)?;
    log::info!(
        "Profile '{}': {} {} is up with {} queue(s) ({} {})",
        name,
        if dev_type == DeviceType::Tap {
            "TAP"
        } else {
            "TUN"
        },
        pcfg.tun.name,
        queues.len(),
        pcfg.tun.address,
        pcfg.tun.netmask
    );

    // Host NAT (iptables) for full-tunnel egress. Always clear any rules we left
    // behind first (covers an unclean exit, or routing.nat toggled off then a
    // restart), then (re)install if this profile requests masquerading.
    nat::cleanup(&pcfg.name);
    if pcfg.routing.nat.enabled {
        match nat::setup(
            &pcfg.name,
            &pcfg.routing.nat.interface,
            &pcfg.pool.cidr,
            &pcfg.tun.name,
            pcfg.tun.mtu,
        ) {
            Ok(wan) => log::info!(
                "Profile '{}': NAT masquerade active via iptables ({} -> {})",
                name,
                pcfg.pool.cidr,
                wan
            ),
            Err(e) => log::error!(
                "Profile '{}': routing.nat.enabled is set but NAT was NOT applied — {e}",
                name
            ),
        }
    }

    // post_up hook: after this profile's TUN + NAT are up. Honoured ONLY from a
    // trusted config file (the panel/API never writes it — RCE guard).
    if !pcfg.routing.post_up.is_empty() {
        let cfg_path = { state.config_path.lock().await.clone() };
        match cfg_path.as_deref().map(crate::hooks::config_is_trusted) {
            Some(Ok(())) => {
                crate::hooks::run(
                    &format!("post_up:{name}"),
                    &pcfg.routing.post_up,
                    &[
                        ("QELI_PROFILE", name.clone()),
                        ("QELI_TUN", pcfg.tun.name.clone()),
                        ("QELI_POOL", pcfg.pool.cidr.clone()),
                        ("QELI_WAN", pcfg.routing.nat.interface.clone()),
                        ("QELI_BIND_PORT", pcfg.bind.port.to_string()),
                    ],
                )
                .await;
            }
            Some(Err(why)) => log::error!("Profile '{name}': ignoring post_up — {why}"),
            None => log::error!("Profile '{name}': ignoring post_up — no config path recorded"),
        }
    }

    // Per-queue reader/writer fds (dup'd so the blocking reader and writer threads each
    // own a closable fd for their queue). Dropping `queues` after this keeps the device
    // alive via these dups (closed when the threads exit).
    let mut reader_fds: Vec<i32> = Vec::with_capacity(queues.len());
    let mut writer_fds: Vec<i32> = Vec::with_capacity(queues.len());
    for q in &queues {
        // Leave the fds BLOCKING: the reader thread sleeps inside read() until a
        // packet arrives (no 1ms busy-poll → 0% idle CPU even with many queues); the
        // writer blocks on a full TUN queue (backpressure, not silent drop).
        let rfd = unsafe { libc::dup(q.as_raw_fd()) };
        let wfd = unsafe { libc::dup(q.as_raw_fd()) };
        if rfd < 0 || wfd < 0 {
            for fd in reader_fds.iter().chain(writer_fds.iter()) {
                unsafe { libc::close(*fd) };
            }
            if rfd >= 0 {
                unsafe { libc::close(rfd) };
            }
            if wfd >= 0 {
                unsafe { libc::close(wfd) };
            }
            return Err(anyhow::anyhow!("failed to dup TUN queue fd"));
        }
        reader_fds.push(rfd);
        writer_fds.push(wfd);
    }
    drop(queues);

    // Inbound (client -> TUN): one channel per queue. handle_client gets a sharded
    // sender (sticky per connection) so a connection's packets stay ordered.
    let mut in_txs: Vec<mpsc::Sender<Vec<u8>>> = Vec::with_capacity(reader_fds.len());
    let mut in_rxs: Vec<mpsc::Receiver<Vec<u8>>> = Vec::with_capacity(reader_fds.len());
    for _ in 0..reader_fds.len() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(4096);
        in_txs.push(tx);
        in_rxs.push(rx);
    }

    let pool = pool::IpPool::new(&pcfg.pool)?;

    // Per-profile server identity (its own static key, bound to this interface).
    let static_keypair = Arc::new(load_or_generate_profile_key(&pcfg)?);
    let pub_hex: String = static_keypair
        .public
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    log::info!(
        "Profile '{}': server identity public key (pin on client): {}",
        name,
        pub_hex
    );

    // Build the REALITY real-TLS rustls config once (cert generation is not free).
    let reality_tls_config = if pcfg.obfuscation.tls.reality_proxy.real_tls {
        log::info!(
            "Profile '{}': REALITY real-TLS termination enabled (SNI {})",
            name,
            pcfg.obfuscation.tls.reality_proxy.target
        );
        if !pcfg.obfuscation.tls.reality_proxy.handrolled {
            log::warn!(
                "Profile '{}': real-TLS via rustls — self-signed cert + rustls JA3S. Set \
                 obf.tls.reality_proxy.handrolled=true for cert-borrowing (real target cert \
                 chain) + JA3S mirroring (Xray-REALITY parity).",
                name
            );
        }
        Some(crate::protocol::realtls::server::make_server_config(
            &pcfg.obfuscation.tls.reality_proxy.target,
        ))
    } else {
        None
    };

    // Probe the borrowed target's ServerHello once so the hand-rolled terminator
    // can mirror its shape (cipher, PQ group, extension order) — making the
    // ServerHello's JA3S match whatever `target` is set to, not just microsoft.
    let reality_borrow = if pcfg.obfuscation.tls.reality_proxy.real_tls
        && pcfg.obfuscation.tls.reality_proxy.handrolled
    {
        let host = pcfg.obfuscation.tls.reality_proxy.target.clone();
        let port = pcfg.obfuscation.tls.reality_proxy.target_port;
        let probe = crate::protocol::realtls::server::probe_borrow_profile(&host, port);
        let dflt = crate::protocol::realtls::server::BorrowProfile::default();
        let (bp, cert) = match tokio::time::timeout(Duration::from_secs(8), probe).await {
            Ok(Ok((bp, cert))) => {
                log::info!(
                    "Profile '{}': borrowed TLS shape from {}:{} → {:?} (real cert chain: {})",
                    name,
                    host,
                    port,
                    bp,
                    if cert.is_some() {
                        "captured"
                    } else {
                        "unavailable → dummy"
                    }
                );
                (bp, cert)
            }
            Ok(Err(e)) => {
                log::warn!(
                    "Profile '{}': target probe {}:{} failed ({}); using default {:?}",
                    name,
                    host,
                    port,
                    e,
                    dflt
                );
                (dflt, None)
            }
            Err(_) => {
                log::warn!(
                    "Profile '{}': target probe {}:{} timed out; using default {:?}",
                    name,
                    host,
                    port,
                    dflt
                );
                (dflt, None)
            }
        };
        let state = Arc::new(std::sync::RwLock::new(
            crate::protocol::realtls::server::BorrowState { profile: bp, cert },
        ));
        // Periodic refresh so a long-running server tracks the target's TLS rotation.
        // Only the ServerHello *shape* (JA3S) is on the wire and matters for detection;
        // the borrowed cert rides inside the encrypted flight. Keep cached values if a
        // refresh probe fails (transient target unreachability must not blank the borrow).
        {
            let state = state.clone();
            let host = host.clone();
            let pname = name.clone();
            tokio::spawn(async move {
                const REFRESH: Duration = Duration::from_secs(12 * 3600);
                loop {
                    tokio::time::sleep(REFRESH).await;
                    let probe = crate::protocol::realtls::server::probe_borrow_profile(&host, port);
                    match tokio::time::timeout(Duration::from_secs(8), probe).await {
                        Ok(Ok((bp, cert))) => {
                            let mut g = state.write().expect("reality_borrow lock");
                            g.profile = bp;
                            if cert.is_some() {
                                g.cert = cert;
                            }
                            log::info!(
                                "Profile '{}': REALITY borrow refreshed (shape {:?}, cert {})",
                                pname,
                                g.profile,
                                if g.cert.is_some() { "present" } else { "none" }
                            );
                        }
                        _ => log::debug!(
                            "Profile '{}': REALITY borrow refresh failed; keeping cached",
                            pname
                        ),
                    }
                }
            });
        }
        Some(state)
    } else {
        None
    };

    let profile = Arc::new(ProfileRuntime {
        name: name.clone(),
        config: pcfg.clone(),
        pool: Arc::new(Mutex::new(pool)),
        sessions: Arc::new(RwLock::new(SessionMap {
            by_ip: HashMap::new(),
            by_token: HashMap::new(),
        })),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(
            pcfg.performance.connection.new_session_rate_max,
            pcfg.performance.connection.new_session_rate_window_secs,
        ))),
        static_keypair,
        reality_tls_config,
        reality_replay: Arc::new(Mutex::new(ReplayGuard::new(Duration::from_secs(
            2 * reality::REALITY_WINDOW_SECS,
        )))),
        reality_borrow,
    });

    // Register in shared profile registry
    state
        .profiles
        .write()
        .await
        .insert(name.clone(), profile.clone());

    let is_tap = dev_type == DeviceType::Tap;
    let gateway_mac: [u8; 6] = if is_tap {
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
    } else {
        [0u8; 6]
    };

    // Per-queue data-plane pump. Each queue gets: a blocking reader (TUN -> forwarder),
    // an async forwarder (lookup + ENCRYPT + send to client — encrypt now runs N-way in
    // parallel, serialized only per-session by the codec lock), a blocking writer (drains
    // its inbound channel -> TUN), and an async bridge feeding that writer. The kernel
    // RSS-distributes outbound TUN packets across the queues by flow.
    let tun_buf_size = pcfg.performance.tun.read_buffer_size;
    for (qi, ((reader_fd, writer_fd), mut in_rx)) in reader_fds
        .into_iter()
        .zip(writer_fds)
        .zip(in_rxs)
        .enumerate()
    {
        // Outbound: TUN[qi] -> forwarder -> client writer.
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(4096);
        {
            let name_r = name.clone();
            let is_tap_reader = is_tap;
            tokio::task::spawn_blocking(move || {
                log::info!("TUN reader q{} for profile '{}' started", qi, name_r);
                let mut buf = vec![0u8; tun_buf_size];
                loop {
                    let n = unsafe {
                        libc::read(reader_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                    };
                    if n < 0 {
                        let err = std::io::Error::last_os_error();
                        // Blocking read: only EINTR is retryable (the fd is no longer
                        // O_NONBLOCK, so WouldBlock can't happen).
                        if err.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        log::error!("TUN read error q{} on profile '{}': {}", qi, name_r, err);
                        break;
                    }
                    if n == 0 {
                        break;
                    }
                    let raw = &buf[..n as usize];
                    let packet = if is_tap_reader {
                        match strip_ethernet_header(raw) {
                            Some(ip) => ip.to_vec(),
                            None => continue,
                        }
                    } else {
                        raw.to_vec()
                    };
                    if out_tx.blocking_send(packet).is_err() {
                        break;
                    }
                }
                unsafe {
                    libc::close(reader_fd);
                }
                log::info!("TUN reader q{} for profile '{}' stopped", qi, name_r);
            });
        }
        {
            let fwd_profile = profile.clone();
            tokio::spawn(async move {
                while let Some(packet) = out_rx.recv().await {
                    if packet.len() < 20 || (packet[0] >> 4) != 4 {
                        continue;
                    }
                    let dest_ip =
                        std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                    let sessions = fwd_profile.sessions.read().await;
                    if let Some(session) = sessions.by_ip.get(&dest_ip) {
                        // Flow-pin each packet to one of the session's bonded streams
                        // (by inner 5-tuple) so a connection stays in order. Each stream
                        // carries its own crypto, so encrypt with the picked codec.
                        if let Some((codec_arc, writer)) =
                            session.pick_stream(crate::protocol::flow_hash(&packet))
                        {
                            // Symmetric obfuscation: pad server→client traffic too. Clamp
                            // under the path MTU so UDP sessions don't get fragmented.
                            let pad_cfg = &fwd_profile.config.obfuscation.padding;
                            let mut obf = crate::protocol::Obfuscator::new();
                            let pad_cap = {
                                let base = packet.len().saturating_add(60);
                                (pad_cfg.max_bytes as usize).min(1400usize.saturating_sub(base))
                                    as u16
                            };
                            let padding = obf.generate_padding_opts(
                                pad_cfg.enabled,
                                pad_cfg.min_bytes,
                                pad_cap,
                                pad_cfg.randomize,
                                pad_cfg.probability,
                            );
                            let mut codec = lock_or_recover(&codec_arc, "fwd::encrypt");
                            if let Ok(encrypted) = codec.encrypt_packet(&packet, &padding) {
                                // A full writer channel = rate-limit / slow-client
                                // backpressure. Count the drop so it's visible in
                                // list-clients instead of silently vanishing.
                                if writer.try_send(encrypted).is_err() {
                                    session
                                        .dropped
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            });
        }

        // Inbound: client -> in_rx -> TUN[qi] (dedicated blocking writer + async bridge).
        let (tun_write_tx, tun_write_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(256);
        {
            let name_w = name.clone();
            let is_tap_writer = is_tap;
            let gw_mac = gateway_mac;
            std::thread::spawn(move || {
                log::info!("TUN writer q{} for profile '{}' started", qi, name_w);
                for packet in tun_write_rx {
                    if packet.is_empty() {
                        continue;
                    }
                    unsafe {
                        if is_tap_writer {
                            // dst = gateway_mac (unicast to this iface); src = MAC from
                            // client src-IP for ARP attribution.
                            let src_ip_mac = if packet.len() >= 16 {
                                [0x02u8, 0x00, packet[12], packet[13], packet[14], packet[15]]
                            } else {
                                [0x02, 0x00, 0x00, 0x00, 0x00, 0x02]
                            };
                            let frame = prepend_ethernet_header(&packet, &gw_mac, &src_ip_mac);
                            libc::write(
                                writer_fd,
                                frame.as_ptr() as *const libc::c_void,
                                frame.len(),
                            );
                        } else {
                            libc::write(
                                writer_fd,
                                packet.as_ptr() as *const libc::c_void,
                                packet.len(),
                            );
                        }
                    }
                }
                unsafe {
                    libc::close(writer_fd);
                }
                log::info!("TUN writer q{} for profile '{}' stopped", qi, name_w);
            });
        }
        tokio::spawn(async move {
            while let Some(packet) = in_rx.recv().await {
                if tun_write_tx.send(packet).is_err() {
                    break;
                }
            }
        });
    }

    // DNS proxy (per-profile)
    if pcfg.dns.enabled {
        let dns_state = state.clone();
        let dns_cfg = pcfg.dns.clone();
        let name_dns = name.clone();
        tokio::spawn(async move {
            if let Err(e) = dns::run_dns_proxy(dns_state, dns_cfg).await {
                log::error!("DNS proxy error on profile '{}': {}", name_dns, e);
            }
        });
    }

    // DHCP server (per-profile)
    if pcfg.dhcp.enabled {
        let pool_start: std::net::Ipv4Addr = pcfg
            .dhcp
            .pool_start
            .as_deref()
            .unwrap_or("10.0.0.2")
            .parse()
            .map_err(|e| anyhow::anyhow!("profile '{}': invalid dhcp.pool_start: {}", name, e))?;
        let pool_end: std::net::Ipv4Addr = pcfg
            .dhcp
            .pool_end
            .as_deref()
            .unwrap_or("10.0.0.254")
            .parse()
            .map_err(|e| anyhow::anyhow!("profile '{}': invalid dhcp.pool_end: {}", name, e))?;
        if u32::from(pool_end) < u32::from(pool_start) {
            anyhow::bail!(
                "profile '{}': dhcp.pool_end ({}) must not be below dhcp.pool_start ({})",
                name,
                pool_end,
                pool_start
            );
        }
        let server_ip: std::net::Ipv4Addr = pcfg
            .tun
            .address
            .parse()
            .map_err(|e| anyhow::anyhow!("profile '{}': invalid tun.address: {}", name, e))?;
        let subnet_mask: std::net::Ipv4Addr = pcfg
            .tun
            .netmask
            .parse()
            .map_err(|e| anyhow::anyhow!("profile '{}': invalid tun.netmask: {}", name, e))?;
        let dhcp_dns: Vec<std::net::Ipv4Addr> = if pcfg.dns.enabled {
            vec![server_ip]
        } else {
            vec![
                std::net::Ipv4Addr::new(1, 1, 1, 1),
                std::net::Ipv4Addr::new(8, 8, 8, 8),
            ]
        };
        let dhcp_listen = if pcfg.dhcp.listen.contains(':') {
            pcfg.dhcp.listen.clone()
        } else {
            format!("{}:67", pcfg.dhcp.listen)
        };

        let dhcp_server = Arc::new(dhcp::DhcpServer::new(
            server_ip,
            subnet_mask,
            server_ip,
            dhcp_dns,
            pcfg.dhcp.domain_name.clone(),
            pcfg.dhcp.lease_time_secs,
            pool_start,
            pool_end,
            profile.pool.clone(),
        ));
        log::info!(
            "DHCP server for profile '{}' starting on {}",
            name,
            dhcp_listen
        );
        let name_dhcp = name.clone();
        tokio::spawn(async move {
            if let Err(e) = dhcp_server.run(&dhcp_listen).await {
                log::error!("DHCP server error on profile '{}': {}", name_dhcp, e);
            }
        });
    }

    // Transport listener
    let transport: TransportProtocol = pcfg
        .bind
        .transport
        .parse()
        .unwrap_or(TransportProtocol::Tcp);
    let bind_addr = format!("{}:{}", pcfg.bind.address, pcfg.bind.port);

    match transport {
        TransportProtocol::Tcp => {
            let listener = TcpListener::bind(&bind_addr).await?;
            log::info!("Profile '{}' listening on {} (TCP)", name, bind_addr);
            loop {
                let (stream, addr) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!("Accept error on profile '{}': {}", name, e);
                        continue;
                    }
                };

                {
                    let mut rl = profile.rate_limiter.lock().await;
                    if !rl.check_and_record(addr.ip()) {
                        log::warn!(
                            "Rate limit exceeded for {} on profile '{}'",
                            addr.ip(),
                            name
                        );
                        continue;
                    }
                }

                log::info!("New TCP connection from {} on profile '{}'", addr, name);
                let state_clone = state.clone();
                let profile_clone = profile.clone();
                // Shard this connection's inbound packets onto one TUN queue (sticky
                // per connection so a connection's packets stay ordered).
                let tun_tx = {
                    use std::hash::{Hash, Hasher};
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    addr.hash(&mut h);
                    in_txs[(h.finish() as usize) % in_txs.len()].clone()
                };
                let use_reality = pcfg.obfuscation.tls.reality_proxy.enabled;
                let nodelay = pcfg.performance.tcp.nodelay;
                let keepalive = pcfg.performance.tcp.keepalive_secs;
                let obfs_key = if pcfg.obfuscation.mode == "obfs" {
                    Some(crate::protocol::obfs::derive_obfs_key(
                        &pcfg.obfuscation.obfs_key,
                    ))
                } else {
                    None
                };
                let obfs_fronting = pcfg.obfuscation.fronting == "websocket";
                let obfs_awg = crate::protocol::obfs::AwgParams {
                    enabled: pcfg.obfuscation.awg.enabled,
                    jc: pcfg.obfuscation.awg.jc,
                    jmin: pcfg.obfuscation.awg.jmin,
                    jmax: pcfg.obfuscation.awg.jmax,
                };
                let name_conn = profile_clone.name.clone();
                tokio::spawn(async move {
                    // Socket options on the raw TcpStream before any obfs wrapping.
                    let _ = stream.set_nodelay(nodelay);
                    let _ = set_tcp_keepalive(&stream, keepalive);
                    if use_reality {
                        if let Err(e) = reality::handle_connection(
                            state_clone,
                            profile_clone,
                            stream,
                            addr,
                            tun_tx,
                        )
                        .await
                        {
                            log::debug!(
                                "REALITY {} disconnected on profile '{}': {}",
                                addr,
                                name_conn,
                                e
                            );
                        }
                    } else if let Some(key) = obfs_key {
                        match crate::protocol::obfs::ObfsStream::accept(
                            stream,
                            &key,
                            obfs_fronting,
                            obfs_awg,
                        )
                        .await
                        {
                            Ok(s) => {
                                if let Err(e) = handler::handle_client(
                                    state_clone,
                                    profile_clone,
                                    s,
                                    addr,
                                    tun_tx,
                                )
                                .await
                                {
                                    log::debug!(
                                        "Client {} disconnected on profile '{}': {}",
                                        addr,
                                        name_conn,
                                        e
                                    );
                                }
                            }
                            Err(e) => log::debug!(
                                "obfs accept failed for {} on profile '{}': {}",
                                addr,
                                name_conn,
                                e
                            ),
                        }
                    } else {
                        if let Err(e) =
                            handler::handle_client(state_clone, profile_clone, stream, addr, tun_tx)
                                .await
                        {
                            log::debug!(
                                "Client {} disconnected on profile '{}': {}",
                                addr,
                                name_conn,
                                e
                            );
                        }
                    }
                });
            }
        }
        TransportProtocol::Udp => {
            // N UDP workers, each on its own SO_REUSEPORT socket. The kernel
            // flow-hashes datagrams across them (a client sticks to one worker), so
            // UDP decrypt spreads across cores. Each worker drains into one TUN queue.
            let workers = nq;
            log::info!(
                "Profile '{}' listening on {} (UDP, {} worker(s))",
                name,
                bind_addr,
                workers
            );
            let mut handles = Vec::with_capacity(workers);
            for wid in 0..workers {
                let socket = udp_handler::bind_reuseport(&bind_addr)?;
                let udp_state = state.clone();
                let udp_profile = profile.clone();
                let tun_tx_udp = in_txs[wid % in_txs.len()].clone();
                let pname = name.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(e) =
                        udp_handler::run_udp_server(udp_state, udp_profile, socket, wid, tun_tx_udp)
                            .await
                    {
                        log::error!("UDP worker {} on profile '{}' exited: {}", wid, pname, e);
                    }
                }));
            }
            for h in handles {
                let _ = h.await;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Minimal single-profile config with a valid [performance] block, so
    /// `validate_profiles` reaches the wire-mode/transport check.
    fn cfg_with(mode: &str, transport: &str) -> ServerConfig {
        let ini = format!(
            "[profile:p]\n\
             bind.address = 0.0.0.0\n\
             bind.port = 4443\n\
             bind.transport = {transport}\n\
             tun.name = vpn0\n\
             tun.address = 10.1.0.1\n\
             tun.netmask = 255.255.255.0\n\
             tun.mtu = 1400\n\
             pool.cidr = 10.1.0.0/24\n\
             pool.exclude = 10.1.0.1\n\
             obf.mode = {mode}\n\
             perf.connection.max_clients = 8\n\
             perf.connection.handshake_timeout_secs = 10\n"
        );
        crate::config::parse_server_config(&ini).expect("fixture INI must parse")
    }

    #[test]
    fn plain_wire_mode_is_rejected_on_udp() {
        // `plain` (raw) is TCP-only by design: a raw datagram stream is a
        // high-entropy "fully encrypted traffic" DPI red-flag and has no framing
        // to delimit records. The guard must fail loud, not silently misbehave.
        let err = validate_profiles(&cfg_with("plain", "udp")).unwrap_err();
        assert!(
            err.to_string().contains("TCP-only"),
            "expected a TCP-only rejection, got: {err}"
        );
    }

    #[test]
    fn plain_wire_mode_is_allowed_on_tcp() {
        assert!(validate_profiles(&cfg_with("plain", "tcp")).is_ok());
    }

    #[test]
    fn unknown_transport_is_rejected() {
        // A typo like `sctp` must fail loud, not silently fall back to TCP via
        // TransportProtocol::from_str().unwrap_or(Tcp).
        let err = validate_profiles(&cfg_with("fake-tls", "sctp")).unwrap_err();
        assert!(
            err.to_string().contains("unknown bind.transport"),
            "expected an unknown-transport rejection, got: {err}"
        );
    }

    #[test]
    fn unknown_wire_mode_is_rejected() {
        // A typo like `realty-tls` must fail loud, not silently run as fake-tls.
        let err = validate_profiles(&cfg_with("realty-tls", "tcp")).unwrap_err();
        assert!(
            err.to_string().contains("unknown obf.mode"),
            "expected an unknown-mode rejection, got: {err}"
        );
    }

    #[test]
    fn reality_tls_wire_mode_label_is_accepted() {
        // `reality-tls` is a valid server-config label (shipped enabled in
        // server-multiprofile.conf); it must pass the allow-list. It needs a
        // reality_proxy short_id to clear the later REALITY check.
        let mut cfg = cfg_with("reality-tls", "tcp");
        cfg.profiles[0].obfuscation.tls.reality_proxy.enabled = true;
        cfg.profiles[0].obfuscation.tls.reality_proxy.short_ids = vec!["0123456789abcdef".into()];
        assert!(validate_profiles(&cfg).is_ok());
    }

    #[test]
    fn fake_tls_is_the_valid_udp_wire_mode() {
        // fake-tls is the only wire mode that also rides UDP (TLS-record-framed
        // datagrams + optional QUIC masking); it must pass validation on UDP.
        assert!(validate_profiles(&cfg_with("fake-tls", "udp")).is_ok());
    }

    #[test]
    fn obfs_wire_mode_requires_obfs_key() {
        // An empty obfs_key derives a publicly-computable constant key (no DPI
        // resistance); validation must fail loud rather than start silently.
        let err = validate_profiles(&cfg_with("obfs", "tcp")).unwrap_err();
        assert!(
            err.to_string().contains("obfs_key"),
            "expected an obfs_key rejection, got: {err}"
        );
    }

    #[test]
    fn obfs_wire_mode_with_key_is_allowed() {
        let mut cfg = cfg_with("obfs", "tcp");
        cfg.profiles[0].obfuscation.obfs_key = "shared-secret".into();
        assert!(validate_profiles(&cfg).is_ok());
    }

    #[test]
    fn reality_without_short_ids_is_rejected() {
        // REALITY with no short_id falls back to the trivially-probeable ALPN
        // heuristic — validation must refuse to start it.
        let mut cfg = cfg_with("fake-tls", "tcp");
        cfg.profiles[0].obfuscation.tls.reality_proxy.enabled = true;
        cfg.profiles[0].obfuscation.tls.reality_proxy.short_ids = vec![];
        let err = validate_profiles(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("short_ids"),
            "expected a short_ids rejection, got: {err}"
        );
        // An all-blank list counts as empty too.
        cfg.profiles[0].obfuscation.tls.reality_proxy.short_ids = vec!["".into(), "  ".into()];
        assert!(validate_profiles(&cfg).is_err());
    }

    #[test]
    fn reality_with_short_id_is_allowed() {
        let mut cfg = cfg_with("fake-tls", "tcp");
        cfg.profiles[0].obfuscation.tls.reality_proxy.enabled = true;
        cfg.profiles[0].obfuscation.tls.reality_proxy.short_ids = vec!["0123456789abcdef".into()];
        assert!(validate_profiles(&cfg).is_ok());
    }

    #[test]
    fn rate_limiter_allows_up_to_limit_then_blocks() {
        let mut rl = RateLimiter::new(2, 60);
        let addr = ip("203.0.113.7");
        assert!(rl.check_and_record(addr)); // 1st
        assert!(rl.check_and_record(addr)); // 2nd
        assert!(!rl.check_and_record(addr), "3rd attempt must be blocked");
    }

    #[test]
    fn rate_limiter_is_per_ip() {
        let mut rl = RateLimiter::new(1, 60);
        assert!(rl.check_and_record(ip("203.0.113.1")));
        assert!(!rl.check_and_record(ip("203.0.113.1")));
        // a different IP has its own independent budget
        assert!(rl.check_and_record(ip("203.0.113.2")));
    }

    #[test]
    fn failed_auth_tarpits_user_after_max_attempts() {
        let mut t = FailedAuthTracker::new(3, 300, 900);
        let user = "alice";
        let src = ip("198.51.100.5");
        assert!(t.user_tarpit(user).is_zero(), "clean state has no delay");
        for _ in 0..3 {
            t.record_failure(user, src);
        }
        assert!(
            t.user_tarpit(user) > Duration::ZERO,
            "user must be tarpitted after 3 failures"
        );
    }

    #[test]
    fn username_flood_never_hard_blocks_a_clean_ip() {
        // The core L1 guarantee: an attacker spraying a victim's username from
        // many distinct IPs throttles (tarpits) that username, but can NEVER
        // hard-lock the victim out — a clean source IP is always allowed.
        let mut t = FailedAuthTracker::new(3, 300, 900);
        let victim = "alice";
        for i in 0..50u8 {
            t.record_failure(victim, ip(&format!("198.51.100.{}", i)));
        }
        assert!(
            t.user_tarpit(victim) > Duration::ZERO,
            "the sprayed username should be throttled"
        );
        assert!(
            t.check_ip(ip("203.0.113.200")).is_ok(),
            "the victim's own clean IP must never be blocked by a username flood"
        );
    }

    #[test]
    fn failed_auth_success_clears_user_but_not_ip() {
        // Several usernames sprayed from one IP trip the per-IP hard lock; a
        // single good login on one user must not unlock the spraying IP.
        let mut t = FailedAuthTracker::new(3, 300, 900);
        let src = ip("198.51.100.9");
        t.record_failure("u1", src);
        t.record_failure("u2", src);
        t.record_failure("u3", src);
        assert!(t.check_ip(src).is_err(), "IP bucket should be locked");
        t.record_success("u1");
        // u1's tarpit history is cleared, but the IP bucket is intentionally kept
        assert!(
            t.check_ip(src).is_err(),
            "IP must stay locked after one success"
        );
    }

    #[test]
    fn failed_auth_skips_oversized_username_key() {
        // An attacker-supplied username longer than the cap must not be stored,
        // so the tarpit map can't be inflated with huge keys — but the source IP
        // is still counted toward the hard lockout.
        let mut t = FailedAuthTracker::new(3, 300, 900);
        let long_user = "a".repeat(MAX_TRACKED_USERNAME_LEN + 1);
        let src = ip("198.51.100.77");
        for _ in 0..3 {
            t.record_failure(&long_user, src);
        }
        assert!(
            t.by_user.is_empty(),
            "oversized username must never be stored in the tarpit map"
        );
        assert!(
            t.check_ip(src).is_err(),
            "the source IP must still be hard-locked after the failures"
        );
    }

    #[test]
    fn failed_auth_is_isolated_across_ips() {
        let mut t = FailedAuthTracker::new(2, 300, 900);
        let attacker = ip("198.51.100.50");
        t.record_failure("bob", attacker);
        t.record_failure("bob", attacker);
        assert!(t.check_ip(attacker).is_err(), "the abusive IP is locked");
        // a clean IP is unaffected
        assert!(t.check_ip(ip("198.51.100.51")).is_ok());
    }

    #[test]
    fn replay_guard_rejects_verbatim_replay() {
        let mut g = ReplayGuard::new(Duration::from_secs(120));
        let sid = [7u8; 32];
        assert!(g.observe(&sid), "first sighting must be fresh");
        assert!(!g.observe(&sid), "a verbatim replay must be rejected");
    }

    #[test]
    fn replay_guard_allows_distinct_tokens() {
        let mut g = ReplayGuard::new(Duration::from_secs(120));
        // Distinct tokens — and genuine reconnects (fresh ephemeral → fresh sid) —
        // are always accepted.
        assert!(g.observe(&[1u8; 32]));
        assert!(g.observe(&[2u8; 32]));
        assert!(g.observe(&[3u8; 32]));
    }

    #[test]
    fn replay_guard_forgets_after_ttl() {
        let ttl = Duration::from_secs(120);
        let mut g = ReplayGuard::new(ttl);
        let t0 = Instant::now();
        let sid = [9u8; 32];
        assert!(g.observe_at(&sid, t0), "first sighting fresh");
        assert!(
            !g.observe_at(&sid, t0 + Duration::from_secs(60)),
            "replay inside the window is rejected"
        );
        // Past the TTL the token is evicted; by then open_session_id's timestamp
        // check rejects it anyway, so a later fresh sighting is correctly accepted.
        assert!(
            g.observe_at(&sid, t0 + ttl + Duration::from_secs(1)),
            "an expired token is forgotten"
        );
    }

    #[test]
    fn replay_guard_evicts_expired_entries() {
        // Memory stays bounded: entries older than the TTL are dropped, not kept.
        let ttl = Duration::from_secs(10);
        let mut g = ReplayGuard::new(ttl);
        let t0 = Instant::now();
        for i in 0..100u32 {
            let mut sid = [0u8; 32];
            sid[..4].copy_from_slice(&i.to_be_bytes());
            g.observe_at(&sid, t0 + Duration::from_secs(i as u64));
        }
        assert!(
            g.len() <= 11,
            "only entries within the TTL window are retained, got {}",
            g.len()
        );
    }

    #[test]
    fn load_users_db_merges_file_and_inline_file_wins() {
        use crate::config::users::UserEntry;

        // A users file as a panel edit would leave it: u1 restricted to profile "pa".
        let path = std::env::temp_dir().join(format!("qeli-loadusers-{}.conf", std::process::id()));
        let file_db = UsersDb {
            users: vec![UserEntry {
                username: "u1".into(),
                password_hash: "$argon2id$file".into(),
                profiles: vec!["pa".into()],
                ..Default::default()
            }],
            groups: Default::default(),
        };
        file_db.save(&path).unwrap();

        // Config carries inline u1 (unrestricted) + inline-only u2, pointing at the file.
        let mut config = ServerConfig::default();
        config.auth.users_file = path.to_string_lossy().into_owned();
        config.auth.users = vec![
            UserEntry {
                username: "u1".into(),
                password_hash: "$argon2id$inline".into(),
                profiles: vec![],
                ..Default::default()
            },
            UserEntry {
                username: "u2".into(),
                password_hash: "$argon2id$inline2".into(),
                profiles: vec![],
                ..Default::default()
            },
        ];

        let db = load_users_db(&config).unwrap();
        let u1 = db
            .users
            .iter()
            .find(|u| u.username == "u1")
            .expect("u1 present");
        // The FILE copy wins → a panel edit to allowed-profiles applies even with
        // inline users in the config (the reported bug).
        assert_eq!(u1.profiles, vec!["pa".to_string()]);
        assert_eq!(u1.password_hash, "$argon2id$file");
        // Inline-only users are still merged in.
        assert!(
            db.users.iter().any(|u| u.username == "u2"),
            "inline-only u2 must be merged"
        );
        assert_eq!(db.users.len(), 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_users_db_inline_only_when_file_absent() {
        use crate::config::users::UserEntry;
        let missing = std::env::temp_dir().join(format!("qeli-none-{}.conf", std::process::id()));
        let _ = std::fs::remove_file(&missing);
        let mut config = ServerConfig::default();
        config.auth.users_file = missing.to_string_lossy().into_owned();
        config.auth.users = vec![UserEntry {
            username: "solo".into(),
            password_hash: "$argon2id$x".into(),
            ..Default::default()
        }];
        // Missing file + inline present → inline loads (no error).
        let db = load_users_db(&config).unwrap();
        assert_eq!(db.users.len(), 1);
        assert_eq!(db.users[0].username, "solo");
    }
}
