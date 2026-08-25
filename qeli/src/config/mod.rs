pub mod server;
// Config data definitions + qeli:// link helpers: several fields/methods are
// declarative API surface or used only by tests / the Android port.
#[allow(dead_code)]
pub mod client;
pub mod format;
mod server_ini;
#[allow(dead_code)]
pub mod share;
pub mod users;

use serde::{Deserialize, Serialize};

/// Parse a server config. The one and only on-disk format is flat INI
/// (`[auth]` / `[web]` / `[logging]` singletons + `[profile:<name>]` sections);
/// see [`server::ServerConfig::from_ini`].
pub fn parse_server_config(s: &str) -> anyhow::Result<server::ServerConfig> {
    let doc = format::IniDoc::parse(s)?;
    server::ServerConfig::from_ini(&doc)
}

/// Known platform/lifecycle keys that the Rust connection parser deliberately does not own.
/// They are not typos: GUI editors preserve them and the relevant platform adapter applies
/// them. Reporting them as unknown would train operators to ignore a real misspelling report.
pub const GUI_ONLY_CLIENT_KEYS: &[&str] = &[
    "dev_node",
    "metric",
    "persist_tun",
    "route_file",
    // Platform-owned, and the mirror image of the GUI ports' own allowlists: GUI clients
    // WRITE these into a shared profile, so `check-config --client` must accept them even
    // though the headless Rust client does not classify OS processes. `allow_lan` is mobile;
    // `apps`/`apps_mode` are implemented by Android and the Windows/macOS platform adapters.
    // (Audit 2026-08-02, §2.)
    "allow_lan",
    "apps",
    "apps_mode",
    // Display metadata and GUI reconnect policy remain outside the Rust connection attempt.
    // Transport-owned timeout/padding/heartbeat/shaping keys used to be listed here too; the
    // shared core now parses and applies them, so exempting them would hide parser drift.
    "name",
    "reconnect",
    "reconnect_retries",
    "reconnect_base_delay",
    "reconnect_max_delay",
];

/// Keys that USED to exist. A config carrying one is stale rather than misspelled, and the
/// distinction matters in the message the operator sees.
pub const RETIRED_KEYS: &[&str] = &[
    "password_hash", // [auth] only — web/user password_hash are real
    "token_ttl_secs",
    "obf.cipher",
    "obf.tls.server_names",
    "obf.tls.session_id",
    "obf.tls.supported_groups",
    "obf.tls.key_share_entropy_bytes",
    "obf.http2_masking.enabled",
    "obf.http2_masking.ratio",
    "obf.traffic_normalization.randomize_sequence",
    "obf.anti_fingerprinting.rotate_ciphers_every",
    "obf.quic.cid_length",
    "obf.quic.version",
    "pool.lease_time_secs",
    "perf.tun.write_buffer_size",
    "perf.tun.read_timeout_ms",
    "perf.tun.max_pending_packets",
    "perf.connection.rate_limit_packets_per_sec",
];

/// GUI-owned keys are valid only in the flat client `[qeli]` section. Matching the name
/// alone would hide a misspelling or misplaced no-op setting in any other section.
pub fn is_gui_only_client_key(section: &str, key: &str) -> bool {
    section == "[qeli]" && GUI_ONLY_CLIENT_KEYS.contains(&key)
}

/// Retired keys remain recognised only where the old setting actually lived. In particular,
/// `password_hash` is still security-critical under `[web]` and `[user:*]`, so a same-named
/// unread key elsewhere must never be waved through as harmless legacy configuration.
pub fn is_retired_key(section: &str, key: &str) -> bool {
    match key {
        "password_hash" | "token_ttl_secs" => section == "[auth]",
        key if RETIRED_KEYS.contains(&key) => {
            section == "[qeli]" || (section.starts_with("[profile:") && section.ends_with(']'))
        }
        _ => false,
    }
}

/// Key NAMES nobody read — i.e. typos — with the two known-benign classes filtered out.
///
/// `unread_keys` is the only thing that can catch a misspelled key name: a wrong name is not a
/// parse error, it simply never reaches an accessor, and the field keeps its default. For
/// `kill_swtich = true` that means the kill switch is OFF and nothing says so.
pub fn unknown_keys(doc: &format::IniDoc, client: bool) -> Vec<String> {
    doc.unread_keys()
        .into_iter()
        // The exemption is SECTION-SCOPED. These names are `[qeli]` keys; the same name under
        // another header is read by nobody, so exempting it there would wave through a setting
        // that does not work — `[logging] reconnect = false` looks accepted and does nothing.
        // The list grew to 22 names, which is 22 more chances for that to happen quietly.
        //
        // `header()` returns the BRACKETED form (`[qeli]`), which is what the message below
        // wants; comparing it against a bare "qeli" silently matched nothing and turned the
        // exemption off entirely, so every desktop profile went back to reporting 22
        // misspellings. Compared in the shape it actually has.
        .filter(|(section, key)| !(client && is_gui_only_client_key(section, key)))
        .filter(|(section, key)| !is_retired_key(section, key))
        .map(|(section, k)| {
            if section.is_empty() {
                k.to_string()
            } else {
                // Already bracketed — wrapping it again printed `[[qeli]] reconnect`.
                format!("{section} {k}")
            }
        })
        .collect()
}

/// Parse a client config and REFUSE anything the runtime would silently reinterpret.
///
/// Two independent ways a config can lie about itself, and both used to fail OPEN on the real
/// start while only `check-config` reported them:
///   * a misspelled key NAME (`kill_swtich`) — never read, so the field keeps its default;
///   * a value PRESENT but not understood (`kill_switch = ture`) — `bool_or` records it and
///     substitutes the default.
///
/// Either one silently disables a security setting, so the process about to ACT on the config
/// is exactly where they must be fatal. `check-config` keeps its own flow: it reports every
/// problem at once rather than stopping at the first. (Audit 2026-08-01, §4/§5.)
/// Parse a SERVER config, returning it together with the values that were present but not
/// understood.
///
/// The server deliberately WARNS rather than refuses on these — aborting a start over a
/// long-standing typo would take a working server down on upgrade, and the operator sees the
/// line in the journal at boot. What changed is only where the findings come from: they belong
/// to this parse rather than to a process-global that any other thread could drain.
/// (Audit 2026-08-01, §2.)
pub fn parse_server_config_reporting(
    s: &str,
) -> anyhow::Result<(server::ServerConfig, Vec<String>)> {
    let doc = format::IniDoc::parse(s)?;
    let cfg = server::ServerConfig::from_ini(&doc)?;
    let mut findings = doc.bad_values();
    // Misspelled key NAMES, which this path did not look at AT ALL. Only the value-level
    // findings were surfaced, so `kill_switch = ture` warned while `kill_swtich = true` — the
    // same setting, silently off, one letter away — produced nothing anywhere but
    // `check-config`, a command nobody runs on an already-working server. The client has
    // refused both since §4; the server reports both and still starts, for the reason above.
    // (Audit 2026-08-01, §1.)
    let unknown = unknown_keys(&doc, false);
    if !unknown.is_empty() {
        findings.push(format!(
            "unknown key(s), likely misspelled — nothing reads these, so the setting they were \
             meant to change is at its default: {}",
            unknown.join(", ")
        ));
    }
    Ok((cfg, findings))
}

pub fn parse_client_config_strict(s: &str) -> anyhow::Result<client::ClientConfig> {
    let doc = format::IniDoc::parse(s)?;
    let cfg = client::ClientConfig::from_ini(&doc)?;
    let unknown = unknown_keys(&doc, true);
    let bad = doc.bad_values();
    if unknown.is_empty() && bad.is_empty() {
        return Ok(cfg);
    }
    let mut why: Vec<String> = Vec::new();
    if !unknown.is_empty() {
        why.push(format!(
            "unknown key(s), likely misspelled: {}",
            unknown.join(", ")
        ));
    }
    why.extend(bad.iter().cloned());
    anyhow::bail!(
        "refusing to start: {} config problem(s) whose defaults would otherwise be substituted silently
  {}",
        unknown.len() + bad.len(),
        why.join("
  ")
    )
}

/// Parse a client config. The one and only format is flat INI with a `[qeli]`
/// section; see [`client::ClientConfig::from_ini`].
pub fn parse_client_config(s: &str) -> anyhow::Result<client::ClientConfig> {
    let doc = format::IniDoc::parse(s)?;
    client::ClientConfig::from_ini(&doc)
}

/// Upsert `key = value` pairs inside a singleton `[section]` of a flat-INI
/// config, **preserving comments, blank lines and every other line** verbatim.
///
/// This is the comment-preserving counterpart to a full struct re-serialization
/// (`ServerConfig::to_ini_string`, which strips comments): use it for surgical
/// edits of a handful of keys on a hand-written, comment-heavy config — the
/// `qeli set-web-password` CLI (`[web]`) and the panel's brute-force settings
/// editor (`[auth]`) both go through here.
///
/// Rules: an active (non-comment) assignment line for a key is replaced in place;
/// keys not found in the section are appended to the end of it; if the section is
/// absent entirely, it is created at the end of the file. A trailing newline is
/// preserved iff the input had one. Pure `std` (string only), so it is unit-tested
/// on every platform.
pub fn set_section_keys(original: &str, section: &str, updates: &[(&str, String)]) -> String {
    let header = format!("[{}]", section);

    // Does `line_trimmed` start an active `key = ...` / `key=...` assignment?
    // Comment lines (`#` / `;`) never match, so a commented-out key is left alone.
    fn is_active_key(line_trimmed: &str, key: &str) -> bool {
        if line_trimmed.starts_with('#') || line_trimmed.starts_with(';') {
            return false;
        }
        match line_trimmed.strip_prefix(key) {
            Some(rest) => rest.trim_start().starts_with('='),
            None => false,
        }
    }

    let mut out: Vec<String> = Vec::new();
    let mut in_section = false;
    let mut section_seen = false;
    let mut written: Vec<String> = Vec::new();

    for line in original.lines() {
        let t = line.trim_start();
        let is_header = t.starts_with('[') && t.trim_end().ends_with(']');
        if is_header {
            // Leaving the target section: emit any keys we haven't placed yet.
            if in_section {
                for u in updates {
                    if !written.iter().any(|w| w == u.0) {
                        out.push(format!("{} = {}", u.0, format::quote_if_needed(&u.1)));
                    }
                }
            }
            in_section = t.trim_end() == header;
            if in_section {
                section_seen = true;
                written.clear();
            }
            out.push(line.to_string());
            continue;
        }
        if in_section {
            let mut replaced = false;
            for u in updates {
                if !written.iter().any(|w| w == u.0) && is_active_key(t, u.0) {
                    out.push(format!("{} = {}", u.0, format::quote_if_needed(&u.1)));
                    written.push(u.0.to_string());
                    replaced = true;
                    break;
                }
            }
            if replaced {
                continue;
            }
        }
        out.push(line.to_string());
    }

    // The target section was the final one: flush any remaining keys at EOF.
    if in_section {
        for u in updates {
            if !written.iter().any(|w| w == u.0) {
                out.push(format!("{} = {}", u.0, format::quote_if_needed(&u.1)));
            }
        }
    }
    // No such section anywhere: append a fresh one.
    if !section_seen {
        out.push(String::new());
        out.push(header);
        for u in updates {
            out.push(format!("{} = {}", u.0, format::quote_if_needed(&u.1)));
        }
    }

    let mut s = out.join("\n");
    if original.ends_with('\n') {
        s.push('\n');
    }
    s
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    pub file: Option<String>,
    #[serde(default = "default_log_format")]
    pub format: String,
    /// Shape of the timestamp prefix: `datetime` (local, default) | `rfc3339` (UTC) |
    /// `time` (local, no date) | `epoch` | `none` (platform already stamps the line).
    /// See [`crate::util::log_timestamp`].
    #[serde(default = "default_log_time_format")]
    pub time_format: String,
}

/// Obfuscation parameters the server pushes to the client at handshake time, so
/// the client no longer has to carry (and keep in sync) these in its own config.
/// Only the params used in the post-auth data phase are pushed — the wire `mode`,
/// `obfs_key`, `cipher` and QUIC masking are needed *before* auth to wrap the
/// handshake itself and therefore stay in the client link/config.
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct PushedObf {
    #[serde(default)]
    pub padding: PaddingConfig,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
    #[serde(default)]
    pub traffic_normalization: TrafficNormalizationConfig,
    #[serde(default)]
    pub traffic_shaping: TrafficShapingConfig,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct PaddingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_padding_min")]
    pub min_bytes: u16,
    #[serde(default = "default_padding_max")]
    pub max_bytes: u16,
    #[serde(default = "default_true")]
    pub randomize: bool,
    #[serde(default = "default_one")]
    pub probability: f64,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct FragmentationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_frag_min")]
    pub min_chunk_size: u16,
    #[serde(default = "default_frag_max")]
    pub max_chunk_size: u16,
    #[serde(default = "default_frag_max_per_packet")]
    pub max_fragments_per_packet: u16,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct HeartbeatConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_heartbeat_interval")]
    pub interval_ms: u64,
    #[serde(default = "default_heartbeat_data_size")]
    pub data_size_bytes: u16,
    #[serde(default = "default_heartbeat_jitter")]
    pub jitter_ms: u64,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct TrafficNormalizationConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_round_sizes")]
    pub round_sizes: Vec<u16>,
}

/// Flow-shaping (DPI-AUDIT 6.1/6.2): when enabled, an idle tunnel emits cover
/// traffic at exponentially-distributed (non-periodic) gaps instead of a fixed
/// heartbeat, so the link looks like interactive browsing think-time rather than
/// either dead air or a metronome beacon. Cover packets are empty-payload
/// encrypted records (the peer drops them like a heartbeat) — not wire-breaking.
/// Off by default; costs only idle bandwidth, capped by `budget_bytes_per_sec`.
/// Real packets are never delayed (Phase 1 = zero added latency). Pushed to the
/// client like padding/heartbeat so both ends shape consistently.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TrafficShapingConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// Mean of the exponential idle inter-cover gap (ms).
    #[serde(default = "default_shaping_gap_mean")]
    pub idle_gap_mean_ms: u64,
    #[serde(default = "default_shaping_gap_min")]
    pub idle_gap_min_ms: u64,
    #[serde(default = "default_shaping_gap_max")]
    pub idle_gap_max_ms: u64,
    /// Cover-traffic ceiling (bytes/sec); 0 disables cover even when `enabled`.
    #[serde(default = "default_shaping_budget")]
    pub budget_bytes_per_sec: u32,
    #[serde(default = "default_shaping_min_size")]
    pub min_size: u16,
    #[serde(default = "default_shaping_max_size")]
    pub max_size: u16,
    /// STEALTH mode (opt-in, trades throughput for DPI passability; DPI-AUDIT 6.1
    /// "download shape"). When on (requires `enabled`), the data plane is rate-capped
    /// to `stealth_rate_mbps` AND cover runs UNDER LOAD (not just idle) — the small
    /// cover packets mix into the rate-capped full-MTU stream, breaking both the
    /// "100% full-MTU" size tell and the constant-rate timing tell, without any
    /// wire-format change (cover = the same empty records all peers already drop).
    #[serde(default = "default_false")]
    pub stealth: bool,
    /// Data-plane rate cap (Mbps) applied in stealth mode. Browsing-ish; the lower
    /// it is, the less the flow looks like a bulk download (and the slower it is).
    #[serde(default = "default_stealth_rate")]
    pub stealth_rate_mbps: u32,
}

impl Default for TrafficShapingConfig {
    fn default() -> Self {
        TrafficShapingConfig {
            enabled: false,
            idle_gap_mean_ms: default_shaping_gap_mean(),
            idle_gap_min_ms: default_shaping_gap_min(),
            idle_gap_max_ms: default_shaping_gap_max(),
            budget_bytes_per_sec: default_shaping_budget(),
            min_size: default_shaping_min_size(),
            max_size: default_shaping_max_size(),
            stealth: false,
            stealth_rate_mbps: default_stealth_rate(),
        }
    }
}

impl TrafficShapingConfig {
    /// Resolve to the protocol-layer [`crate::protocol::ShapingConfig`].
    pub fn to_shaping(&self) -> crate::protocol::ShapingConfig {
        crate::protocol::ShapingConfig {
            enabled: self.enabled,
            idle_gap_mean_ms: self.idle_gap_mean_ms,
            idle_gap_min_ms: self.idle_gap_min_ms,
            idle_gap_max_ms: self.idle_gap_max_ms,
            budget_bytes_per_sec: self.budget_bytes_per_sec,
            min_size: self.min_size,
            max_size: self.max_size,
            stealth: self.stealth,
            stealth_rate_mbps: self.stealth_rate_mbps,
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct TcpConfig {
    #[serde(default = "default_true")]
    pub nodelay: bool,
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,
    #[serde(default = "default_buffer_size")]
    pub send_buffer_size: u32,
    #[serde(default = "default_buffer_size")]
    pub recv_buffer_size: u32,
}

/// Socket buffers for a UDP listener. Separate from [`TcpConfig`] because the two need
/// opposite defaults, not because the knobs differ.
///
/// TCP autotunes between the `tcp_rmem` bounds, so a fixed size is a hint at most. **UDP has
/// no autotuning at all**: the socket keeps whatever `net.core.rmem_default` was at creation
/// — 208 KB on a stock kernel, only tens of milliseconds of traffic at tunnel speeds. One
/// scheduling stall and the kernel drops datagrams, and every dropped datagram is a lost TCP
/// segment *inside* somebody's tunnel, so their connection halves its window.
///
/// The server used to set neither, relying on the installer to raise `net.core.rmem_max` —
/// which does nothing on its own, because `rmem_max` is a CEILING for explicit requests, not
/// a default. A container, a hand-started binary or a pre-existing install therefore ran on
/// the 208 KB default no matter what the installer wrote. (Audit 2026-08-02, §14.)
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UdpPerfConfig {
    /// `SO_SNDBUF`. `0` leaves the kernel value alone — an undersized send buffer only
    /// applies backpressure, it never loses data, and pinning a size here would *lower* it
    /// on a host tuned for exactly this workload.
    #[serde(default)]
    pub send_buffer_size: u32,
    /// `SO_RCVBUF`. A real default rather than "leave it alone", for the reason above.
    /// `0` opts back out to the kernel value.
    #[serde(default = "default_udp_recv_buffer")]
    pub recv_buffer_size: u32,
    /// Round-trip state: omitted size enables bounded auto-grow, while an explicit size is
    /// a fixed operator override. This bit must cross the structured JSON API as well as the
    /// INI codec; hiding it made any unrelated panel save turn a fixed override back into
    /// automatic mode and silently remove `perf.udp.recv_buffer_size` from disk.
    #[serde(default = "default_true")]
    pub recv_buffer_auto: bool,
}

impl Default for UdpPerfConfig {
    fn default() -> Self {
        UdpPerfConfig {
            send_buffer_size: 0,
            recv_buffer_size: default_udp_recv_buffer(),
            recv_buffer_auto: true,
        }
    }
}

fn default_udp_recv_buffer() -> u32 {
    crate::transport_core::udp_buffer::AUTO_INITIAL_RECV_BYTES
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct TunPerfConfig {
    #[serde(default = "default_tun_buf")]
    pub read_buffer_size: usize,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ConnectionConfig {
    #[serde(default = "default_max_clients")]
    pub max_clients: u32,
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// New-connection rate limit (per source IP): at most `new_session_rate_max`
    /// fresh sessions per `new_session_rate_window_secs`. Throttles connection
    /// floods without affecting established tunnels. Was hardcoded 10/60.
    #[serde(default = "default_new_session_rate_max")]
    pub new_session_rate_max: usize,
    #[serde(default = "default_new_session_rate_window_secs")]
    pub new_session_rate_window_secs: u64,
}

fn default_log_level() -> String {
    "info".into()
}

#[cfg(test)]
mod tests {

    /// A profile written by the desktop GUI must produce NO "check the spelling" report.
    ///
    /// The keys below are platform/lifecycle fields the Rust connection parser does not read.
    /// They belong in `GUI_ONLY_CLIENT_KEYS`; when they were
    /// missing from it, `check-config --client` failed with exit 1 on a perfectly correct
    /// profile and called 22 valid keys misspellings. Asserting on the list itself rather than
    /// on the command keeps the failure message pointed at the cause — add a key to the GUI
    /// and this test names it. (Audit 2026-08-03, F1.)
    #[test]
    fn gui_only_list_covers_every_desktop_key() {
        let gui_only = [
            // profile metadata / desktop-side connection knobs
            "name",
            "reconnect",
            "reconnect_retries",
            "reconnect_base_delay",
            "reconnect_max_delay",
            // platform-specific interface handling
            "dev_node",
            "metric",
            "persist_tun",
            "route_file",
            // platform-owned
            "allow_lan",
            "apps",
            "apps_mode",
        ];
        let missing: Vec<_> = gui_only
            .iter()
            .filter(|k| !super::GUI_ONLY_CLIENT_KEYS.contains(k))
            .collect();
        assert!(
            missing.is_empty(),
            "GUI_ONLY_CLIENT_KEYS is missing {} key(s) the desktop clients write — \
             `check-config --client` will report them as misspellings on a valid profile: {:?}",
            missing.len(),
            missing
        );
    }

    /// The GUI-key exemption must not leak out of `[qeli]`.
    ///
    /// The list exists so a desktop profile is not reported as 22 misspellings. Matching on the
    /// NAME alone extended that pardon to every section: `[logging] reconnect = false` looks
    /// accepted and is read by nobody, which is precisely the silent-default failure the
    /// unknown-key check was built to catch — and the wider the list grew, the wider that hole
    /// got. Both halves are asserted here, because a fix for one that breaks the other just
    /// moves the problem.
    #[test]
    fn gui_key_exemption_is_scoped_to_the_qeli_section() {
        let doc = super::format::IniDoc::parse(
            "[qeli]\nserver = 1.2.3.4:443\nuser = u\npass = p\nreconnect = false\n\
             [logging]\nreconnect = false\n",
        )
        .expect("parses");
        let _ = super::client::ClientConfig::from_ini(&doc).expect("valid client config");
        let unknown = super::unknown_keys(&doc, true);
        assert!(
            unknown.iter().any(|k| k == "[logging] reconnect"),
            "a GUI key under the wrong section must still be reported, got {unknown:?}"
        );
        assert!(
            !unknown.iter().any(|k| k == "reconnect"),
            "the same key in [qeli] is a real desktop setting and must stay exempt, got {unknown:?}"
        );
    }

    #[test]
    fn retired_key_exemption_is_scoped_to_its_historical_section() {
        assert!(super::is_retired_key("[auth]", "password_hash"));
        assert!(super::is_retired_key("[auth]", "token_ttl_secs"));
        assert!(!super::is_retired_key("[web]", "token_ttl_secs"));
        assert!(!super::is_retired_key("[logging]", "password_hash"));

        assert!(super::is_retired_key("[qeli]", "obf.cipher"));
        assert!(super::is_retired_key(
            "[profile:tcp]",
            "perf.tun.write_buffer_size"
        ));
        assert!(!super::is_retired_key("[logging]", "obf.cipher"));
    }

    /// A wire mode that needs a stream must not validate on a datagram transport.
    ///
    /// `proto` and `mode` were each checked against their own enum and never against each
    /// other, so `udp` + `reality-tls` passed here while the SERVER refuses it — the client
    /// could not reach any working profile, and failed later and less clearly. `reality-tls` is
    /// the dangerous half: nothing in the name says TCP, so the operator believes they have the
    /// strongest masking available while the datagram path falls back to fake-tls framing.
    /// (Audit 2026-08-03, P2.)
    #[test]
    fn stream_only_wire_modes_are_refused_on_udp() {
        // Each mode carries whatever IT requires (a REALITY short_id and a pinned key, an
        // obfs key), so this test fails on the transport pairing and nothing else.
        let profile = |proto: &str, mode: &str| {
            let extra = match mode {
                "reality-tls" => concat!(
                    "reality_sid = 0123456789abcdef\n",
                    "sni = www.cloudflare.com\n",
                    "key = 1111111111111111111111111111111111111111111111111111111111111111\n"
                ),
                "obfs" => "obfs_key = deadbeefcafe\n",
                _ => "",
            };
            format!(
                "[qeli]\nserver = 1.2.3.4:443\nuser = u\npass = p\n\
                 proto = {proto}\nmode = {mode}\n{extra}"
            )
        };
        for mode in ["plain", "reality-tls"] {
            let err = super::parse_client_config(&profile("udp", mode))
                .and_then(|c| c.validate())
                .expect_err(&format!("udp + {mode} must be refused"));
            let msg = err.to_string();
            assert!(
                msg.contains("TCP-only") && msg.contains(mode),
                "the message must name the mode and say why, got: {msg}"
            );
            // The same mode over TCP is exactly what it is for.
            super::parse_client_config(&profile("tcp", mode))
                .and_then(|c| c.validate())
                .unwrap_or_else(|e| panic!("tcp + {mode} must still be accepted: {e}"));
        }
        // ...and the datagram modes are untouched, so this cannot pass by refusing all UDP.
        for mode in ["fake-tls", "obfs"] {
            super::parse_client_config(&profile("udp", mode))
                .and_then(|c| c.validate())
                .unwrap_or_else(|e| panic!("udp + {mode} must be accepted: {e}"));
        }
    }

    #[test]
    fn user_profile_authorization() {
        let all = crate::config::users::UserEntry {
            username: "all".into(),
            password_hash: "x".into(),
            ..Default::default()
        };
        let tcp_only = crate::config::users::UserEntry {
            username: "tcp_only".into(),
            password_hash: "x".into(),
            profiles: vec!["tcp".into()],
            ..Default::default()
        };
        // empty profiles list => allowed on every interface
        assert!(all.allowed_on_profile("tcp"));
        assert!(all.allowed_on_profile("udp"));
        // restricted user: only its listed profile, blocked elsewhere
        assert!(tcp_only.allowed_on_profile("tcp"));
        assert!(!tcp_only.allowed_on_profile("udp"));
    }

    use crate::config::set_section_keys;

    #[test]
    fn set_section_keys_replaces_in_place_and_keeps_comments() {
        let src = "\
; keep me
[auth]
users_file = /etc/qeli/users.conf   ; inline note preserved elsewhere
brute_force.max_attempts = 5
brute_force.window_secs = 300
brute_force.lockout_secs = 900

[web]
enabled = true
";
        let out = set_section_keys(
            src,
            "auth",
            &[
                ("brute_force.max_attempts", "3".into()),
                ("brute_force.window_secs", "60".into()),
                ("brute_force.lockout_secs", "120".into()),
            ],
        );
        // Comments and the untouched [web] section survive.
        assert!(out.contains("; keep me"));
        assert!(out.contains("[web]\nenabled = true"));
        assert!(out.contains("users_file = /etc/qeli/users.conf"));
        // Values updated in place (no duplicates).
        assert!(out.contains("brute_force.max_attempts = 3"));
        assert!(out.contains("brute_force.window_secs = 60"));
        assert!(out.contains("brute_force.lockout_secs = 120"));
        assert_eq!(out.matches("brute_force.max_attempts").count(), 1);
        // Re-parses cleanly and the new values land under [auth].
        let auth = crate::config::format::IniDoc::parse(&out)
            .unwrap()
            .section("auth")
            .unwrap()
            .clone();
        assert_eq!(auth.parse_or::<u32>("brute_force.max_attempts", 0), 3);
        assert_eq!(auth.parse_or::<u64>("brute_force.window_secs", 0), 60);
        assert_eq!(auth.parse_or::<u64>("brute_force.lockout_secs", 0), 120);
    }

    #[test]
    fn set_section_keys_appends_missing_keys_into_existing_section() {
        // [auth] present but relies on brute_force defaults (keys absent).
        let src = "[auth]\nusers_file = /etc/qeli/users.conf\n\n[web]\nenabled = true\n";
        let out = set_section_keys(src, "auth", &[("brute_force.max_attempts", "7".into())]);
        let doc = crate::config::format::IniDoc::parse(&out).unwrap();
        assert_eq!(
            doc.section("auth")
                .unwrap()
                .parse_or::<u32>("brute_force.max_attempts", 0),
            7
        );
        // Inserted under [auth], not [web].
        assert!(out.contains("[web]\nenabled = true"));
        assert!(out.contains("brute_force.max_attempts = 7"));
    }

    #[test]
    fn set_section_keys_creates_absent_section() {
        let src = "[web]\nenabled = true\n";
        let out = set_section_keys(src, "auth", &[("brute_force.lockout_secs", "42".into())]);
        assert!(out.contains("[auth]"));
        let doc = crate::config::format::IniDoc::parse(&out).unwrap();
        assert_eq!(
            doc.section("auth")
                .unwrap()
                .parse_or::<u64>("brute_force.lockout_secs", 0),
            42
        );
    }

    #[test]
    fn set_section_keys_ignores_commented_key_and_trailing_newline() {
        let no_nl = "[auth]\n; brute_force.max_attempts = 99\nusers_file = /etc/qeli/users.conf";
        let out = set_section_keys(no_nl, "auth", &[("brute_force.max_attempts", "4".into())]);
        // The commented line is left intact; a fresh active key is added.
        assert!(out.contains("; brute_force.max_attempts = 99"));
        assert!(out.contains("brute_force.max_attempts = 4"));
        // Input had no trailing newline → output has none either.
        assert!(!out.ends_with('\n'));
    }
}
fn default_log_format() -> String {
    "plain".into()
}
fn default_log_time_format() -> String {
    "datetime".into()
}
fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_padding_min() -> u16 {
    32
}
fn default_padding_max() -> u16 {
    512
}
fn default_one() -> f64 {
    1.0
}
// Handshake-record split sizes. The point is that the ServerHello must not arrive
// in ONE segment, where a signature matcher can read it whole — not that it be
// shredded. The old 64/512/16 cut a ~2 KB ServerHello into ~16 segments of ~125 B,
// which defeats the matcher but is itself an anomaly: no real TLS server writes
// like that, so it trades one tell for another. 256/1024/4 gives 2-4 plausibly
// sized segments — indistinguishable from ordinary TCP segmentation.
fn default_frag_min() -> u16 {
    256
}
fn default_frag_max() -> u16 {
    1024
}
fn default_frag_max_per_packet() -> u16 {
    4
}
fn default_heartbeat_interval() -> u64 {
    15_000
}
fn default_heartbeat_data_size() -> u16 {
    16
}
fn default_heartbeat_jitter() -> u64 {
    20
}
fn default_round_sizes() -> Vec<u16> {
    vec![64, 128, 256, 512, 1024, 1500]
}
fn default_shaping_gap_mean() -> u64 {
    700
}
fn default_shaping_gap_min() -> u64 {
    40
}
fn default_shaping_gap_max() -> u64 {
    6_000
}
fn default_shaping_budget() -> u32 {
    16 * 1024
}
fn default_shaping_min_size() -> u16 {
    64
}
fn default_shaping_max_size() -> u16 {
    1024
}
fn default_stealth_rate() -> u32 {
    2
}
fn default_keepalive() -> u64 {
    60
}
fn default_buffer_size() -> u32 {
    262144
}
fn default_tun_buf() -> usize {
    65535
}
fn default_max_clients() -> u32 {
    128
}
fn default_handshake_timeout() -> u64 {
    10
}
fn default_idle_timeout() -> u64 {
    300
}
fn default_new_session_rate_max() -> usize {
    10
}
fn default_new_session_rate_window_secs() -> u64 {
    60
}
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct QuicMaskingConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
}

/// AmneziaWG-style junk-record pre-handshake (F2). In `obfs` mode only, when
/// `enabled && jc > 0`, the sender emits `jc` junk records (each `jmin..=jmax`
/// random bytes) and the receiver reads+discards exactly `jc` of them, right
/// before the 12-byte ChaCha20 nonce exchange (after the WS front handshake when
/// fronting=websocket, else right after TCP connect). Both ends MUST share the
/// same `jc`; `jmin`/`jmax` are sender-only. Off by default => zero extra bytes
/// => byte-identical to the current wire. Caps: `jc <= 128`, record len <= 1400
/// (enforced at config load — warn+clamp, never panic — to bound memory).
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AwgConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// Junk record count sent before the nonce exchange. 0 = disabled. Capped 128.
    #[serde(default = "default_awg_jc")]
    pub jc: u32,
    /// Minimum junk record length (bytes). Sender-only.
    #[serde(default = "default_awg_jmin")]
    pub jmin: u16,
    /// Maximum junk record length (bytes); require jmin <= jmax <= 1400. Sender-only.
    #[serde(default = "default_awg_jmax")]
    pub jmax: u16,
}

impl Default for AwgConfig {
    fn default() -> Self {
        AwgConfig {
            enabled: false,
            jc: default_awg_jc(),
            jmin: default_awg_jmin(),
            jmax: default_awg_jmax(),
        }
    }
}

impl AwgConfig {
    /// Hard cap on junk record count (bounds memory / handshake cost).
    pub const JC_CAP: u32 = 128;
    /// Hard cap on a single junk record length (bounds memory).
    pub const LEN_CAP: u16 = 1400;

    /// Clamp out-of-range fields to their valid domain, logging a warning for each
    /// change. NEVER panics — a bad hand-written value degrades gracefully instead
    /// of aborting the daemon. Called at config load (server profile + client).
    pub fn sanitize(&mut self, ctx: &str) {
        if self.jc > Self::JC_CAP {
            log::warn!(
                "{}: obf.awg.jc {} exceeds cap {}, clamping",
                ctx,
                self.jc,
                Self::JC_CAP
            );
            self.jc = Self::JC_CAP;
        }
        if self.jmax > Self::LEN_CAP {
            log::warn!(
                "{}: obf.awg.jmax {} exceeds cap {}, clamping",
                ctx,
                self.jmax,
                Self::LEN_CAP
            );
            self.jmax = Self::LEN_CAP;
        }
        if self.jmin > self.jmax {
            log::warn!(
                "{}: obf.awg.jmin {} > jmax {}, clamping jmin to jmax",
                ctx,
                self.jmin,
                self.jmax
            );
            self.jmin = self.jmax;
        }
    }
}

fn default_awg_jc() -> u32 {
    0
}
fn default_awg_jmin() -> u16 {
    40
}
fn default_awg_jmax() -> u16 {
    300
}
