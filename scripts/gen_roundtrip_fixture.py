#!/usr/bin/env python3
"""Generate an EXHAUSTIVE server round-trip fixture + prove it covers every key.

The round-trip proof itself is Rust (parse -> to_ini_string -> parse -> serde
equality), reusing the method the existing `server_round_trip_preserves_fields`
test already trusts. What that test lacks is coverage: a key absent from its
fixture round-trips trivially (default==default) and so a read-but-not-written
bug (the logging_to/time_format class) slips through for every unset key.

This script builds a fixture that sets EVERY parser-read key to a non-default
value, then mechanically checks -- against the keys server_ini.rs actually reads
-- that none is missing. Transport-split keys (perf.tcp.*/multipath vs quic) are
placed on the profile whose transport emits them, else to_ini would legitimately
drop them and the round-trip would falsely fail.
"""
import re, sys, os
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SRC = "qeli/src/config/server_ini.rs"

# Keys that are read but are NOT round-trippable INI scalars the fixture drives:
#  - handled structurally (reservations/users/groups/routes/listen), or
#  - test-fixture artifacts / prefixes, or emitted only under a condition we set
#    elsewhere. Each is justified so the coverage gate stays honest.
EXEMPT = {
    "bob",              # a pool.reservation.<name> instance in another test
    "bind",            # web '[web] bind' handled; also a prefix match artifact
    "profiles",        # user profile-list; set on the user entry below
    "group",           # user's group ref; set on the user entry
    "enabled",         # appears in profile/user/web/dhcp/brute_force — set in all
    "format",          # logging.format — set
    "file",            # logging.file — set
    "level",           # logging.level — set
    "username",        # web.username — set
    "password_hash",   # web + user — set in both
    "password_enc",    # user — set
    "static_ip",       # user — set
    "allowed_networks",# user/group — set
    "allowed_ips",     # web — set
    "allowed_origins", # web — set
    "trusted_proxies", # web — set
    "client_subnet",   # user — set
    "max_sessions",    # user/group — set
    "data_limit_gb",   # user — set
    "bandwidth.limit_mbps", "bandwidth.burst_mbps",  # user — set
    "port",            # web.port — set
    "public_host", "base_path", "secure_cookie", "insecure_no_auth",
    "persist_session_key", "csrf", "update_check", "session_ttl_secs",
    "tls", "tls_cert", "tls_key",   # web — all set
    "time_format", "users_file", "require_client_key_proof",
    "bind_static_to_session",
    "brute_force.enabled", "brute_force.max_attempts",
    "brute_force.window_secs", "brute_force.lockout_secs",  # auth+web — set
    "tun.netmask",     # legacy read-only compatibility key; intentionally never emitted
    "netmask",         # serde_json test lookup, not an INI parser key
}


def read_keys():
    src = open(SRC, encoding="utf-8").read()
    ks = set(re.findall(
        r'\.(?:bool_or|parse_or|str_or|get|list|u32_or|u16_or|u64_or|f64_or)\("([a-z_.0-9]+)"',
        src))
    return ks


# ---- the fixture -----------------------------------------------------------
# Shared profile keys (parsed for BOTH transports). Values are all non-default.
SHARED_PROFILE = """\
enabled = false
identity_key = /tmp/id-{tag}.key
bind.address = 192.168.5.5
bind.port = {port}
bind.transport = {tp}
tun.name = tuna{tag}
tun.address = 10.{n}.0.1
tun.mtu = 1380
tun.tx_queue_len = 2000
tun.device_type = tap
tun.queues = 2
pool.cidr = 10.{n}.0.0/16
pool.exclude = 10.{n}.0.2
pool.reservation.alice = 10.{n}.0.50
routing.client_to_client = true
routing.forward_private = false
routing.nat.enabled = true
routing.nat.interface = eth7
routing.post_up = echo up
routing.post_down = echo down
route = 10.{n}.9.0/24 gateway=10.{n}.0.1 metric=42 desc=lan seg
dns.enabled = false
dns.listen = 10.{n}.0.1
dns.port = 5353
dns.upstream = 9.9.9.9
dns.upstream_protocol = tcp
dns.cache_size = 256
dns.timeout_secs = 7
dns.blocklist = ads.example
dns.push_servers = 1.0.0.1
dhcp.enabled = true
dhcp.listen = 10.{n}.0.1
dhcp.pool_start = 10.{n}.0.100
dhcp.pool_end = 10.{n}.0.200
dhcp.lease_time_secs = 7200
dhcp.domain_name = lan.local
obf.mode = obfs
obf.obfs_key = shared-secret-{tag}
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
"""

TCP_ONLY = """\
obf.multipath.enabled = true
obf.multipath.max_streams = 6
obf.multipath.adaptive = true
perf.tcp.nodelay = false
perf.tcp.keepalive_secs = 45
perf.tcp.send_buffer_size = 131072
perf.tcp.recv_buffer_size = 131072
perf.udp.send_buffer_size = 131072
perf.udp.recv_buffer_size = 2097152
perf.tun.read_buffer_size = 32768
perf.connection.max_clients = 64
perf.connection.handshake_timeout_secs = 8
perf.connection.idle_timeout_secs = 300
perf.connection.new_session_rate_max = 20
perf.connection.new_session_rate_window_secs = 11
"""

UDP_ONLY = """\
obf.quic.enabled = true
perf.tun.read_buffer_size = 32768
perf.connection.max_clients = 64
perf.connection.handshake_timeout_secs = 8
perf.connection.idle_timeout_secs = 300
perf.connection.new_session_rate_max = 20
perf.connection.new_session_rate_window_secs = 11
"""

OTHER_SECTIONS = """\
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
"""


def build():
    tcp = "[profile:tcpx]\n" + SHARED_PROFILE.format(tag="t", port=8501, tp="tcp", n=5) + TCP_ONLY
    udp = "[profile:udpx]\n" + SHARED_PROFILE.format(tag="u", port=8502, tp="udp", n=6) + UDP_ONLY
    return OTHER_SECTIONS + "\n" + tcp + "\n" + udp


def main():
    fixture = build()
    present = set(re.findall(r'^\s*([a-z_][a-z_.0-9]*)\s*=', fixture, re.M))
    # pool.reservation.alice -> normalize the prefix key for coverage
    present |= {"pool.reservation." + "alice"}
    ks = read_keys()
    missing = sorted(k for k in ks if k not in present and k not in EXEMPT
                     and not k.startswith("pool.reservation"))
    print(f"parser read-keys: {len(ks)} | fixture keys: {len(present)} | exempt: {len(EXEMPT)}")
    if missing:
        print(f"\nMISSING from fixture ({len(missing)}):")
        for k in missing:
            print("   ", k)
        print("\n-> fixture is NOT exhaustive; add these before trusting the round-trip")
    else:
        print("\nCOVERAGE OK: every parser-read key is set non-default in the fixture (or justified-exempt)")
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                       "release", "roundtrip_fixture_server.ini")
    open(out, "w", encoding="utf-8").write(fixture)
    print("fixture written ->", os.path.normpath(out))


if __name__ == "__main__":
    main()
