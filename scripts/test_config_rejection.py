#!/usr/bin/env python3
"""L2 -- value-domain rejection: for every config key with a constrained value
(CIDR / IP / port / enum / range), feed a junk value and assert
`qeli check-config` refuses it (non-zero exit). Complements L1 (which proves a
VALID value is read+persisted) by proving an INVALID one cannot slip through.

Each case config is built ENTIRELY in Python (no sed) and uploaded via sftp, so
there is zero ambiguity about what reached the parser -- an earlier sed-based
version produced inconsistent rows. Every row records check-config's verdict AND
the real server's startup, so a check-config miss that the server also swallows
(silent) or crash-loops on (the pool.cidr=/33 class) is surfaced.
"""
import os, sys, io, json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab_hygiene as hy
from lab_common import connect, run, LAB_SRV

BIN = "/opt/qeli-src/target/release/qeli"
HASH = "$argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w"


def cfg(profile_extra="", user_extra="", **over):
    """Build a full, valid-by-default server config; `over` replaces one field."""
    d = dict(bind_port="8443", bind_transport="tcp", tun_address="10.9.0.1",
             tun_mtu="1400", pool_cidr="10.9.0.0/24",
             pool_exclude="10.9.0.1", obf_mode="fake-tls")
    d.update(over)
    return f"""[auth]
require_client_key_proof = false

[logging]
level = info
file = /tmp/rej.log

[profile:p]
identity_key = /tmp/rej/id.key
bind.address = 0.0.0.0
bind.port = {d['bind_port']}
bind.transport = {d['bind_transport']}
tun.name = rej0
tun.address = {d['tun_address']}
tun.mtu = {d['tun_mtu']}
pool.cidr = {d['pool_cidr']}
pool.exclude = {d['pool_exclude']}
obf.mode = {d['obf_mode']}
{profile_extra}

[user:u]
password_hash = {HASH}
enabled = true
{user_extra}
"""


# (label, config text, expect_reject_is_correct)
CASES = [
    ("pool.cidr /33",        cfg(pool_cidr="10.9.0.0/33")),
    ("pool.cidr garbage",    cfg(pool_cidr="not-a-cidr")),
    ("tun.address bad oct",  cfg(tun_address="300.1.1.1")),
    ("tun.address garbage",  cfg(tun_address="hello")),
    ("tun.address outside pool", cfg(tun_address="10.10.0.1")),
    ("bind.port 0",          cfg(bind_port="0")),
    ("bind.port >65535",     cfg(bind_port="99999")),
    ("bind.transport enum",  cfg(bind_transport="ftp")),
    ("obf.mode enum",        cfg(obf_mode="teleport")),
    ("tun.mtu absurd",       cfg(tun_mtu="999999")),
    ("tun.mtu tiny",         cfg(tun_mtu="10")),
    ("pool.exclude outside", cfg(pool_exclude="10.99.0.1")),
    ("pool.exclude bad ip",  cfg(pool_exclude="10.9.0.999")),
    ("reality target_port",  cfg(profile_extra="obf.tls.reality_proxy.target_port = 99999")),
    ("dns.upstream bad ip",  cfg(profile_extra="dns.enabled = true\ndns.upstream = 10.0.0.999")),
    ("route bad cidr",       cfg(profile_extra="route = 10.0.0.0/99")),
    ("dhcp.pool_start bad",  cfg(profile_extra="dhcp.enabled = true\ndhcp.pool_start = 10.9.0.999\ndhcp.pool_end = 10.9.0.200")),
    ("user allowed_networks",cfg(user_extra="allowed_networks = 10.0.0.0/33")),
]

# What check-config SHOULD do per case. Anything the server would crash-loop on
# MUST be a hard reject; values it tolerates (warn + ignore, or a genuinely valid
# edge) must NOT be rejected. tun.mtu bounds and dhcp.pool_start IP validity are
# the two gaps this round's fix (validate_profiles) closes.
EXPECT_REJECT = {
    "pool.cidr /33": True, "pool.cidr garbage": True,
    "tun.address bad oct": True, "tun.address garbage": True,
    "tun.address outside pool": True,
    "bind.port 0": False,           # port 0 = OS-assigned ephemeral, accepted
    "bind.port >65535": True, "bind.transport enum": True, "obf.mode enum": True,
    "tun.mtu absurd": True, "tun.mtu tiny": True,          # FIX: mtu bounds
    "pool.exclude outside": False,  # excluding an IP outside the pool is a no-op
    "pool.exclude bad ip": False,   # warned + ignored by IpPool::new (not fatal)
    "reality target_port": True,
    "dns.upstream bad ip": False,   # warned at load now, skipped per-query (not fatal)
    "route bad cidr": False,        # dropped + warned by parse_route_checked
    "dhcp.pool_start bad": True,    # FIX: dhcp pool IP validity
    "user allowed_networks": False, # invalid entry skipped + warned by the ACL at runtime
}


def put(s, path, text):
    sf = s.open_sftp(); sf.putfo(io.BytesIO(text.encode()), path); sf.close()


def main():
    s = connect(LAB_SRV)
    run(s, "mkdir -p /tmp/rej; systemctl stop qeli-server.service 2>/dev/null; pkill -9 -x qeli; sleep 1; true")
    ver = run(s, f"{BIN} --version 2>&1 | tail -1").strip().splitlines()[-1]
    print("binary:", ver)
    put(s, "/tmp/rej/base.conf", cfg())
    rc0 = run(s, f"{BIN} check-config -c /tmp/rej/base.conf >/dev/null 2>&1; echo $?").strip().splitlines()[-1]
    print(f"base config valid: check-config rc={rc0} (expect 0)\n")

    rows = []
    print(f"{'case':<24}{'check-config':<13}{'server':<14}verdict")
    print("-" * 72)
    for label, text in CASES:
        put(s, "/tmp/rej/t.conf", text)
        cc = run(s, f"{BIN} check-config -c /tmp/rej/t.conf >/dev/null 2>&1; echo $?").strip().splitlines()[-1]
        cc_reject = cc != "0"
        run(s, "pkill -9 -x qeli 2>/dev/null; sleep 1; ip link del rej0 2>/dev/null; rm -f /tmp/rej.log; true")
        run(s, f"setsid {BIN} server --config /tmp/rej/t.conf >/dev/null 2>&1 </dev/null & sleep 4")
        respawn = run(s, "grep -ac 'respawning' /tmp/rej.log 2>/dev/null || echo 0").strip().splitlines()[-1]
        proferr = run(s, "grep -ac \"Profile 'p' error\" /tmp/rej.log 2>/dev/null || echo 0").strip().splitlines()[-1]
        run(s, "pkill -9 -x qeli 2>/dev/null; sleep 1; ip link del rej0 2>/dev/null; true")
        srv_reject = respawn != "0" or proferr != "0"
        expect = EXPECT_REJECT.get(label, True)
        # PASS = check-config matches the expectation, AND anything it lets through
        # must not crash the server (no residual GAP).
        ok = (cc_reject == expect) and not (not cc_reject and srv_reject)
        verdict = "PASS" if ok else ("GAP (cc ok, srv crashes)" if srv_reject else "MISMATCH")
        print(f"{label:<24}{('REJECT' if cc_reject else 'pass'):<13}"
              f"{('crash' if srv_reject else 'runs'):<14}{verdict}")
        rows.append({"case": label, "cc_rejects": cc_reject, "srv_crashes": srv_reject,
                     "expect_reject": expect, "pass": ok})

    run(s, "systemctl start qeli-server.service 2>/dev/null; true")
    s.close()
    gaps = [r["case"] for r in rows if r["srv_crashes"] and not r["cc_rejects"]]
    fails = [r["case"] for r in rows if not r["pass"]]
    npass = sum(1 for r in rows if r["pass"])
    print(f"\n{npass}/{len(rows)} cases PASS (check-config matches expectation, no residual gap)")
    print(f"remaining GAP (cc passes but server crash-loops): {gaps or 'none'}")
    if fails:
        print(f"FAILURES: {fails}")
    _out = hy.versioned_result_path(ver, "config_rejection")
    open(_out, "w", encoding="utf-8").write(json.dumps(rows, indent=2, ensure_ascii=False))
    print("saved ->", _out)


if __name__ == "__main__":
    main()
