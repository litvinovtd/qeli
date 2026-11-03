#!/usr/bin/env python3
"""Instrument the existing contract peer and admit bounded AUTH burst evidence.

The generated peer links Qeli's real crypto/protocol library. No client parser,
key schedule or authentication implementation is copied into this harness.
"""
import math


TIMING = r'''
fn monotonic_ns() -> Result<u64> {
    let mut stamp = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    ensure!(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut stamp) } == 0,
        "monotonic clock unavailable");
    Ok(u64::try_from(stamp.tv_sec)? * 1_000_000_000 + u64::try_from(stamp.tv_nsec)?)
}
fn barrier(stage: &str) -> Result<()> {
    let root = std::path::PathBuf::from(std::env::var("QELI_AUTH_BARRIER")?);
    if stage == "go" {
        std::fs::write(root.join(format!("ready-{}", std::process::id())), b"ready")?;
    }
    let until = std::time::Instant::now() + Duration::from_secs(20);
    while !root.join(stage).exists() {
        ensure!(std::time::Instant::now() < until, "benchmark barrier timeout");
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}
'''


def instrument_peer(source):
    """Fail on source drift; keep the existing negative-contract peer unchanged."""
    changes = [
        ('fn main() -> Result<()> {', TIMING + '\nfn main() -> Result<()> {'),
        ('    wire.send(&hello, true)?;',
         '    barrier("go")?;\n    let hello_started_ns = monotonic_ns()?;\n    wire.send(&hello, true)?;'),
        ('    let mut auth =', '    let proof_verified_ns = monotonic_ns()?;\n    let mut auth ='),
        ('    wire.send(&tx.encrypt_packet(&auth, &[])?, false)?;',
         '    let auth_started_ns = monotonic_ns()?;\n    wire.send(&tx.encrypt_packet(&auth, &[])?, false)?;'),
        ('    if case == "legacy" || case == "valid" {',
         '    let auth_verified_ns = monotonic_ns()?;\n    if case == "legacy" || case == "valid" {'),
        ('{"case":case,"transport":args[1],',
         '{"hello_started_ns":hello_started_ns,"proof_verified_ns":proof_verified_ns,"auth_started_ns":auth_started_ns,"auth_verified_ns":auth_verified_ns,"case":case,"transport":args[1],'),
    ]
    # Only main's final return is changed, after the original JSON output.
    for old, new in changes:
        if source.count(old) != 1:
            raise ValueError('contract peer changed at instrumentation boundary: ' + old)
        source = source.replace(old, new)
    end = '    Ok(())\n}\n'
    if not source.endswith(end):
        raise ValueError('contract peer final return changed')
    return source[:-len(end)] + '    std::io::stdout().flush()?;\n    barrier("release")?;\n' + end


def admit_burst(rows, transport, concurrency):
    """All requested peers must verify proof and AUTH; no failure filtering.

    Rates describe a finite synchronized offered burst, not sustained server
    capacity. CLOCK_MONOTONIC is shared by processes on this one Linux host.
    """
    if transport not in ('tcp', 'udp', 'quic') or type(concurrency) is not int or concurrency < 1:
        raise ValueError('invalid burst condition')
    if len(rows) != concurrency:
        raise ValueError('incomplete offered burst')
    clocks = ('hello_started_ns', 'proof_verified_ns', 'auth_started_ns', 'auth_verified_ns')
    for row in rows:
        if row.get('case') != 'valid' or row.get('transport') != transport:
            raise ValueError('wrong peer condition')
        if row.get('accepted') is not True or row.get('server_proof_verified') is not True or row.get('response') != 'OK':
            raise ValueError('proof or AUTH refused')
        values = [row.get(key) for key in clocks]
        if any(type(value) is not int or value <= 0 for value in values) or values != sorted(values) or values[-1] <= values[0]:
            raise ValueError('invalid monotonic timing')
        if values[-1] == values[-2] or values[1] == values[0]:
            raise ValueError('empty timing phase')
    first = min(row['hello_started_ns'] for row in rows)
    last = max(row['auth_verified_ns'] for row in rows)
    span = (last - first) / 1e9
    auth = [(row['auth_verified_ns'] - row['auth_started_ns']) / 1e6 for row in rows]
    handshake = [(row['auth_verified_ns'] - row['hello_started_ns']) / 1e6 for row in rows]
    proof = [(row['proof_verified_ns'] - row['hello_started_ns']) / 1e6 for row in rows]
    def percentile(values, fraction):
        return sorted(values)[math.ceil(len(values) * fraction) - 1]
    return dict(offered=concurrency, accepted=concurrency, burst_seconds=span,
        burst_admissions_per_second=concurrency / span,
        release_start_spread_ms=(max(row['hello_started_ns'] for row in rows) - first) / 1e6,
        auth_ms=auth, handshake_ms=handshake, proof_ms=proof,
        auth_p50_ms=percentile(auth, .5), auth_p95_ms=percentile(auth, .95), auth_max_ms=max(auth),
        handshake_p50_ms=percentile(handshake, .5), handshake_p95_ms=percentile(handshake, .95), handshake_max_ms=max(handshake))
