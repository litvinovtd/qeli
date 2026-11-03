#!/usr/bin/env python3
"""Instrument a private native client copy, never the production source tree.

The native CLI performs its own wrapper, crypto, proof and AUTH parsing. The
prepared-peer barrier excludes process startup, key generation and TCP outer
transport establishment. Successful peers park before NetworkPlan application.
"""
from benchmark_auth import admit_burst


def validate_instrumented_peer(path):
    """Refuse a stock/stale peer before the benchmark creates any fixtures.

    This marker is only an early artifact sanity check. Successful measurements
    still require each real peer's barrier, proof, AUTH result and registry entry.
    """
    marker = b'QELI_AUTH_BARRIER'
    overlap = b''
    with open(path, 'rb') as source:
        while chunk := source.read(1024 * 1024):
            data = overlap + chunk
            if marker in data:
                return
            overlap = data[-(len(marker) - 1):]
    raise ValueError('native AUTH peer lacks instrumentation marker; rebuild the instrumented library')


def validate_control_path(root):
    # sockaddr_un.sun_path is 108 bytes on this Linux fixture, including NUL.
    if len(str(root / 'control.sock').encode('utf-8')) >= 108:
        raise ValueError('native AUTH fixture control socket path exceeds Linux SUN_LEN')


HELPERS = r'''
// Private benchmark instrumentation; absent from the production binary.
pub(crate) fn audit_auth_clock() -> anyhow::Result<u64> {
    let mut stamp = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    anyhow::ensure!(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut stamp) } == 0,
        "benchmark monotonic clock unavailable");
    Ok(u64::try_from(stamp.tv_sec)? * 1_000_000_000 + u64::try_from(stamp.tv_nsec)?)
}
pub(crate) async fn audit_auth_barrier(stage: &str) -> anyhow::Result<()> {
    let root = std::path::PathBuf::from(std::env::var("QELI_AUTH_BARRIER")?);
    if stage == "go" {
        std::fs::write(root.join(format!("ready-{}", std::process::id())), b"ready")?;
    }
    let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !root.join(stage).exists() {
        anyhow::ensure!(std::time::Instant::now() < until, "benchmark barrier timeout");
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    Ok(())
}
pub(crate) async fn audit_auth_finish(
    transport: &str, inner_handshake: &str, hello_started_ns: u64,
    proof_verified_ns: u64, auth_started_ns: u64,
) -> anyhow::Result<()> {
    let auth_verified_ns = audit_auth_clock()?;
    let root = std::path::PathBuf::from(std::env::var("QELI_AUTH_BARRIER")?);
    let row = serde_json::json!({"case":"valid", "transport":transport,
        "mode":std::env::var("QELI_AUTH_MODE")?, "inner_handshake":inner_handshake,
        "pid":std::process::id(), "accepted":true, "server_proof_verified":true,
        "response":"OK", "hello_started_ns":hello_started_ns,
        "proof_verified_ns":proof_verified_ns, "auth_started_ns":auth_started_ns,
        "auth_verified_ns":auth_verified_ns});
    let temporary = root.join(format!("result-{}.tmp", std::process::id()));
    let mut bytes = serde_json::to_vec(&row)?; bytes.push(b'\n');
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(temporary, root.join(format!("result-{}.json", std::process::id())))?;
    audit_auth_barrier("release").await?;
    // Deliberate lab-only exit before any client NetworkPlan/TUN/data-plane setup.
    // OS closes descriptors; the namespace runner observes all admitted peers first.
    std::process::exit(0);
}
'''


def replace_exact(source, old, new, count=1):
    if source.count(old) != count:
        raise ValueError('native AUTH source drift at: ' + old)
    return source.replace(old, new)


def instrument_sources(session, client):
    """Fail closed on boundary drift, including a second instrumentation attempt."""
    if 'audit_auth_' in session or 'audit_auth_' in client:
        raise ValueError('source already instrumented')
    session = replace_exact(session, 'use crate::config::PushedObf;', HELPERS + '\nuse crate::config::PushedObf;')
    session = replace_exact(session,
        '    if matches!(config.obfuscation.mode.as_str(), "plain" | "reality-tls") {\n        stream',
        '    if matches!(config.obfuscation.mode.as_str(), "plain" | "reality-tls") {\n'
        '        audit_auth_barrier("go").await?;\n        let hello_started_ns = audit_auth_clock()?;\n        stream')
    session = replace_exact(session, '    stream.write_all_flush(&client_hello).await?;',
        '    audit_auth_barrier("go").await?;\n    let hello_started_ns = audit_auth_clock()?;\n'
        '    stream.write_all_flush(&client_hello).await?;')
    session = replace_exact(session, 'verify_key(server_static).await?;',
        'verify_key(server_static).await?;\n        let proof_verified_ns = audit_auth_clock()?;', 2)
    session = replace_exact(session, 'stream.write_all_flush(&auth_packet).await?;',
        'let auth_started_ns = audit_auth_clock()?;\n        stream.write_all_flush(&auth_packet).await?;', 2)
    session = replace_exact(session,
        'let auth = parse_auth_ok(&String::from_utf8(auth_response)?)?;\n        log::info!("Auth OK (raw inner)',
        'let auth = parse_auth_ok(&String::from_utf8(auth_response)?)?;\n'
        '        audit_auth_finish("tcp", "raw_x25519", hello_started_ns, proof_verified_ns, auth_started_ns).await?;\n'
        '        log::info!("Auth OK (raw inner)')
    session = replace_exact(session,
        'let auth = parse_auth_ok(&String::from_utf8(auth_response)?)?;\n    log::info!("Auth OK,',
        'let auth = parse_auth_ok(&String::from_utf8(auth_response)?)?;\n'
        '    audit_auth_finish("tcp", "hybrid_mlkem_x25519", hello_started_ns, proof_verified_ns, auth_started_ns).await?;\n'
        '    log::info!("Auth OK,')
    prefix = 'crate::transport_core::session::audit_auth_'
    client = replace_exact(client, '    let n_frags = ch_frags.len();',
        '    let n_frags = ch_frags.len();\n    ' + prefix + 'barrier("go").await?;\n'
        '    let hello_started_ns = ' + prefix + 'clock()?;')
    client = replace_exact(client,
        '    identity_verifier(server_static_pub_bytes).await?;\n\n    log::info!("UDP: Server identity verified");',
        '    identity_verifier(server_static_pub_bytes).await?;\n    let proof_verified_ns = ' + prefix + 'clock()?;\n'
        '    log::info!("UDP: Server identity verified");')
    client = replace_exact(client, "    let auth_response = 'auth: loop {",
        '    let auth_started_ns = ' + prefix + 'clock()?;\n' + "    let auth_response = 'auth: loop {")
    client = replace_exact(client, '    log::info!("UDP: Auth OK, assigned IP: {}", client_ip);',
        '    ' + prefix + 'finish(\n'
        '        if quic_enabled { "quic" } else { "udp" }, "hybrid_mlkem_x25519",\n'
        '        hello_started_ns, proof_verified_ns, auth_started_ns,\n    ).await?;\n'
        '    log::info!("UDP: Auth OK, assigned IP: {}", client_ip);')
    return session, client


def admit_native_burst(rows, mode, concurrency, pids):
    transport = 'quic' if mode.get('quic') else mode['transport']
    handshake = 'raw_x25519' if mode['client_mode'] in ('plain', 'reality-tls') else 'hybrid_mlkem_x25519'
    if len(set(pids)) != concurrency or any(type(pid) is not int or pid <= 0 for pid in pids):
        raise ValueError('invalid offered native peer PIDs')
    if (any(type(row.get('pid')) is not int for row in rows)
            or {row.get('pid') for row in rows} != set(pids) or len(rows) != concurrency):
        raise ValueError('native peer identity mismatch')
    if any(row.get('mode') != mode['name'] or row.get('inner_handshake') != handshake for row in rows):
        raise ValueError('native mode/handshake mismatch')
    return admit_burst(rows, transport, concurrency)
