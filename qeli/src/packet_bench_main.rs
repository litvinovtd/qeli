//! Stable release-mode PacketCodec benchmark used by CI and lab comparisons.
//!
//! This deliberately avoids a benchmark-framework dependency: the executable is small,
//! cross-platform, and can be run by the exact Rust toolchain used for a release. CI uses a
//! deliberately conservative floor to catch catastrophic regressions; the printed throughput
//! remains available for trend analysis and lab work.

use qeli::protocol::packet::PacketCodec;
use qeli_core as qeli;
use std::hint::black_box;
use std::time::Instant;

const PAYLOAD_BYTES: usize = 1400;
const WARMUP_ITERATIONS: usize = 2_000;
const DEFAULT_ITERATIONS: usize = 50_000;
const CI_MIN_MIB_PER_SECOND: f64 = 50.0;

struct Options {
    ci: bool,
    iterations: usize,
}

fn options() -> Result<Options, String> {
    let mut ci = false;
    let mut iterations = std::env::var("QELI_PACKET_BENCH_ITERS")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| "QELI_PACKET_BENCH_ITERS must be a positive integer")?
        .unwrap_or(DEFAULT_ITERATIONS);
    for argument in std::env::args().skip(1) {
        if argument == "--ci" {
            ci = true;
        } else if let Some(value) = argument.strip_prefix("--iterations=") {
            iterations = value
                .parse()
                .map_err(|_| "--iterations must be a positive integer")?;
        } else {
            return Err(format!("unknown argument: {argument}"));
        }
    }
    if iterations == 0 {
        return Err("iteration count must be greater than zero".into());
    }
    Ok(Options { ci, iterations })
}

fn run_roundtrips(
    encryptor: &mut PacketCodec,
    decryptor: &mut PacketCodec,
    payload: &[u8],
    record: &mut Vec<u8>,
    iterations: usize,
) -> Result<u64, String> {
    let mut checksum = 0u64;
    for iteration in 0..iterations {
        encryptor
            .encrypt_packet_into(black_box(payload), &[], record)
            .map_err(|error| format!("encrypt failed: {error}"))?;
        decryptor
            .decrypt_packet_in_place(record)
            .map_err(|error| format!("decrypt failed: {error}"))?;
        if record.as_slice() != payload {
            return Err(format!("round-trip mismatch at iteration {iteration}"));
        }
        checksum = checksum.wrapping_add(record[iteration % record.len()] as u64);
    }
    Ok(black_box(checksum))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("packet-codec-bench: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = options()?;
    let key = [0x42; 32];
    let payload = [0xA5; PAYLOAD_BYTES];
    let mut encryptor = PacketCodec::new(key);
    let mut decryptor = PacketCodec::new(key);
    let mut record = Vec::with_capacity(2048);

    run_roundtrips(
        &mut encryptor,
        &mut decryptor,
        &payload,
        &mut record,
        WARMUP_ITERATIONS,
    )?;
    let warmed_capacity = record.capacity();
    let started = Instant::now();
    let checksum = run_roundtrips(
        &mut encryptor,
        &mut decryptor,
        &payload,
        &mut record,
        options.iterations,
    )?;
    let elapsed = started.elapsed();
    if record.capacity() != warmed_capacity {
        return Err(format!(
            "caller-owned record buffer grew after warm-up: {warmed_capacity} -> {}",
            record.capacity()
        ));
    }

    let mib = (options.iterations * PAYLOAD_BYTES) as f64 / (1024.0 * 1024.0);
    let mib_per_second = mib / elapsed.as_secs_f64();
    println!(
        "{{\"implementation\":\"rust\",\"payload_bytes\":{PAYLOAD_BYTES},\"iterations\":{},\"elapsed_ms\":{:.3},\"mib_per_second\":{:.3},\"record_capacity\":{},\"checksum\":{checksum}}}",
        options.iterations,
        elapsed.as_secs_f64() * 1000.0,
        mib_per_second,
        record.capacity()
    );
    if options.ci && mib_per_second < CI_MIN_MIB_PER_SECOND {
        return Err(format!(
            "throughput {mib_per_second:.3} MiB/s is below the conservative CI floor {CI_MIN_MIB_PER_SECOND:.1} MiB/s"
        ));
    }
    Ok(())
}
