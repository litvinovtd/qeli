# Lab benchmark: dev `cf22e9d4` vs qeli 0.7.14

Date: 2026-08-12

## Provenance and hygiene

- Source: local `dev`, commit `cf22e9d416523d2c40fd3a1476c7a50efa26d776`.
  After the later `dev` rebase, the same measured qeli source is represented by
  `962c000`; subsequent changes before release affected web assets only.
- Binary: `qeli 0.7.15`, SHA-256
  `ef4f7b54a22c3719a6db72f73d05ba39c0038783eda7a1e8a185f06603efaf66`.
- Build: `cargo build --release --features jemalloc`; 604 tests passed.
- Both VMs were rebooted. Before measurements: 0% steal, no Android/QEMU emulator,
  no qeli/iperf3/java/gradle processes, no netem/shaping qdisc, and no VPN interfaces.
- The subsequent source-only `#[cfg(test)]` fix for `MARKER` does not change the
  non-test binary measured here. Clippy with jemalloc passes after that fix.

Raw data:

- `stability_baseline_v0.7.15_dev_2026-08-12.json`
- `benchmark_v0.7.15_2026-08-12_run2.json`
- `udp_quic_100_1000_v0.7.15_dev_2026-08-12.json`
- `benchmark_v0.7.14_2026-08-12.json`
- `benchmark_v0.7.14_2026-08-12_run2.json`
- `reality_tls_5x_v0.7.14_2026-08-12.json`

## Direct no-VPN stability samples

- Upload: 15,212.8–19,379.0 Mbps; difference 4,166.2 Mbps (27.4% of minimum).
- Download: 16,660.2–22,173.4 Mbps; difference 5,513.2 Mbps (33.1% of minimum).
- The full-sweep single baseline was 19,614.7 Mbps. The two 0.7.14 full-sweep
  baselines were 19,335.6 and 20,026.2 Mbps.

No pass/fail threshold is applied; the observed difference is reported as requested.

## TCP throughput

0.7.14 is shown as the range of its two complete sweeps. Delta is the current dev
value relative to the midpoint of those two values.

| Mode | 0.7.14 up | Dev up | Delta | 0.7.14 down | Dev down | Delta |
|---|---:|---:|---:|---:|---:|---:|
| plain | 519.7–529.8 | 517.6 | −1.4% | 743.2–753.9 | 711.5 | −4.9% |
| fake-tls | 519.5–528.2 | 500.5 | −4.5% | 730.9–760.9 | 718.1 | −3.7% |
| padding | 503.5–527.3 | 493.0 | −4.3% | 692.4–724.4 | 706.7 | −0.2% |
| frag | 445.6–548.0 | 550.0 | +10.7% | 717.8–745.1 | 702.6 | −3.9% |
| obfs | 583.2–594.3 | 582.2 | −1.1% | 654.3–679.9 | 620.5 | −7.0% |
| reality | 514.9–539.2 | 483.5 | −8.3% | 732.2–737.8 | 705.4 | −4.0% |
| reality-tls | 477.9–571.2 | 540.3 | +3.0% | 377.5–379.2 | 365.1 | −3.5% |
| obfs + AWG | 547.5–572.9 | 576.0 | +2.8% | 639.1–683.9 | 633.4 | −4.2% |

All TCP modes connected, ping loss was 0%, and current server session drops were zero.
The earlier same-host interleaved A/B in `ab_memset_fix.json` put the fixed data path
within −1.3%, −3.7%, and −2.6% of 0.7.14 for plain, fake-tls, and obfs download.

## UDP loss

| Mode | 0.7.14 @400M | Dev @400M | 0.7.14 @500M | Dev @500M |
|---|---:|---:|---:|---:|
| fake-tls | 0.02–0.13% | 0% | 1.28–10.19% | 4.43% |
| padding | 0–0.04% | 0% | 0.89–1.62% | **14.07%** |
| QUIC | 0.12–0.21% | 0% | 0.35–2.72% | 0% |
| fake-tls + AWG | 0–0.10% | 0% | 4.13–11.38% | 0.07% |

The current run was lossless through 400 Mbps in every UDP mode. At the 500 Mbps
saturation step, padding is the sole adverse outlier: 14.07% loss, with 1,016 qeli
session drops and zero kernel receive-buffer drops.

## CPU and memory

- Current maximum sampled qeli CPU: 76.3%; 0.7.14 maximum: 72.2–73.4%.
- Current TCP worker RSS range: 74.8–101.4 MB; 0.7.14: 44.4–47.4 MB.

The RSS increase is reproducible across the current sweep and should be treated as a
real version-level difference until its allocation source is measured; the benchmark
alone does not establish whether it is retained capacity or a leak.

## Earlier results

The two 0.7.13 sweeps are not used as the primary baseline: their direct no-VPN
baselines diverged from 18.574 to 13.996 Gbps, and the prior run was already rejected
as host-contended. The 0.7.12 files also contain strongly inconsistent per-mode and UDP
results. The documented clean 0.7.4/0.7.7 and host-neutral 0.7.11 results remain useful
historical context; the current TCP values are generally in their established range,
except for the explicitly listed reality upload and RSS differences above.
