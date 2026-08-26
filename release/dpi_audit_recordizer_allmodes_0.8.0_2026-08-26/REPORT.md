# Qeli 0.8.0 — all-mode PACKET_MUX_V1 PCAP/DPI test

Binary SHA-256: `c5bb4e0d8427ed2d0ee03e7925c2ecaa55f5063be5363a67bd2317e29413060a`. All 12 modes: AUTH OK and recordizer active.

The historical 22-feature Qeli shape classifier detected 4/12 new samples; nearest-centroid detected 4/12. These are regression scores, not industrial-DPI probabilities.

| Mode | old-model Qeli score | entropy old → new | unique sizes old → new |
|---|---:|---:|---:|
| tcp-plain-raw | 0.0000 | 0.327 → 1.265 | 0.0111 → 0.0405 |
| tcp-faketls | 0.0000 | 0.323 → 1.261 | 0.0108 → 0.0412 |
| tcp-padding | 0.0000 | 2.462 → 1.592 | 0.2318 → 0.0640 |
| tcp-frag | 0.0000 | 2.458 → 1.597 | 0.2300 → 0.0663 |
| tcp-obfs | 0.0000 | 2.506 → 1.616 | 0.2315 → 0.0658 |
| tcp-reality | 0.0000 | 0.331 → 1.281 | 0.0117 → 0.0420 |
| tcp-reality-tls | 0.0000 | 0.325 → 1.531 | 0.0111 → 0.0332 |
| udp-faketls | 0.9922 | 0.343 → 4.161 | 0.0114 → 0.0412 |
| udp-padding | 0.9945 | 2.482 → 3.994 | 0.2300 → 0.0458 |
| udp-quic | 0.9932 | 0.342 → 4.161 | 0.0116 → 0.0418 |
| tcp-obfs-awg | 0.0000 | 0.326 → 1.316 | 0.0148 → 0.0416 |
| udp-faketls-awg | 0.9932 | 0.343 → 4.121 | 0.0116 → 0.0416 |

## Interpretation

PACKET_MUX_V1 removes the shared one-inner-packet/one-Qeli-record load invariant in every carrier. It does not replace the visible carrier: plain remains opaque TCP, fake-TLS remains synthetic TLS-like traffic, obfs remains an opaque stream, UDP fake-TLS/AWG remains non-standard UDP, and quic-shape is not a real QUIC/H3 state machine. Reality-TLS with genuine H2 is still the strongest passive-camouflage profile.

A classifier miss here means that the old Qeli-specific size/timing model did not recognise this sample. It does not mean that the carrier is indistinguishable from the cover protocol or that detection probability is zero.
