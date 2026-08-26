# Qeli 0.8.0 — UDP adaptive-PMTU PACKET_MUX_V1 PCAP/DPI retest

Binary SHA-256: `2f69b48f102571518e2582de64a51d48442baf22b80b8f1586ba369d164d0b49`. All four UDP modes passed Auth OK, PACKET_MUX_V1 negotiation, and server recordizer PMTU adaptation.

The historical 22-feature Qeli shape classifier detected 0/4 new captures; nearest-centroid classification also detected 0/4. These are regression scores, not real-world DPI detection probabilities.

| Mode | Old-model Qeli score | Entropy old → fixed | Unique sizes old → fixed |
|---|---:|---:|---:|
| udp-faketls | 0.0019 | 0.343 → 3.762 | 0.0114 → 0.0694 |
| udp-padding | 0.0023 | 2.482 → 3.733 | 0.2300 → 0.0792 |
| udp-quic | 0.0012 | 0.342 → 3.726 | 0.0116 → 0.0696 |
| udp-faketls-awg | 0.0021 | 0.343 → 3.777 | 0.0116 → 0.0697 |

## Interpretation

The frozen 548-byte server recordizer ceiling is gone. Both directions now use the certified path budget, removing the strong 548/1450 bimodal asymmetry that the old classifier recognised in all four UDP modes.

This does not make every UDP carrier equivalent to genuine QUIC/HTTP/3. Fake-TLS and AWG remain non-standard UDP carriers, while quic-shape is not a complete QUIC/H3 state machine. A classifier miss means only that the historical Qeli-specific size/timing model did not recognise these samples; it does not imply zero detection probability.
