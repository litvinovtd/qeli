# Short-test pilot — publication status

The 16 October 2026 development pilot is not a release benchmark or an accepted
regression reference. Its status is `PILOT_REVIEW_REQUIRED`: UDP load and
repeatability findings require investigation. It does not qualify the current
release binary, which must be tested separately after rebuilding.

Complete original reports, JSON receipts, configuration and raw measurements are
retained locally for audit. Withdrawn development measurements are not republished
here or in the release notes, and no performance claim is inferred from them.

The [short-test methodology](../manuals/RELEASE-SHORT-TEST.md) and its regression
tests are public. This suite supplements, rather than replaces, CI, native-core
qualification and mandatory release runtime checks. The published comparative
benchmark remains [qeli 0.8.0](benchmarks/vpn_protocol_benchmark_repeat_2026-09-01.md).
