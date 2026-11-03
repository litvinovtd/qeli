# Q36-F018: UDP shutdown and retained task failures

<!-- normative-sync: q36-udp-shutdown-v2 -->

Development performance measurements for unreleased 0.8.2 have been withdrawn from publication. Complete original data and reports are retained locally for internal audit. They are not a public release benchmark or a basis for comparing version performance.

Normal cancellation of the UDP receive pump no longer treats channel closure as an unexpected failure. The supervisor distinguishes owner shutdown from worker loss and retains completed errors and panics from other tasks. Unexpected completion in a live profile remains an error. INI, ABI and the wire format are unchanged.

This describes a functional fix, not an AUTH-rate or throughput measurement.
