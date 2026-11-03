# Q34: complete CI fuzz target inventory

<!-- normative-sync: q34-fuzz-inventory-v1 -->

Date: 9 October 2026.

## F484 / Q34-F038

The Cargo fuzz manifest registers15 binaries, but both manual CI lists run11.
control_v2,quic_envelope,realtls_client,websocket_frame are omitted. A general
fuzz build may compile these targets but does not run their30/600-second jobs.
The exact old smoke shell with controlled cargo returned0 with only11calls.

scripts/fuzz_targets.py reads registered bins and requires cargo-fuzz metadata,
nonempty targets,safe unique names,existing source paths within the package and
the256matrix limit. Invalid TOML/missing/external sources refuse before output.
Sorted stdout and GitHub JSON output carry the same inventory;this is CI metadata,
not a Qeli configuration format. Smoke uses checked command substitution instead
of process substitution,so inventory failure cannot silently become an empty loop.
Nightly takes a dynamic matrix from a dedicated needs/output job. Its schedule/
workflow_dispatch boundary,corpus cache keys and crash artifacts are retained.
Regression tests run in the normal native-libs job. Newly registered targets enter
both consumers without editing a second list.

The dynamic matrix follows [GitHub documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations)
and the [matrix limit](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idstrategymatrix).
Local parsing is not hosted scheduler execution.

## Qualification and limits

69Windows methodsPASS:10inventory,38native recipes,21release tag/workflow. The same
10inventory methods repeated on Linux,no skips. The previous SHA-qualified private
PyYAML6.0.3 parses actual workflow fields/cwd/needs/outputs/if/matrix and extracts
the exact old/new commands.

10Linux shell scenarios pass:baseline11-target gap,all15calls,early cargo exit23
stops remaining calls,full nightly output,missing/malformed manifest with zero
cargo calls,preserved old output on malformed input,new16thtarget in smoke/matrix,
external source symlink refusal. Original Rust input bytes restored afterward.
Controlled cargo records arguments/status only;no new actual Rust/libFuzzer/ASan/
parser crash/corpus or30/600-second runtime qualification. Fuzz tool/nightly pins
and current hosted Actions remain OPEN.

Initial input preparation rc1 lacked global yaml;the previous SHA-qualified private
parser was reused without global installs and successful parsing repeated. This
harness diagnostic is retained separately. Full owned small lab fixture backup and
every member SHA verified locally,then /proc fd/cwd/exe/root and mount guards permit
exact own root/sibling removal. Original service active/PID777845/binarySHA retained;
lab .10 unused. Credential stdin only;raw/decoded archive scan PASS. Nativee3fb/14SHA/
protected inputs unchanged. qeli tree did not change;prior exact OpenWrt cut retains
its original applicability and scope.

Q34IN_PROGRESS30/37DONE81.1percent7remain;Q35TODO,not full fuzz/concurrency/DoS/soak
completion. Q29SIGKILLFAIL-ENONET/Q30/Q31/F459braces/D06accepted/USER_EXCLUDED retained.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-fuzz-inventory-20261009`: SEALED 108 files / 1459713 bytes; manifest SHA256 `c580a0c3430eb9828987e68c2a9f7e44c35391830e83c6a308371efff076e6f6`.
