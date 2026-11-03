# Q34: permanent GitHub Actions semantic gate

<!-- normative-sync: q34-workflow-lint-v1 -->

9 October 2026. F488 / Q34-F042 closed within workflow semantic validation.

## Problem and change

The previous F487 packet found invalid job-level `env` references that a YAML
parser did not detect. After their correction, all four workflows already passed
manual lint. The remaining coverage gap was that actionlint was absent from
regular CI. This is a control gap, not a new client parser defect.

CI now has a failing `workflow-lint` job. Shared `scripts/check_workflows.py`
selects every direct `.yml` and `.yaml` in `.github/workflows`, including newly
added files. Missing or empty inventory, nonregular files, lint failures and
timeouts refuse admission.

Official [actionlint 1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12)
archives and executable bytes have reviewed SHA256 pins for Linux x86_64 and
Windows AMD64. Installation uses only the caller's directory; an unknown existing
file is neither overwritten nor executed. CI uses `$RUNNER_TEMP/qeli-actionlint`.
There is no global installation or execution of workflow jobs by this validator.

From the repository root:

```sh
python scripts/check_workflows.py --install-dir /tmp/qeli-actionlint
```

Alternatively, `--actionlint` admits an existing official executable by the same
SHA check. External ShellCheck and pyflakes are explicitly disabled: this gate
covers Actions semantics, contexts and expressions. The separate existing
ShellCheck job retains its prior scope; comprehensive inline shell/Python checks
and branch protection settings are not qualified by this packet.

## Qualification

Windows and Linux each passed 11 admission/failure unit tests and eight actual
semantic scenarios. Pinned download/install and reuse, all four current workflows,
and five valid workflows pass. Invalid job-level `env`, a newly added invalid
`.yaml`, modified cached executable, empty inventory and missing inventory are
actually refused. Unit tests also cover archive corruption, extracted binary
mismatch, network refusal, timeout and temporary-file cleanup after failed atomic
installation. Synthetic unit executable bytes are never executed; the official
actionlint performs the semantic tests.

An owned temporary .11 fixture retained exact inputs and logs in a SHA-verified
archive. Archive members were checked before process/fd/mount-guarded removal
of the root and remote backup. Active service, original 777/845 PIDs and installed
Qeli SHA are unchanged; .10 unused. An initial local command with the wrong cwd
is retained separately; final qualification uses an explicit product root.

## Boundaries

Only CI, Python gate/tests and documentation changed. Core/native inputs are
unchanged; previous native qualification and all 14 SHA remain valid. The `qeli`
tree is unchanged too: the existing SDK cut 746e09 / 9b4b source gate is checked,
without claiming a new SDK build. Earlier ASan smoke is inherited, not repeated
or replaced by this report. Current hosted CI, signatures and publication remain
separate obligations.

Q34 IN_PROGRESS. Overall: 30/37 DONE (81.1%), 7 sections remain. Q35 TODO;
Q29 SIGKILL FAIL/ENONET, Q30/Q31, F459 braces OPEN, D06 ACCEPTED_LIMITATION and
USER_EXCLUDED retained. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

Evidence: `q34-workflow-lint-20261009`; SEALED 66 files; manifest SHA256 `ca97933767737d439342934438d2d8e250a9090cd9020f775cf5b0e62741c772`.
82 related CI/release regression methods PASS; 722 tracked Markdown / all 9 documentation checks PASS.
