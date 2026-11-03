# Q34: Git trust flags in OpenWrt source admission

<!-- normative-sync: q34-openwrt-source-flags-v1 -->

Date:9 October2026.

## F482 / Q34-F036

The source gate required committed inputs using git status, but assume-unchanged
and skip-worktree flags could hide working edits. The gate then read committed
Makefile/Cargo and could return PASS for different working inputs. This bypassed
its clean-source contract; release_preflight calls the same function.

Real temporary Git repositories reproduced ten false-PASS cells:two flags times
qeli source,package Makefile,verify-source.sh,source gate and release_preflight.py.
Git status actually hid the edits;immutable pin,matching committed qeli tree and
fixture archive hash remained valid. This demonstrates admission,not an SDK build.

Scoped git ls-files -v now checks the same INPUTS before pin reading/archive hashing.
Lowercase assume-unchanged and S skip-worktree entries are refused even if currently
unchanged:status cannot establish their cleanliness. No flags or files are mutated.
Unrelated notes retain admission, preserving the original INPUTS boundary.
The OpenWrt README explains inspection and explicit flag removal after review.

## Qualification

37methods PASS:25source-gate and12whole-preflight. Source suite registers28methods;
three existing POSIX symlink/FIFO/old opt-in baseline skips remain. Three new
methods use real Git:ten hidden-input refusals and two unrelated-flags positives.
Two methods against exact prior gate reproduced ten false-PASS. POSIX archive APIs
were unchanged;prior Linux evidence is not a new execution. No network or lab used.

Read-only production source-cut inspection finds pin
dd0b736276b9ad5b89d117abd1bfe324210f3b26 has a different qeli tree than current HEAD.
Pin/hash/SDK recipe unchanged;matching source cut,actual SDK archive/current Actions
and publication remain OPEN. A stale release source was not relabelled PASS.
Only trust in Git status changed;no new SDK/native/compiler/runtime qualification.

Docs/diff/native digest e3fb/14 artifact SHA checked;historical cases and scope
preserved. Q34 IN_PROGRESS,30/37DONE81.1percent,7remain;Q29SIGKILLFAIL/ENONET,Q30/Q31,
F459braces,D06ACCEPTED_LIMITATION/USER_EXCLUDED unchanged.
LOCAL_DEV_COMMIT; NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-openwrt-source-flags-20261009`: SEALED 34 files / 1231613 bytes; manifest SHA256 `1bf2fd09bf340d81a75fc334d07ad07188cac0514d15dc34fa9027837385e190`.
