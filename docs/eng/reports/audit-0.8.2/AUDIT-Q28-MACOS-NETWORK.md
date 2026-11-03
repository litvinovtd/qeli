# Q28: macOS network cleanup and firewall ownership

<!-- normative-sync: audit-q28-macos-network-v1 -->

**5 October 2026: stage PASS; Q28 IN_PROGRESS. Plan 27/37 (73.0%), 10 sections remain.**

## Fixes

| ID | Defect and resulting behavior |
|---|---|
| F249 | Empty filter output authorized global /etc/pf.conf reload, potentially discarding NAT/rdr/scrub. Resolve requires an existing unconditional qeli or com.apple/* reference, refuses absent/conditional anchors, and never reloads the global ruleset. |
| F250 | Disengage flushed anchors without checking a live foreign owner and could globally disable pf after another tool enabled it. PfRecovery validates a bounded strict owner stamp, protects live owners/refreshes and retains its last journal until all cleanup succeeds. Global pf remains enabled. State/rules/locks use ServiceState's protected descriptor store; malformed/ownerless legacy state requires manual repair. |
| F251 | Stale DNS restoration could delete a newer journal/override. A reentrant sidecar lease now spans recovery, claim, mutation and release; original release remains retryable. Reads are bounded/strict UTF-8, only absence is absence; root production storage uses trusted descriptors/private atomic publication. Native read/write exceptions become failed results, allowing rollback after partial apply. |
| F252 | Failed address removal returned false inside Action and was discarded as success; partial apply was not recorded. Address undo is registered before mutation, rejects errors unless an absent interface/address is verified, and remains retryable. Prefix/interface validation precedes apply. |
| F253 | Unknown networksetup output became automatic DNS, a missing primary service guessed Wi-Fi, and desktop resolver allowlists accepted IPv4 multicast/broadcast and mapped loopback. DNS output now parses a complete literal list or exact automatic-state diagnostic; failed service selection refuses; IPv6-only hosts use their IPv6 default service. Shared PhysicalDnsPolicy supplies Windows/Mac physical resolver filtering. Server unicast loopback/link-local remains separately supported; generated rule literals are checked. |
| F254 | Concurrent utun Open/Dispose could leak/double-close descriptors; child tools could inherit the utun fd. Lifetime is serialized, closes once, validates kernel name/length/terminator and sets FD_CLOEXEC through architecture-specific Darwin fcntl calls. |
| F255 | Failed route query looked absent and cleanup deleted an externally replaced carrier route. Unknown queries refuse before mutation; matching ownership is inspected before deletion and newer external routes survive. Network/pf/sysctl commands use the bounded ToolProcess runner; forwarding retries clear only successfully restored family flags. Rule generation dispatches before startup recovery. |

## Checks and evidence

- Mac network-selftest: **117/117 PASS**. Existing DNS/route/roaming fixtures plus production PfRecovery, DNS transactions, malformed/oversized snapshots, partial DNS/address failure, external route replacement, lease contention, physical resolver matrix and injected descriptor lifetime.
- Mac control **83/83**, storage **54/54**, Windows **325/325**, shared conformance **549/549 PASS**, fresh checks after common policy changes.
- Baseline **10/10 expected FAIL**, exit 1: original NetworkConfigurator + Roaming, DnsJournal, KillSwitch and Windows resolver body. Only namespace, service directory and Exec/Pf boundaries are adapted; a real isolated Windows child supplies a live foreign PID. Includes deterministic stale-recovery/new-owner collision.
- Release Mac/Windows/shared: zero errors/warnings. Docs/bindings/panel/diff, unchanged native provenance and 14 checksum rows PASS.
- Production pf rule generator runs without startup recovery. Its output is retained; actual pf parse/load/traffic enforcement was not run here.

Raw directory: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-network-20261005.
Evidence: release/certification/evidence/q28-macos-network-20261005.json. User profiles, installed services, networking and lab were not changed.

## Scope and remaining work

This is host C#/fake-command/filesystem qualification on Windows, not a Mac kernel E2E. Actual Darwin fcntl/flock/openat/renameatx_np/utun, pf precedence/state behavior, networksetup diagnostics, IPv6 scope handling and native Intel/ARM dylib remain **USER SKIPPED**. The root fd adapter is reviewed; Windows tests inject its boundary. Exact English networksetup automatic-state text is a conservative compatibility fixture; changed diagnostics fail closed. Rule generation is not native pf parsing.

The descriptor getter remains borrowed: Rust duplicates it under the tunnel generation lifetime contract. Cooperative locks do not bound the owner's whole operation or native OS I/O; commands have individual deadlines. Direct root state edits/replacement are unsupported. Physical DNS exceptions still permit other apps to query those resolvers during reconnect; pf foreign quick rules/order require administrator assessment. Global pf staying enabled after release is intentional.

Remaining Q28: Swift per-app providers/helper/guardian, entitlements and build contracts; forwarding ownership/crash recovery and complete platform cleanup integration review. No Mac SIGKILL/sleep/roaming/foreign-firewall execution claim; no fresh Linux/JNI/soak/benchmark.

Primary contracts: [Darwin fcntl/FD_CLOEXEC](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/fcntl.h), [utun kernel interface](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if_utun.h), [Apple ARM64 calling conventions](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms).

The final journal-size guard initially failed to compile (long/int relational pattern). The comparison was corrected; the retained failed build is followed by a fresh clean build and all three Mac test suites on that new DLL.
