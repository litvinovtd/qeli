# Q34: Rust dependencies, CI policy and TLS PEM

<!-- normative-sync: q34-dependency-policy-v1 -->

8 October 2026. F451–F454 / Q34-F005–F008 are closed within the scope below. Full Q34 remains IN_PROGRESS:30/37 full audit items DONE(81.1%),7remain. This packet does not qualify a release.

## Findings and fixes

| Finding | Before | After |
|---|---|---|
| F451 / Q34-F005 | The only two rustls-pemfile calls loaded panel PEMs;the archived crate produced RUSTSEC-2025-0134;lockfile also held yanked der0.8.0 | Existing rustls-pki-types1.15.0 PemObject API replaces wrapper;removed feature/dependency/lock entries;precise der update to0.8.1 |
| F452 / Q34-F006 | CI checked only bans/sources,no license policy;core metadata omitted its existing license | all-features/locked licenses+bans+sources gate,necessary permissive SPDX allowlist,AGPL exception scoped to qeli;metadata reflects existing AGPL-3.0-only,no file/client relicensing |
| F453 / Q34-F007 | cargo-audit warnings allowed and installed version floated | `cargo audit --deny warnings`,pinned cargo-audit0.22.2/cargo-deny0.18.4/Rust1.97.0 |
| F454 / Q34-F008 | Existing log fixture failed whole-tree rustfmt | Formatting-only fixture correction |

Lockfile delta removes rustls-pemfile2.2.0 and replaces der0.8.0 with0.8.1;all other dependency records preserved. Upstream changelog attributes the der0.8.0 yank to minimal-versions CI,not an announced cryptographic vulnerability. Newer patch0.8.2 is not qualified here;this pass resolves the confirmed yank without claiming every dependency is latest.

PEM reading retains4MiB bounds,nonblocking FIFO open,regular-file validation and certificate-rotation symlinks. Ordered certificate iteration refuses malformed later blocks;key selection accepts the first supported PKCS#1/SEC1/PKCS#8. rustls ServerConfig additionally validates the actual certificate/key pair.

## Actual checks

| Check | Result and scope |
|---|---|
| Fresh RustSec database | Git5701a6d2a6158d5d4a933df5141a0415c285075d,1294advisories. Baseline237packages:0vulnerabilities,1unmaintained+1yanked;current236:0vulnerabilities/0warnings,strict gate PASS |
| Licenses | Baseline standalone gate rejected190 requirements without allow-policy;current all-features/locked0errors/0warnings/211notes. Actual negative fixtures reject a third-party AGPL using the core exception and an unexpected GPL core license |
| Bans/sources | PASS;20 existing multiple-versions warnings remain warnings. Zero audit warnings does not suppress these separate diagnostics |
| Linux debug Rust |10TLS tests,2445library tests,5CLI tests PASS;60ignored not run;strict Clippy and whole-tree fmt PASS |
| Features | no-features/client-only/server-only/transport-core-ffi PASS;47/1/24 existing dead-code warnings in reduced feature sets preserved,not proof of unused shipped code |
| Release settings | Expected compiler refusal without jemalloc,release check with jemalloc PASS;no fresh Linux release payload build/runtime |
| HTTPS runtime |14assertions on current CLI:trusted HTTPS/API for auto/reused pairs and PKCS#1/PKCS#8/SEC1,unchanged operator files,auto key0600,private network restored |
| Windows driver files | Both Wintun0.14.1 copies pass pinned version/hash/signer/thumbprint/license;no driver load or OS route changes |
| Release/native harness |70native+48release Python tests PASS;67literal Actions references pinned SHA/local,not runner-image/SDK or Actions success qualification |
| Native qualification | Fresh independent A/B4targets/6compiler batches PASS; panic-unwind/jobs1/offline/private targets and per-command caches; exports6realtls+22client(+21JNI Android),14SHA/copies/provenance PASS; fresh Windows C ABI22PASS. Within-own-CargoHome reproducibility only; Mac cross-link missing-SDK warnings retained,physical runtime USER_EXCLUDED. |

Product source1751a44f686dc2212284b72180bf74a2b9ec06de. Actual Linux debug ELF ef8c71496f2f13afec52dc62d5ccf3db312e5d727dd15fd7d054ae41ef3b4e3a,78,756,672bytes;HTTPS ELF equals final downloaded CLI by SHA.

## Harness failures and lab preservation

Initial formatter run refused existing logs.rs formatting. Desktop upload stopped before compilation;abandoned own root archived/downloaded/SHA-verified/guard-cleaned. First full unit run2444PASS/1FAIL/60ignored:DNS fixture needs both endpoints of512connections,exceeding inherited1024fd. Repeat with4096 for test-process only:2445PASS/0FAIL/60ignored. No system/service limit change or hidden skip;initial logs/progress retained.

Initial Windows signature invocation refused execution policy;second inherited an incompatible PowerShell module path. Final check passed in system Windows PowerShell with policy/module changes limited to its child process. Two external helpers interrupted before SSH for quoting/fmt sequencing corrections;raw harness log records this.

Linux tests/HTTPS use private mount/net/pid namespaces and private managed paths where needed. Own Cargo/targets/caches,jobs1/offline after precise fetch. Original .11service/777/845/installed ELF75bc and .10processes745/901 preserved. Cleanup requires a downloaded SHA-verified recoverable archive followed by resolved-prefix/cwd/exe/root/fd/mount guards.

`q34-dependencies-20261008`: SEALED 148 files / 217225967 bytes; manifest SHA256 `9337f372ece61476968f431f7de55f60e2fa8dfc405043cb661ade0f57f926be`.

## Remaining scope

Latest [remote CI37598403060](https://github.com/litvinovtd/qeli/actions/runs/37598403060) ran SHA83c07f5c and failed macos-build/native-libs/ios-build. Current exact-SHA admission correctly refuses mismatch and failure;local PASS results do not replace it. No workflow dispatch,push,deployment or release.

Full Q34 still requires remaining dependency/SDK/package review,current release payload signatures and current CI/source-cut in agreed scope. No fresh Android full runtime/soak,Mac/iOS runtime,VPN/benchmark or other release payload qualification. Mac/iOS/router/Windows network VM USER_EXCLUDED,D06 ACCEPTED_LIMITATION;Q29SIGKILLFAIL/ENONET,Q30Apple/callbackOPEN,Q31capacity/source-cut/currentActions preserved. Old14debtDONE and41cases/71prior certification supplements retain historical results;one scoped supplement is appended.

Rust license policy: [LICENSING](../../../../LICENSING.md),[cargo-deny documentation](https://embarkstudios.github.io/cargo-deny/checks/licenses/cfg.html). PEM migration: [RustSec](https://rustsec.org/advisories/RUSTSEC-2025-0134.html).
