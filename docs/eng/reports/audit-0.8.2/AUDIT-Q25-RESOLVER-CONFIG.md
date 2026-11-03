# Q25 — system resolver configuration validation

<!-- normative-sync: audit-q25-resolver-config-v1 -->

24 September 2026. Baseline `6fd3ef6d`. Partial D06/D09 closure.

## Q25-F093, P2 — false success from symlink names or substrings

`resolved_is_active` accepted symlink names containing `systemd/resolve` or
`stub-resolv.conf`, even for missing files or external DNS contents. Searching
all text for `127.0.0.53` accepted comments and mixed resolver lists. The client
could successfully configure per-link DNS while applications reading `resolv.conf`
bypassed that path.

The check now reads one opened regular file: at most 64 KiB, metadata checked
before/after, nonblocking open to refuse FIFOs. Ordinary symlinks remain supported;
their names are not evidence. At least one actual `nameserver` line is required,
and every such line must specify only `127.0.0.53` or `127.0.0.54`. Comments are
ignored; unknown/fallback addresses, malformed input, NUL, oversized/invalid UTF-8
and unavailable files are refused.

`/run/systemd/resolve/resolv.conf` lists real upstream DNS and allows applications
to bypass resolved per-link routing; the standard stub file uses `127.0.0.53`,
while `127.0.0.54` is the proxy listener. Source: [systemd v257 manual](https://github.com/systemd/systemd/blob/v257/man/systemd-resolved.service.xml).

For `dns = tunnel`, use an operating stub resolver or explicitly leave DNS to the
platform with `dns = off`/`system`. Qeli still does not overwrite `/etc/resolv.conf`;
there are no new INI parameters. Refusal occurs before acquiring a DNS lease.

## Validation and boundaries

3 new Linux regressions: valid/false nameserver cases; dangling/misleading symlinks,
oversized/invalid UTF-8; an actual FIFO without a writer.
**1491 host + 71 config, 9 feature/cross/lint checks PASS**.
**2012 Linux + 32 privileged + 8 worker E2E PASS**.
Restoring the old predicates reproduces **2 FAILs**; restoration gives **18 DNS PASS**.
All 323 source files were verified before/after the runs.

Source archive: `08df0d8f509bced3731b180f5913cb8132c00b922d6cb9230894f329e56f42ce`.
Debug worker: `b4e3cf4075f942cd647223bee9218d69139ceaf6d08704e167703fefb6413542`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/dns-context-phase/`,
`dns-context-final.log`, `dns-config-counterfactual/`, `lifecycle-dns-context/`.
Lab `.11`, private namespaces; live server `.10` unchanged. Linux Rust 1.97 / host
1.98, existing Clippy exception `chunks_exact_to_as_chunks`.

This validates the file, not DNS service identity/liveness. A separate isolated
`resolver-context-probe-v2` confirmed that `resolvectl dns 2` from another netns
changes the original service's `foreign0` with the same ifindex through the shared
bus. The change was reverted within that private fixture after observation.
D06 bus/service context remains open and requires a separate fix; this file check
does not close it. D04/D05/D09/D10/D13 also remain open. Windows VM/Mac/iOS/router
runtime is skipped by user decision.

[Register](../../plans/AUDIT-DEBT.md) · [Manual](../../manuals/CONFIG.md)

Follow-up: [Q25-F094/F095](AUDIT-Q25-RESOLVER-CONTEXT.md) binds the bus/service context and command receiver, validates real resolved and fixes nonstandard DNS ports. Historical results above are unchanged.

Follow-up: [Q25-F104](AUDIT-Q25-RESOLVER-FILES.md) moves resolver-file reads before firewall setup, shares bounded admission with NSS and unifies the reader/parser with stub detection. Historical results above are unchanged.
