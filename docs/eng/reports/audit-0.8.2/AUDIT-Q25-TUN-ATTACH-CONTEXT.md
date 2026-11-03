# Q25-F123: sysfs context during TUN dev_attach

Date: 25 September 2026. Base: `bf95bcdf`. D06 remains **IN_PROGRESS**.

After a process enters another network namespace, an inherited `/sys` mount can
still expose links from the previous namespace. The private .11 lab reproduced
two TUN devices named `qeli-audit0`: the current link had `ifindex=3`, while the
inherited sysfs exposed `ifindex=2` and `tun_flags=0x1801`. Previously,
`TunInterface::attach` trusted these foreign flags. If the devices have different
features, the first `TUNSETIFF` could pass the foreign feature set to the current
device.

Before reading `tun_flags`, Qeli now queries the name's index through a socket
ioctl in the current network namespace and compares it with
`/sys/class/net/<name>/ifindex`. A mismatch returns `refusing foreign tun_flags`
before `TUNSETIFF`. It checks both indexes again after parsing flags, also
rejecting an ordinary replacement between observations. The external manager
must keep the device stable until attachment completes.

The Linux test creates private mount and network namespaces on a disposable
thread, verifies successful attachment when sysfs matches, then checks refusal
for a same-name TUN in another namespace with a different index. All resources
remain inside the private namespaces and disappear with the thread.

This is a **partial guard**, not proof of namespace identity. Different
namespaces can allocate the same numeric `ifindex`, which this guard cannot
distinguish. An external replacement can also race between the last check and
`TUNSETIFF`. Netlink omits some TUN features in use, so a simple substitution
for `tun_flags` could reset them. `dev_attach` with a foreign inherited sysfs
is not certified; provide a sysfs mount for the current network namespace or
avoid attaching in that environment. The audit debt completion percentage is
unchanged.

## Validation

On private lab server .11, `cargo fmt --check` and Linux `--lib --no-run`
passed; all 8 ignored native `tun::iface::linux_tests` and all 49 regular
`tun::` tests passed (the 8 native tests were expected to be ignored in
the regular run). Direct foreign-sysfs reproduction showed indexes 2
versus 3 for the same name. Log:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/tun-attach-context-phase/attachfinal3.log`.
