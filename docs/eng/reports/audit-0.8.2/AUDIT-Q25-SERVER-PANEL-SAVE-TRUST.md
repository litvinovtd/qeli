# Q25-F151: panel saves cannot promote an untrusted INI

1 October 2026. Base: `324a3418`. D07 remains **IN_PROGRESS**.

The worker correctly refused to execute `routing.post_up/post_down` from a group/world-writable INI or symlink. The panel, however, reread that file without checking trust, preserved its hooks, and published the result as a private `0600` inode. A restart could then execute a command that was untrusted before the save. Quick Start, structured and raw saves, configuration-history restore, and brute-force threshold saves shared this flaw. Full archive restore could likewise accept an “unchanged” command from an untrusted live file before normalizing the restored file permissions.

All five panel save paths now read bounded INI bytes and trust from the same opened inode. They check the original configured pathname so canonicalization cannot make a symlink trusted, and the pre-publication rereads check trust again. History restore requires a trusted snapshot. Archive restore requires a trusted live source for any preserved server or client command; archives without commands can still repair a broken live config. A nested `.conf` is now compared with its live counterpart in the same subdirectory, rather than a same-named file at the root of `/etc/qeli`.

On isolated lab server .11, focused tests for untrusted INI, symlinks, and unchanged archive commands passed, as did the existing editor/restore tests, `cargo fmt`, and strict Clippy. Log: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/panelsavetrust5.log`. No services were started or changed.

If server INI permissions are unsafe, the operator must review its contents and restore safe permissions (`chmod 600`) before using panel saves. A manual SSH editor still does not honor the advisory lock: an edit between the panel's last read and `rename` can be overwritten. The full D07 field/path matrix remains open. Register: **5/15 DONE**.
