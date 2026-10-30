# Selected applications through Qeli

Choose applications permitted to use the VPN path while others retain normal
networking. This is a separate policy axis: `apps_mode`/`apps` select applications;
`gateway`, `include`, `exclude` and server push select destinations.

[Catalog and preparation](README.md) · [Русский](../../ru/scenarios/PER-APP.md)

## Platform support

| Platform | Identifier | Requirement |
| --- | --- | --- |
| Windows | Complete `.exe` path | Normal client/drivers and required privileges |
| Android | Installed package name | VpnService permission and a valid application list |
| macOS | Code-signing identifier, usually bundle ID | Signed System/Network Extensions with entitlements; the ad-hoc 0.8.3 archive does not provide them |
| iOS | Bundle ID | Arbitrary per-app needs MDM and NEAppRule; a normal profile does not apply it, and the client is unpublished |
| Linux CLI | — | Does not classify processes using these fields |

Lists are not portable between operating systems. Preserved INI fields do not
establish platform enforcement. On macOS, do not bypass signed-extension checks
or silently replace a rejected per-app mode with device-wide full tunnel.

## Select applications

`apps_mode=include` permits only the `apps` list; `exclude` excludes that list;
`all` uses normal device-wide behavior. Include/exclude require a nonempty list.
Prefer the GUI picker to obtain correctly formatted identifiers.

Windows example, in an existing client profile:

```ini
[qeli]
apps_mode = include
apps = C:\Program Files\Mozilla Firefox\firefox.exe
gateway = true
dns = tunnel
```

Android example, VPN for every application except the selected ones:

```ini
[qeli]
apps_mode = exclude
apps = com.android.vending, com.google.android.youtube
gateway = true
dns = tunnel
```

For a suitable signed macOS build, an example list is:

```ini
[qeli]
apps_mode = include
apps = org.mozilla.firefox
gateway = true
```

For VPN access only to corporate networks, use `gateway=false` and routes from
[SPLIT-ROUTING](SPLIT-ROUTING.md). Per-app does not enable full tunnel by itself.
`apps_mode`/`apps` are local settings; a `qeli://` link does not transfer this policy.

## Startup and verification

1. Verify installed applications and identifiers/paths. Stop and reconnect the VPN
   after changing policy.
2. Open an external-IP endpoint in the selected browser, then in an unselected
   application. A full-tunnel setup should use different paths.
3. Test selected-application DNS and UDP, not just a TCP page. A terminal's `curl`
   belongs to another process and does not itself verify browser policy.
4. Test IPv6, application child processes and behavior after path-changing updates.
5. Test VPN loss. With Android Always-on/lockdown, do not assume excluded apps
   retain direct Internet: OS blocking takes precedence. macOS per-app is not a
   host-wide kill-switch and does not intercept ICMP.

## Errors and rollback

Windows/macOS reject per-app without applicable identifiers. Android rejects
include when no installed package matches; exclude without matches can leave all
applications in the VPN with a warning. That is not a successful list test.

To return to ordinary operation, disconnect, set `apps_mode=all`, remove the local
`apps` list and reconnect. Verify both applications' networking. Details:
[CONFIG](../manuals/CONFIG.md), [client matrix](../reference/CLIENT-CONFIG-MATRIX.md).
