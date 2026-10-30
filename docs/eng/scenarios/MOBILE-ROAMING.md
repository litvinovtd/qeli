# Mobile and unstable Wi-Fi networks

Recover from Wi-Fi/LTE changes, sleep and temporary loss of connectivity.
Successful roaming retains the session; when that is unavailable, reconnect creates a new one.

[Catalog and preparation](README.md) · [Русский](../../ru/scenarios/MOBILE-ROAMING.md)

## Preparation

Update both ends to compatible versions and test the profile on a stable network
first. For UDP, verify that the operator permits the selected UDP port.
Published 0.8.3 includes Android recovery fixes, but does not claim to resolve the
previously documented Android API34 `ENONET`. The iOS client is unpublished and
has not been qualified on a real device; source availability does not change that.

## Settings

In the client profile:

```ini
[qeli]
roaming = auto
reconnect = true
reconnect_retries = -1
reconnect_base_delay = 1
reconnect_max_delay = 60
timeout = 30
mtu = 0
mtu_probe = true
```

In the matching server profile:

```ini
[profile:main]
roaming.enabled = true
roaming.grace_secs = 30
```

Retain other roaming limits from the working profile. `auto` migrates when the
core, server and platform support the required contract, otherwise allowing a
full reconnect. `required` does not improve older peers: incompatible peers are
rejected. Do not pin `local`/`lport` when migration between interfaces is required.

`mtu=0` selects the inner MTU automatically. For UDP, `mtu_probe=true` checks the
outer path budget. In 0.8.3, setting a manual inner MTU does not itself disable
that check. Large socket buffers are not a substitute for measuring loss and RTT.

## Android system settings

Grant VPN permission and allow the service notification. On devices with restrictive
background policies, check background operation and battery optimization exceptions.
For blocking without VPN, enable OS Always-on VPN and Block connections without VPN.
Disabling Wi-Fi and force-stopping the app are different events: OS force-stop
may require another manual launch.

## Step-by-step verification

1. On Wi-Fi, verify an actual request, DNS, IPv4/IPv6 and external IP.
2. During a transfer, disable Wi-Fi and wait for LTE availability. Distinguish
   migration from new AUTH in logs, then establish a new application connection.
3. Return to Wi-Fi and repeat. TUN/IP stability is possible after successful
   migration, not guaranteed for every outage or server.
4. Test sleep/wake and temporary complete network loss. Measure VPN recovery
   separately from application recovery.
5. Test explicit Disconnect: reconnect must not override the user's choice.
6. For a backup transport, test [PRIMARY-BACKUP](PRIMARY-BACKUP.md). Roaming does
   not switch TCP to UDP or select another profile.

## Diagnostics and rollback

Record event time, version/OS, transport and a structured diagnostic report if
available. Before publishing, check for keys, passwords, complete INIs and private
addresses. Do not bypass a key mismatch, incomplete stop or recovery to reconnect.
Restore previous profile settings and reconnect cleanly to roll back; avoid
unnecessarily revoking system VPN permission.

Details: [roaming plan](../plans/ROAMING.md),
[troubleshooting](../manuals/TROUBLESHOOTING.md).
