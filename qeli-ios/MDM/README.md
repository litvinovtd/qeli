# Managed deployment templates

These files are administrator templates, not consumer-app features. Validate and
sign edited profiles in the MDM product before deployment. Every example bundle ID,
UUID, server, profile ID and credential must be replaced.

## Qeli per-app VPN

`Qeli-PerApp-VPN.mobileconfig` uses Apple's `com.apple.vpn.managed.applayer`
payload and the Qeli packet tunnel provider. Keep these identifiers aligned with
`Config/Signing.xcconfig`:

- `VPNSubType`: the containing Qeli app bundle ID (`QELI_APP_BUNDLE_ID`).
- `VPN.ProviderBundleIdentifier`: `QELI_TUNNEL_BUNDLE_ID`.
- `VPNUUID`: the stable UUID the MDM service also assigns to each managed app.
- `VendorConfig.profileID`: a profile UUID already present in Qeli's encrypted
  App Group store. The example does not provision credentials or profile text.

On iOS, the target app must itself be managed. Associate it with the VPN by setting
the same `VPNUUID` in the managed app's attributes. For an MDM `InstallApplication`
command, the relevant fragment is:

```xml
<key>Attributes</key>
<dict>
    <key>VPNUUID</key>
    <string>1653840A-E082-4CC2-877A-A8D188C183B6</string>
</dict>
```

Declarative Device Management uses the equivalent `Attributes.VPNUUID` property on
the managed app declaration. A normal App Store install can't assign arbitrary apps
to this VPN and Qeli doesn't attempt to enumerate installed apps.

Apple references:

- https://developer.apple.com/documentation/devicemanagement/applayervpn
- https://developer.apple.com/documentation/devicemanagement/installapplicationcommand/command-data.dictionary/attributes-data.dictionary

## Always On VPN

`Apple-IKEv2-AlwaysOn.mobileconfig` documents Apple's actual Always On facility. It
requires a supervised, MDM-managed device and an IKEv2 server. It does **not** make
the Qeli custom Packet Tunnel Provider Always On and is not compatible with the Qeli
wire protocol. For consumer devices use Qeli's VPN On Demand setting instead.

The shared-secret placeholder keeps the example self-contained, but certificate
authentication with a separately deployed identity payload is preferable in a real
organization. Never deploy the placeholder secret or `.invalid` host names.

Apple references:

- https://support.apple.com/guide/deployment/depae3d361d0/web
- https://developer.apple.com/documentation/devicemanagement/vpn
- https://developer.apple.com/documentation/devicemanagement/vpn/alwayson-data.dictionary

## Managed app configuration

`Qeli-Managed-App-Configuration.plist` is the dictionary to send as legacy managed
app configuration, not a configuration profile. Qeli's standalone
`ManagedConfigurationReader` reads it from
`UserDefaults.standard["com.apple.configuration.managed"]` and accepts:

- `configurationVersion` — integer schema version.
- `activeProfileID` — UUID string referring to an existing encrypted profile.
- `onDemandEnabled` — Boolean policy value.
- `widgetControlsEnabled` — Boolean policy value.

The reader itself is side-effect free. `AppModel` gives these managed values
precedence at launch and whenever the app becomes active: it selects the managed
profile for the next connection, enforces the managed On Demand value, and mirrors
the widget-control policy into the App Group so the widget extension can reject
disabled actions. An `activeProfileID` key that is malformed or does not match an
encrypted local profile fails closed: Qeli blocks manual/widget starts, stops the
old tunnel, removes On Demand rules and disables the stale provider configuration.
It never accepts profile text, passwords, or private keys. On newer managed
deployments, Apple's ManagedApp framework can replace this legacy `UserDefaults`
delivery path.

Apple reference:

- https://developer.apple.com/documentation/devicemanagement/configuring-managed-apps-and-extensions
