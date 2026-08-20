import XCTest
@testable import Qeli

/// Guards for the Android↔iOS parity pass. Each test pins a divergence that was live in the
/// tree, so a regression shows up red instead of as a profile that quietly behaves
/// differently on one platform.
final class ParityHardeningTests: XCTestCase {

    private func minimalINI(_ extra: String = "") -> String {
        """
        [qeli]
        server = vpn.example.com:443
        user = alice
        pass = s3cret
        \(extra)
        """
    }

    /// The `[logging]` section used to be parsed into the section map and then dropped, so
    /// opening a desktop/router `client.conf` on the phone and saving it deleted the
    /// operator's logging configuration.
    func testLoggingSectionSurvivesRoundTrip() throws {
        let source = """
        [qeli]
        server = vpn.example.com:443
        user = alice
        pass = s3cret

        [logging]
        level = debug
        file = /var/log/qeli/client.log
        time_format = rfc3339
        """
        let first = try VPNConfig(parsing: source)
        XCTAssertEqual(first.loggingLevel, "debug")
        XCTAssertEqual(first.loggingTimeFormat, "rfc3339")

        let second = try VPNConfig(parsing: first.toINI())
        XCTAssertEqual(second.loggingLevel, "debug")
        XCTAssertEqual(second.loggingFile, "/var/log/qeli/client.log")
        XCTAssertEqual(second.loggingTimeFormat, "rfc3339")
    }

    /// Rust clamps an out-of-range link MTU to auto. This client used to reject the whole
    /// link, so one shared `qeli://` imported on Android and failed here.
    func testOutOfRangeLinkMTUFallsBackToAuto() throws {
        let uri = "qeli://alice:s3cret@vpn.example.com:443?proto=tcp&mode=fake-tls&mtu=99999"
        XCTAssertEqual(try VPNConfig(parsing: uri).mtu, 0)
    }

    /// Lists are emitted with ", " to match the Rust and Android writers byte-for-byte.
    func testListSeparatorMatchesOtherClients() throws {
        var config = try VPNConfig(parsing: minimalINI())
        config.dnsServers = ["1.1.1.1", "8.8.8.8"]
        config.includeRoutes = ["10.0.0.0/8", "192.0.2.0/24"]
        let ini = try config.toINI()
        XCTAssertTrue(ini.contains("dns_servers = 1.1.1.1, 8.8.8.8"), ini)
        XCTAssertTrue(ini.contains("include = 10.0.0.0/8, 192.0.2.0/24"), ini)
    }

    /// The UI language is an explicit setting defaulting to English, not the device locale —
    /// a Russian phone must not silently open the app in Russian (Android behaves this way).
    func testLanguageDefaultsToEnglish() {
        XCTAssertEqual(AppSettings().language, .en)
        XCTAssertEqual(AppLanguage.allCases, [.en, .ru])
    }

    /// Settings saved by an older build lack the newer keys. Swift's synthesized decoder
    /// throws on a missing key rather than using the property default, and `SettingsStore`
    /// answers a decode failure by returning fresh defaults — so without a tolerant decoder,
    /// adding one field silently wipes every preference the user had.
    func testSettingsFromAnOlderBuildKeepTheirValues() throws {
        let legacy = Data(#"{"autoConnectOnLaunch":true,"allowLAN":true}"#.utf8)
        let decoded = try JSONDecoder().decode(AppSettings.self, from: legacy)
        XCTAssertTrue(decoded.autoConnectOnLaunch)
        XCTAssertTrue(decoded.allowLAN)
        XCTAssertEqual(decoded.language, .en)
        XCTAssertEqual(decoded.logTimeFormat, .time)
        XCTAssertEqual(decoded.logLevel, .info)
    }

    /// Every option the settings pickers show has to exist as a localization key in BOTH
    /// bundles; a missing entry silently renders the English key to a Russian user.
    func testPickerOptionKeysAreLocalizedInEveryLanguage() throws {
        let keys = LogTimeFormat.allCases.map(\.title)
            + ClientLogLevel.allCases.map(\.title)
            + AppAppearance.allCases.map(\.title)
        for language in AppLanguage.allCases {
            guard let path = Bundle.main.path(forResource: language.rawValue, ofType: "lproj"),
                  let bundle = Bundle(path: path) else {
                XCTFail("missing \(language.rawValue).lproj")
                continue
            }
            for key in keys {
                let sentinel = "\u{0}missing"
                let value = bundle.localizedString(forKey: key, value: sentinel, table: nil)
                XCTAssertNotEqual(value, sentinel, "\(language.rawValue) is missing the key \"\(key)\"")
            }
        }
    }

    /// The protection card may only claim "all traffic is protected" when nothing narrows
    /// what the tunnel carries. Mirrors ProtectionSummaryTest on Android — the two cards
    /// must never disagree about the same profile.
    func testProtectionSummaryNeverOverstates() throws {
        let base = try VPNConfig(parsing: minimalINI("key = " + String(repeating: "aa", count: 32)))
        XCTAssertTrue(ProtectionSummary(config: base).carriesEverything)

        for narrowing in ["allow_lan = true", "allow_ipv4_leak = true", "allow_ipv6_leak = true",
                          "exclude = 192.168.0.0/16", "gateway = false"] {
            let config = try VPNConfig(parsing: minimalINI(
                "key = " + String(repeating: "aa", count: 32) + "\n" + narrowing))
            XCTAssertFalse(
                ProtectionSummary(config: config).carriesEverything,
                "\(narrowing) must stop the card claiming everything"
            )
        }
    }

    /// `plain` is the only mode without the hybrid handshake; obfs and reality-tls wrap the
    /// The GLOBAL LAN toggle narrows the tunnel just as the per-profile one does.
    ///
    /// `TunnelManager` sets `excludeLocalNetworks` from `config.allowLAN || settings.allowLAN`,
    /// but the card read only the profile field — so with the app-wide switch on it announced
    /// "all traffic is protected" while RFC1918, link-local and multicast went past the VPN.
    /// A card that makes security claims has to err in the SAFE direction, and this erred the
    /// other way. Mirror of the Android test. (Audit 2026-08-02, §13.)
    func testTheGlobalLANToggleAlsoStopsItClaimingEverything() throws {
        let config = try VPNConfig(parsing: minimalINI("key = " + String(repeating: "aa", count: 32)))

        let global = ProtectionSummary(config: config, globalAllowLAN: true)
        XCTAssertFalse(global.carriesEverything, "the global toggle must count")
        XCTAssertTrue(global.warnings.contains(.lanOutside))

        // ...and with it off a clean profile still claims everything — otherwise this would
        // pass against a summary that simply always warns.
        XCTAssertTrue(ProtectionSummary(config: config, globalAllowLAN: false).carriesEverything)
    }

    func testLANToggleDoesNotPretendToExcludeSplitTunnelRoutes() throws {
        let config = try VPNConfig(parsing: minimalINI(
            "gateway = false\ninclude = 10.20.0.0/16\nallow_lan = true"
        ))
        let summary = ProtectionSummary(config: config, globalAllowLAN: true)
        XCTAssertEqual(summary.scope, .splitRoutes)
        XCTAssertFalse(summary.warnings.contains(.lanOutside))
    }

    func testMissingFamilyWarningOutranksNarrowerBypasses() throws {
        let config = try VPNConfig(parsing: minimalINI(
            "allow_ipv4_leak = true\nallow_lan = true\nexclude = 192.168.0.0/16"
        ))
        XCTAssertEqual(ProtectionSummary(config: config).warnings.first, .ipv4Outside)
    }

    func testLegacyTunnelSnapshotDecodesWithoutGateway() throws {
        let legacy = Data(#"""
        {"phase":"connected","message":"ok","clientAddress":"fd71:e100::2",
         "bytesUploaded":0,"bytesDownloaded":0,"uploadBytesPerSecond":0,
         "downloadBytesPerSecond":0,"updatedAt":0,"maxStreams":1,"pushedRoutes":0}
        """#.utf8)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        let snapshot = try decoder.decode(TunnelSnapshot.self, from: legacy)
        XCTAssertEqual(snapshot.clientAddress, "fd71:e100::2")
        XCTAssertNil(snapshot.tunnelGateway)
        XCTAssertNil(snapshot.liveConnectionProperties)

        var current = snapshot
        current.tunnelGateway = "fd71:e100::1"
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        let roundTrip = try decoder.decode(
            TunnelSnapshot.self,
            from: encoder.encode(current)
        )
        XCTAssertEqual(roundTrip.tunnelGateway, "fd71:e100::1")
    }

    func testLiveConnectionPropertiesRoundTripWithoutCredentials() throws {
        let config = try VPNConfig(parsing: minimalINI(
            "key = " + String(repeating: "aa", count: 32)
                + "\nallow_ipv6_leak = true\nmtu = 1312\nreconnect = false"
        ))
        let live = LiveConnectionProperties(config: config, globalAllowLAN: true)
        XCTAssertEqual(live.serverAddress, config.serverAddress)
        XCTAssertEqual(live.displayEndpoint, "\(config.serverAddress):\(config.port)")
        XCTAssertEqual(live.configuredMTU, 1312)
        XCTAssertFalse(live.reconnectEnabled)
        XCTAssertTrue(live.warnings.contains(.ipv6Outside))
        XCTAssertTrue(live.warnings.contains(.lanOutside))

        var snapshot = TunnelSnapshot()
        snapshot.liveConnectionProperties = live
        let encoded = try JSONEncoder().encode(snapshot)
        let text = String(decoding: encoded, as: UTF8.self)
        XCTAssertFalse(text.contains("password"))
        XCTAssertFalse(text.contains("sessionToken"))
        let decoded = try JSONDecoder().decode(TunnelSnapshot.self, from: encoded)
        XCTAssertEqual(decoded.liveConnectionProperties, live)
        XCTAssertEqual(ProtectionSummary(live: live).warnings,
                       ProtectionSummary(config: config, globalAllowLAN: true).warnings)

        var ipv6 = config
        ipv6.serverAddress = "2001:db8::10"
        XCTAssertEqual(
            LiveConnectionProperties(config: ipv6, globalAllowLAN: false).displayEndpoint,
            "[2001:db8::10]:\(config.port)"
        )
    }

    /// `apps_mode` is REPORTED on iOS, never applied — `NEAppRule` needs an MDM-managed
    /// configuration, so every app goes through the tunnel whatever the profile says.
    ///
    /// The card used to map the mode straight onto the scope and announce "only the selected
    /// apps are protected", confirming a restriction that is not in force: the user arranges
    /// their traffic around that belief and the truth is the opposite. The scope now follows
    /// the ROUTES — what this platform actually enforces — and the unapplied selection gets
    /// its own warning. That warning must NOT clear `carriesEverything`, because an
    /// unapplied per-app selection widens the tunnel rather than narrowing it.
    /// (Audit 2026-08-02, §7.)
    func testPerAppSelectionIsReportedAsUnappliedNotAsScope() throws {
        for mode in ["include", "exclude"] {
            let config = try VPNConfig(parsing: minimalINI(
                "key = " + String(repeating: "aa", count: 32)
                    + "\napps_mode = \(mode)\napps = com.example.a"))
            let summary = ProtectionSummary(config: config)
            XCTAssertEqual(summary.scope, .all, "\(mode) must not narrow the reported scope")
            XCTAssertTrue(summary.warnings.contains(.perAppNotApplied), mode)
            XCTAssertTrue(
                summary.carriesEverything,
                "an unapplied \(mode) selection widens the tunnel — the card must not claim less"
            )
        }

        // The warning is specific to a request, not permanent furniture.
        let plain = try VPNConfig(parsing: minimalINI("key = " + String(repeating: "aa", count: 32)))
        XCTAssertFalse(ProtectionSummary(config: plain).warnings.contains(.perAppNotApplied))
    }

    /// SAME PQ ClientHello, so claiming post-quantum for them is correct.
    func testPostQuantumIsClaimedForEveryModeExceptPlain() throws {
        for mode in ["fake-tls", "obfs", "reality-tls"] {
            // reality-tls now requires BOTH reality_sid and a pinned key at parse time, so the
            // fixture has to carry them. This test is about the post-quantum claim, not about
            // those preconditions — they have their own coverage below.
            let config = try VPNConfig(parsing: minimalINI(
                "mode = \(mode)\nobfs_key = k\nreality_sid = 0a1b\nkey = "
                    + String(repeating: "aa", count: 32)))
            XCTAssertTrue(ProtectionSummary(config: config).postQuantum, mode)
        }
        let plain = try VPNConfig(parsing: minimalINI("mode = plain"))
        XCTAssertFalse(ProtectionSummary(config: plain).postQuantum)
    }

    /// A reality-tls profile with no pinned key is REFUSED, at parse time.
    ///
    /// This inverts what the test asserted before: parsing used to accept such a profile and
    /// the connect-time precondition in `TunnelManager` was what refused it, so a half-filled
    /// profile stayed editable. The refusal moved into the config layer, because accepting the
    /// profile is what makes the failure surface mid-handshake, where it reads as a server or
    /// network fault rather than a missing field.
    ///
    /// The trade is real and recorded here rather than glossed over: an unfinished reality-tls
    /// profile can no longer be saved from the editor, only completed or discarded. That is the
    /// stricter of the two behaviours and matches the Rust client, which refuses at config load.
    func testRealityWithoutPinnedKeyIsRefused() throws {
        XCTAssertThrowsError(
            try VPNConfig(parsing: minimalINI("mode = reality-tls\nreality_sid = 0a1b")),
            "reality-tls without a pinned key must not parse: an unauthenticated peer is proxied "
                + "to the decoy site, which a TOFU client cannot tell apart from the real server")

        // With the key present the same profile parses and round-trips.
        let ok = try VPNConfig(parsing: minimalINI(
            "mode = reality-tls\nreality_sid = 0a1b\nkey = " + String(repeating: "aa", count: 32)))
        XCTAssertEqual(ok.wireMode, "reality-tls")
        XCTAssertNoThrow(try ok.toINI())
    }

    func testQRScannerPreviewUsesTheGeometricSheetCenter() {
        for size in [CGSize(width: 390, height: 600), CGSize(width: 844, height: 390)] {
            let center = QRScannerLayout.previewCenter(in: size)
            XCTAssertEqual(center.x, size.width / 2, accuracy: 0.001)
            XCTAssertEqual(center.y, size.height / 2, accuracy: 0.001)

            let side = QRScannerLayout.previewSide(in: size)
            XCTAssertLessThanOrEqual(side, QRScannerLayout.maximumSide)
            XCTAssertLessThanOrEqual(side, size.width - QRScannerLayout.horizontalInset * 2)
            XCTAssertLessThanOrEqual(side, size.height - QRScannerLayout.promptReserve)
        }
    }
}
