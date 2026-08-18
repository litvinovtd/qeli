import NetworkExtension
import XCTest
@testable import Qeli

final class TrustedWiFiTests: XCTestCase {
    func testSSIDListIsExactTrimmedAndDeduplicated() {
        XCTAssertEqual(
            TrustedWiFiPolicy.parse(" Home \n\nOffice, 5G\nHome\nhome"),
            ["Home", "Office, 5G", "home"]
        )
    }

    func testLegacyOnDemandSettingPreservesConnectionIntent() throws {
        let legacy = Data(#"{"onDemandEnabled":true}"#.utf8)
        let decoded = try JSONDecoder().decode(AppSettings.self, from: legacy)
        XCTAssertTrue(decoded.onDemandEnabled)
        XCTAssertTrue(decoded.connectionDesired)
        XCTAssertFalse(decoded.trustedWiFiEnabled)
        XCTAssertTrue(decoded.trustedWiFiSSIDs.isEmpty)
    }

    func testOnDemandRulesPauseOnlyExactTrustedWiFiThenConnectEverythingElse() {
        var settings = AppSettings()
        settings.onDemandEnabled = true
        settings.connectionDesired = true
        settings.trustedWiFiEnabled = true
        settings.trustedWiFiSSIDs = ["Home", "Office"]

        let rules = TunnelManager.makeOnDemandRules(settings: settings)
        XCTAssertEqual(rules.count, 2)
        let pause = rules[0] as? NEOnDemandRuleDisconnect
        XCTAssertNotNil(pause)
        XCTAssertEqual(pause?.interfaceTypeMatch, .wiFi)
        XCTAssertEqual(pause?.ssidMatch ?? [], ["Home", "Office"])
        XCTAssertTrue(rules[1] is NEOnDemandRuleConnect)
        XCTAssertTrue(
            TunnelManager.hasTrustedWiFiDisconnectRule(
                isOnDemandEnabled: true,
                rules: rules
            )
        )
        XCTAssertFalse(
            TunnelManager.hasTrustedWiFiDisconnectRule(
                isOnDemandEnabled: false,
                rules: rules
            )
        )

        // An explicit Disconnect clears this bit, so iOS cannot immediately auto-resume.
        settings.connectionDesired = false
        XCTAssertTrue(TunnelManager.makeOnDemandRules(settings: settings).isEmpty)
    }

    func testEmptyTrustedListCannotPauseVPN() {
        var settings = AppSettings()
        settings.onDemandEnabled = true
        settings.connectionDesired = true
        settings.trustedWiFiEnabled = true

        let rules = TunnelManager.makeOnDemandRules(settings: settings)
        XCTAssertEqual(rules.count, 1)
        XCTAssertTrue(rules[0] is NEOnDemandRuleConnect)
    }
}
