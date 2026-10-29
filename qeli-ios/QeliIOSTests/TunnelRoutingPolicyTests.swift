import NetworkExtension
import XCTest
@testable import Qeli

final class TunnelRoutingPolicyTests: XCTestCase {
    private let profile = Profile(name: "Routing test", configText: "")

    func testSplitRoutesAreEnforcedWithoutCapturingUnrelatedTraffic() {
        var config = VPNConfig(serverAddress: "198.51.100.10", port: 443)
        config.routingMode = "split-tunnel"
        config.addDefaultGateway = false
        config.includeRoutes = ["10.0.0.0/8"]
        config.excludeRoutes = ["10.10.0.0/16"]
        config.allowLAN = true
        var settings = AppSettings()
        settings.allowLAN = true

        let result = TunnelManager.makeTunnelProtocol(
            profile: profile, config: config, settings: settings)
        XCTAssertTrue(result.enforceRoutes)
        XCTAssertFalse(result.includeAllNetworks)
        // A full-tunnel LAN exception must not weaken an explicit split private route.
        XCTAssertFalse(result.excludeLocalNetworks)
    }

    func testStrictFullTunnelRetainsSystemCapture() {
        let config = VPNConfig(serverAddress: "198.51.100.10", port: 443)
        let result = TunnelManager.makeTunnelProtocol(
            profile: profile, config: config, settings: AppSettings())
        XCTAssertTrue(result.includeAllNetworks)
        XCTAssertTrue(result.enforceRoutes)
        XCTAssertFalse(result.excludeLocalNetworks)
        XCTAssertFalse(result.excludeAPNs)
        XCTAssertFalse(result.excludeCellularServices)
    }

    func testFullTunnelExceptionsKeepRouteEnforcement() {
        for exception in ["ipv4", "ipv6", "route", "profile-lan", "global-lan"] {
            var config = VPNConfig(serverAddress: "198.51.100.10", port: 443)
            var settings = AppSettings()
            switch exception {
            case "ipv4": config.allowIPv4Leak = true
            case "ipv6": config.allowIPv6Leak = true
            case "route": config.excludeRoutes = ["192.0.2.0/24"]
            case "profile-lan": config.allowLAN = true
            default: settings.allowLAN = true
            }
            let result = TunnelManager.makeTunnelProtocol(
                profile: profile, config: config, settings: settings)
            XCTAssertFalse(result.includeAllNetworks, exception)
            XCTAssertTrue(result.enforceRoutes, exception)
            XCTAssertEqual(result.excludeLocalNetworks,
                           exception == "profile-lan" || exception == "global-lan", exception)
        }
    }
}
