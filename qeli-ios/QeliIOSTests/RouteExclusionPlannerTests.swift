import XCTest
@testable import Qeli

final class RouteExclusionPlannerTests: XCTestCase {
    func testLANBypassOnlyExtendsFullTunnelExclusions() {
        let configured = ["203.0.113.0/24"]
        XCTAssertEqual(
            RouteExclusionPlanner.effectiveExcludes(
                configured: configured, fullTunnel: false, allowLAN: true
            ),
            configured,
            "split-tunnel pushed private routes must not be removed by allow_lan"
        )

        let full = RouteExclusionPlanner.effectiveExcludes(
            configured: configured, fullTunnel: true, allowLAN: true
        )
        XCTAssertTrue(full.contains("10.0.0.0/8"))
        XCTAssertTrue(full.contains("fc00::/7"))
        XCTAssertEqual(full.first, configured.first)

        XCTAssertEqual(
            RouteExclusionPlanner.effectiveExcludes(
                configured: configured, fullTunnel: true, allowLAN: false
            ),
            configured
        )
    }

    func testIPv4SubtractionPreservesBothSidesOfANarrowExclusion() {
        let routes = RouteExclusionPlanner.subtract(
            "10.0.0.0/8",
            excludes: ["10.1.0.0/16", "2001:db8::/32"]
        )
        XCTAssertEqual(routes?.count, 8)
        XCTAssertEqual(routes?.first, "10.0.0.0/16")
        XCTAssertEqual(routes?.last, "10.128.0.0/9")
        XCTAssertFalse(routes?.contains("10.0.0.0/8") ?? true)
    }

    func testIPv6SubtractionIsExactAndFamilyAware() {
        let routes = RouteExclusionPlanner.subtract(
            "2001:db8::/32",
            excludes: ["192.0.2.0/24", "2001:db8:53::/48"]
        )
        XCTAssertEqual(routes?.count, 16)
        XCTAssertEqual(routes?.first, "2001:db8::/42")
        XCTAssertFalse(routes?.contains("2001:db8::/32") ?? true)
    }

    func testFullCoverageEmptyUnchangedAndMalformedAreDistinct() {
        XCTAssertEqual(
            RouteExclusionPlanner.subtract("192.0.2.0/24", excludes: ["0.0.0.0/0"]),
            []
        )
        XCTAssertEqual(
            RouteExclusionPlanner.subtract("192.0.2.0/24", excludes: ["198.51.100.0/24"]),
            ["192.0.2.0/24"]
        )
        XCTAssertNil(RouteExclusionPlanner.subtract("not-a-route", excludes: []))
    }

    func testTunnelGatewayCanOverrideOnlyBroaderPhysicalExclusions() {
        XCTAssertEqual(RouteExclusionPlanner.overridesOnLinkGateway(
            "10.0.0.0/8", gateway: "10.8.0.1", onLinkPrefixLength: 24
        ), false)
        XCTAssertEqual(RouteExclusionPlanner.overridesOnLinkGateway(
            "10.8.0.0/24", gateway: "10.8.0.1", onLinkPrefixLength: 24
        ), true)
        XCTAssertEqual(RouteExclusionPlanner.overridesOnLinkGateway(
            "10.8.0.1/32", gateway: "10.8.0.1", onLinkPrefixLength: 24
        ), true)
        XCTAssertEqual(RouteExclusionPlanner.overridesOnLinkGateway(
            "fc00::/7", gateway: "fd71:e1::1", onLinkPrefixLength: 64
        ), false)
        XCTAssertEqual(RouteExclusionPlanner.overridesOnLinkGateway(
            "fd71:e1::/64", gateway: "fd71:e1::1", onLinkPrefixLength: 64
        ), true)
        XCTAssertNil(RouteExclusionPlanner.overridesOnLinkGateway(
            "invalid", gateway: "10.8.0.1", onLinkPrefixLength: 24
        ))
    }
}
