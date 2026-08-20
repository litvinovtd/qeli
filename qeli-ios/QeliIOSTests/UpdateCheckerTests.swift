import XCTest
@testable import Qeli

final class UpdateCheckerTests: XCTestCase {
    func testVersionNormalizationAndNumericComparison() {
        XCTAssertEqual(UpdateChecker.normalize(" v0.7.12-beta+5 "), "0.7.12")
        XCTAssertTrue(UpdateChecker.isNewer("0.10.0", than: "0.9.9"))
        XCTAssertFalse(UpdateChecker.isNewer("v0.7.12", than: "0.7.12+715"))
        XCTAssertFalse(UpdateChecker.isNewer("0.7.11", than: "0.7.12"))
    }

    func testPrivatePathRejectsEitherFamilyLeakAndExcludedRoutes() throws {
        let base = """
        [qeli]
        server = vpn.example.com:443
        user = alice
        pass = secret
        """
        XCTAssertTrue(UpdateChecker.hasPrivatePath(try VPNConfig(parsing: base)))

        for narrowing in [
            "gateway = false",
            "allow_ipv4_leak = true",
            "allow_ipv6_leak = true",
            "allow_lan = true",
            "exclude = 203.0.113.0/24",
        ] {
            let config = try VPNConfig(parsing: base + "\n" + narrowing)
            XCTAssertFalse(UpdateChecker.hasPrivatePath(config), narrowing)
        }
        XCTAssertFalse(UpdateChecker.hasPrivatePath(
            try VPNConfig(parsing: base), globalAllowLAN: true
        ))
    }
}
