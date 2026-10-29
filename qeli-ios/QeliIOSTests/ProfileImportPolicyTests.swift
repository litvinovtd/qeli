import XCTest
@testable import Qeli

final class ProfileImportPolicyTests: XCTestCase {
    private let source = """
    # Frankfurt
    [qeli]
    # Keep the operator's routing explanation.
    server = vpn.example:443
    user = test
    pass = test
    # Keep this ordering and the final newline.
    """ + "\n"

    func testINIImportPreservesCommentsWhitespaceAndLabel() throws {
        let profile = try ProfileImportPolicy.profile(rawText: source, suggestedName: "client")
        XCTAssertEqual(profile.configText, source)
        XCTAssertEqual(profile.name, "Frankfurt")
    }

    func testLinkInsideGenericFileKeepsEmbeddedLabel() throws {
        let profile = try ProfileImportPolicy.profile(
            rawText: "qeli://test:test@vpn.example:443?proto=tcp&mode=fake-tls#Frankfurt",
            suggestedName: "client"
        )
        XCTAssertEqual(profile.name, "Frankfurt")
        XCTAssertTrue(profile.configText.contains("[qeli]"))
        XCTAssertEqual(try VPNConfig(parsing: profile.configText).serverAddress, "vpn.example")
    }

    func testFallbackDoesNotMistakeAnInternalCommentForTheName() throws {
        let text = "[qeli]\n# routing explanation\nserver = vpn.example:443\nuser = test\npass = test\n"
        XCTAssertEqual(try ProfileImportPolicy.profile(rawText: text).name, "vpn.example")
        XCTAssertEqual(try ProfileImportPolicy.profile(rawText: text, suggestedName: " Work ").name, "Work")
        XCTAssertEqual(try ProfileImportPolicy.profile(rawText: text, suggestedName: " ").name, "vpn.example")
    }

    func testMalformedAndOversizedImportsAreRejectedBeforeStorage() {
        XCTAssertThrowsError(try ProfileImportPolicy.profile(rawText: "[qeli]\nserver = vpn.example:bad"))
        XCTAssertThrowsError(try ProfileImportPolicy.profile(
            rawText: String(repeating: "#", count: ProfileLimits.maximumConfigBytes + 1)
        )) { error in
            guard let storeError = error as? ProfileStoreError,
                  case .profileTooLarge(1) = storeError else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }
}
