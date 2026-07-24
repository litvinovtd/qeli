import XCTest
@testable import Qeli

/// Cross-implementation conformance for the `qeli://` link.
///
/// Reads the SAME fixtures as the Rust, Kotlin and C# suites (`conformance/qeli-links.json`
/// at the repository root). The format is implemented four separate times in four
/// languages, so every field is four chances to disagree — and the failure is silent: the
/// link "imports fine" with a field dropped or re-defaulted, and the user gets a profile
/// that cannot connect. Writing these fixtures immediately exposed one such split — Swift
/// and C# rejected an out-of-range port while Rust accepted 0 and Kotlin accepted anything.
final class LinkConformanceTests: XCTestCase {

    /// Locate the fixtures by walking up from THIS source file rather than from a bundle
    /// resource: the file is shared with three other languages and deliberately lives
    /// outside the Xcode project, and `#filePath` is stable regardless of where the test
    /// runner's working directory happens to be.
    private func fixtures() throws -> [String: Any] {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let candidate = dir.appendingPathComponent("conformance/qeli-links.json")
            if FileManager.default.fileExists(atPath: candidate.path) {
                let data = try Data(contentsOf: candidate)
                guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    throw VPNConfigError.invalid("fixtures are not a JSON object")
                }
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        XCTFail("conformance/qeli-links.json not found walking up from \(#filePath)")
        throw VPNConfigError.invalid("fixtures not found")
    }

    func testAcceptsEveryValidFixtureWithTheExpectedFields() throws {
        let fx = try fixtures()
        let cases = fx["cases"] as? [[String: Any]] ?? []
        XCTAssertFalse(cases.isEmpty, "fixture file has no cases")

        for c in cases {
            let name = c["name"] as? String ?? "?"
            let uri = c["uri"] as? String ?? ""
            let cfg: VPNConfig
            do {
                cfg = try VPNConfig.fromQeliURI(uri)
            } catch {
                XCTFail("case '\(name)': expected the link to parse, got \(error)")
                continue
            }
            let e = c["expect"] as? [String: Any] ?? [:]

            if let v = e["host"] as? String { XCTAssertEqual(cfg.serverAddress, v, "case '\(name)': host") }
            if let v = e["port"] as? Int { XCTAssertEqual(cfg.port, v, "case '\(name)': port") }
            if let v = e["user"] as? String { XCTAssertEqual(cfg.username, v, "case '\(name)': user") }
            if let v = e["pass"] as? String { XCTAssertEqual(cfg.password, v, "case '\(name)': pass") }
            if let v = e["proto"] as? String { XCTAssertEqual(cfg.protocolName, v, "case '\(name)': proto") }
            if let v = e["mode"] as? String { XCTAssertEqual(cfg.wireMode, v, "case '\(name)': mode") }
            if let v = e["server_key"] as? String {
                // "" in the fixture means "unpinned"; Swift models that as nil.
                XCTAssertEqual(cfg.serverPublicKeyHex ?? "", v, "case '\(name)': server_key")
            }
            if e.index(forKey: "sni") != nil {
                assertOptional(e["sni"], cfg.sni, "case '\(name)': sni")
            }
            if e.index(forKey: "reality_sid") != nil {
                assertOptional(e["reality_sid"], cfg.realityShortID, "case '\(name)': reality_sid")
            }
            if e.index(forKey: "obfs_key") != nil {
                // An absent obfs key is "" here, not nil.
                assertOptional(e["obfs_key"], cfg.obfsKey.isEmpty ? nil : cfg.obfsKey,
                               "case '\(name)': obfs_key")
            }
            if let v = e["quic"] as? Bool { XCTAssertEqual(cfg.quicEnabled, v, "case '\(name)': quic") }
            if let v = e["awg"] as? Bool { XCTAssertEqual(cfg.awgEnabled, v, "case '\(name)': awg") }
            if let v = e["jc"] as? Int { XCTAssertEqual(cfg.awgJunkCount, v, "case '\(name)': jc") }
            if let v = e["jmin"] as? Int { XCTAssertEqual(cfg.awgJunkMin, v, "case '\(name)': jmin") }
            if let v = e["jmax"] as? Int { XCTAssertEqual(cfg.awgJunkMax, v, "case '\(name)': jmax") }
        }
    }

    func testRejectsEveryInvalidFixture() throws {
        let fx = try fixtures()
        let rejects = fx["reject"] as? [[String: Any]] ?? []
        XCTAssertFalse(rejects.isEmpty, "fixture file has no reject cases")

        for c in rejects {
            let name = c["name"] as? String ?? "?"
            let uri = c["uri"] as? String ?? ""
            XCTAssertThrowsError(try VPNConfig.fromQeliURI(uri),
                                 "case '\(name)': this link MUST be rejected, but it parsed: \(uri)")
        }
    }

    func testEveryValidFixtureSurvivesARoundTrip() throws {
        // Emit and re-import: the check that catches a field written into the link with
        // nothing to read it back (exactly what happened with `mtu` on Android).
        let fx = try fixtures()
        for c in fx["cases"] as? [[String: Any]] ?? [] {
            let name = c["name"] as? String ?? "?"
            let first = try VPNConfig.fromQeliURI(c["uri"] as? String ?? "")
            let again: VPNConfig
            do {
                again = try VPNConfig.fromQeliURI(first.toQeliURI())
            } catch {
                XCTFail("case '\(name)': re-emitted link does not parse: \(error)")
                continue
            }
            XCTAssertEqual(first.serverAddress, again.serverAddress, "case '\(name)': host round-trip")
            XCTAssertEqual(first.port, again.port, "case '\(name)': port round-trip")
            XCTAssertEqual(first.username, again.username, "case '\(name)': user round-trip")
            XCTAssertEqual(first.password, again.password, "case '\(name)': pass round-trip")
            XCTAssertEqual(first.protocolName, again.protocolName, "case '\(name)': proto round-trip")
            XCTAssertEqual(first.wireMode, again.wireMode, "case '\(name)': mode round-trip")
            XCTAssertEqual(first.serverPublicKeyHex, again.serverPublicKeyHex, "case '\(name)': key round-trip")
            XCTAssertEqual(first.sni, again.sni, "case '\(name)': sni round-trip")
            XCTAssertEqual(first.realityShortID, again.realityShortID, "case '\(name)': rsid round-trip")
            XCTAssertEqual(first.obfsKey, again.obfsKey, "case '\(name)': obfs round-trip")
            XCTAssertEqual(first.quicEnabled, again.quicEnabled, "case '\(name)': quic round-trip")
            XCTAssertEqual(first.awgEnabled, again.awgEnabled, "case '\(name)': awg round-trip")
        }
    }

    /// Fixture value that may be JSON null, meaning "absent". Treats nil and "" alike:
    /// the platforms differ in which they use, and that is not a protocol divergence.
    private func assertOptional(_ expected: Any?, _ actual: String?, _ message: String) {
        let want = expected as? String
        if want == nil || want!.isEmpty {
            XCTAssertTrue(actual == nil || actual!.isEmpty, "\(message): expected absent, got \(actual ?? "nil")")
        } else {
            XCTAssertEqual(actual, want, message)
        }
    }
}
