import XCTest
@testable import Qeli

/// Config values that used to be resolved SILENTLY instead of reported.
///
/// The pattern each of these guards is the same, and it is the one the cross-port audits keep
/// finding: parsing never fails, so a config the user plainly did not mean still connects —
/// with a security setting off, or to a different server than the one the file names. Parsing
/// must still SUCCEED (an editor has to be able to open a bad profile in order to fix it);
/// ``VPNConfig/validate()`` is what refuses. Same split as the Kotlin, C# and Rust ports.
final class ConfigHardeningTests: XCTestCase {

    func testAuthCredentialBudgetMatchesRustWireContract() {
        XCTAssertEqual(VPNConfig.authCredentialBudget, UDPFragmentation.maxChunk - (32 + 17))
    }

    private func ini(_ extra: String...) -> String {
        var out = "[qeli]\nserver = vpn.example.com:443\nuser = alice\npass = secret\n"
        for line in extra { out += line + "\n" }
        return out
    }

    /// `dns` is a MODE in the Rust client and a resolver LIST here — the same key, two meanings.
    ///
    /// Legacy profiles overloaded the key. The mode has to be kept separately from the
    /// resolver list and survive a round-trip so `dns = off` continues to mean LEAVE MY
    /// RESOLVER ALONE.
    /// (Audit 2026-08-02, §3.)
    func testDNSModeSurvivesImportAndRoundTrip() throws {
        for mode in ["off", "system"] {
            let c = try VPNConfig.fromINI(ini("dns = \(mode)"))
            XCTAssertEqual(c.dnsMode, mode)
            XCTAssertTrue(c.dnsServers.isEmpty, "a mode is not a resolver list")
            XCTAssertEqual(try VPNConfig.fromINI(c.toINI()).dnsMode, mode,
                           "re-saving must not lose the mode")
        }

        // The list form is unchanged and defaults to the tunnel mode.
        let list = try VPNConfig.fromINI(ini("dns = 10.0.0.1, 10.0.0.2"))
        XCTAssertEqual(list.dnsMode, "tunnel")
        XCTAssertEqual(list.dnsServers, ["10.0.0.1", "10.0.0.2"])
        XCTAssertEqual(try VPNConfig.fromINI(list.toINI()).dnsServers, ["10.0.0.1", "10.0.0.2"])

        // Absent: today's behaviour, the tunnel mode with no explicit servers.
        let none = try VPNConfig.fromINI(ini())
        XCTAssertEqual(none.dnsMode, "tunnel")
        XCTAssertTrue(none.dnsServers.isEmpty)
    }

    /// A misspelled key name must be refused — but a key another PORT owns must not be.
    ///
    /// Nothing reads a typo, so the setting it was meant to change silently keeps its default:
    /// `gatway = true` left the tunnel split with nothing said. The trap is over-correcting:
    /// `keepalive`, `post_up`, `exit_node` and friends are real Rust-client file-only keys
    /// (docs/ru/manuals/CONFIG.md, "Что пушем НЕ передаётся"), and refusing a CLI profile carrying
    /// them would be a worse regression than the typo it catches. (Audit 2026-08-01, §14.)
    func testAMisspelledKeyIsRefusedButAnotherPortsKeyIsNot() throws {
        let typo = try VPNConfig.fromINI(ini("gatway = true"))
        XCTAssertTrue(typo.unknownKeys.contains("gatway"), "the typo must be recorded")
        XCTAssertThrowsError(try typo.validate()) { error in
            XCTAssertTrue("\(error)".contains("gatway"), "message must name the key: \(error)")
        }

        // Keys this port does not read but the Rust client does — must open cleanly.
        for k in ["keepalive = 25", "post_up = /bin/true", "exit_node = true",
                  "lan_subnet = 10.0.0.0/24", "tcp_nodelay = true", "autostart = true"] {
            let c = try VPNConfig.fromINI(ini(k))
            XCTAssertTrue(c.unknownKeys.isEmpty, "\(k) must not be treated as a typo")
            XCTAssertNoThrow(try c.validate())
        }

        // The strongest guard against a wrong list: everything this port WRITES must be
        // something it accepts back, or the client would refuse its own saved profile.
        let full = try VPNConfig.fromINI(ini("mtu = 1400", "quic = true", "front = none"))
        XCTAssertTrue(try VPNConfig.fromINI(full.toINI()).unknownKeys.isEmpty)
    }

    /// A number that is present but unreadable must be refused, not replaced by the default.
    ///
    /// `server`'s port has always thrown here, which is why the worst case never bit this port —
    /// but every other numeric key fell back in silence, so `padding_min = abc` quietly became
    /// 0. The C# port had it worse (`server = host:notnum` became `host:443`, a different
    /// server), and all four must now agree. (Audit 2026-08-01, §P2.)
    func testAnUnreadableNumberIsRefusedNotReplacedByTheDefault() throws {
        let cfg = try VPNConfig.fromINI(ini("padding_min = abc"))
        XCTAssertTrue(cfg.unparsedNumericKeys.contains("padding_min"),
                      "the bad number must be recorded, got \(cfg.unparsedNumericKeys)")
        XCTAssertThrowsError(try cfg.validate()) { error in
            XCTAssertTrue("\(error)".contains("padding_min"), "message must name the key: \(error)")
        }

        // EVERY numeric field, not just padding: `mtu = abc` used to become auto-MTU, a
        // mistyped timeout became 30 s, a mistyped AWG knob became its default — each one a
        // setting the operator chose and did not get. (Audit 2026-08-01, §8.)
        for key in ["mtu", "timeout", "jc", "jmin", "jmax", "reconnect_retries",
                    "reconnect_base_delay", "reconnect_max_delay", "heartbeat_interval",
                    "heartbeat_size", "heartbeat_jitter", "shaping_gap_mean", "shaping_budget",
                    "shaping_min_size", "shaping_max_size", "shaping_stealth_mbps"] {
            let c = try VPNConfig.fromINI(ini("\(key) = abc"))
            XCTAssertTrue(c.unparsedNumericKeys.contains(key),
                          "\(key): an unreadable value must be recorded")
        }

        // An ABSENT key keeps its default silently — that is what a default is for.
        XCTAssertTrue(try VPNConfig.fromINI(ini()).unparsedNumericKeys.isEmpty)
        // ...and a readable one records nothing, so the check above cannot pass vacuously.
        let good = try VPNConfig.fromINI(ini("padding_min = 10", "padding_max = 200"))
        XCTAssertTrue(good.unparsedNumericKeys.isEmpty)
        XCTAssertNoThrow(try good.validate())

        // The port was already strict and must stay that way — an outright throw, not a record.
        XCTAssertThrowsError(try VPNConfig.fromINI("[qeli]\nserver = 1.2.3.4:notnum\n"))
    }

    func testInvertedShapingRangesAndInsufficientBudgetAreRefused() throws {
        let invalid = [
            ["shaping_gap_min = 500", "shaping_gap_max = 100"],
            ["shaping_min_size = 900", "shaping_max_size = 300"],
            ["shaping = true", "shaping_budget = 200", "shaping_max_size = 300"],
        ]
        for lines in invalid {
            let config = try VPNConfig.fromINI(ini(
                lines[0], lines[1], lines.count > 2 ? lines[2] : ""))
            XCTAssertThrowsError(try config.validate(), "\(lines) must be refused")
        }

        let valid = try VPNConfig.fromINI(ini(
            "shaping = true",
            "shaping_gap_min = 40",
            "shaping_gap_max = 6000",
            "shaping_budget = 1024",
            "shaping_min_size = 64",
            "shaping_max_size = 1024"
        ))
        XCTAssertNoThrow(try valid.validate())
    }

    /// A key written twice must be refused, not silently resolved.
    ///
    /// The ports disagreed on which line wins: this parser folds entries into a dictionary and
    /// keeps the LAST, while the Rust client (`config/format.rs` `Section::get`) takes the
    /// FIRST. Two `server` lines therefore sent the Rust client to one host and every GUI
    /// client to another, out of one file, with nothing reported anywhere.
    /// (Audit 2026-08-01, §7.)
    func testAKeyWrittenTwiceIsRefusedNotSilentlyResolved() throws {
        let dup = try VPNConfig.fromINI(ini("server = other.example.com:8443"))
        XCTAssertTrue(dup.duplicateKeys.contains("qeli.server"),
                      "the duplicate must be recorded, got \(dup.duplicateKeys)")
        XCTAssertThrowsError(try dup.validate()) { error in
            // The message must name the key, so this cannot pass because validate() happened
            // to dislike something else about the fixture.
            XCTAssertTrue("\(error)".contains("qeli.server"), "message must name the key: \(error)")
        }

        // Duplicates are found per SECTION — the same key name in two different sections is not
        // a duplicate, and a clean file must stay clean. Without this the check above would
        // pass just as well against a parser that flagged everything.
        let clean = try VPNConfig.fromINI(ini("mtu = 1400") + "[logging]\nlevel = debug\n")
        XCTAssertTrue(clean.duplicateKeys.isEmpty, "clean config recorded \(clean.duplicateKeys)")
        XCTAssertNoThrow(try clean.validate())

        // Recorded ONCE however many times the key repeats, and the last value still wins, so a
        // file that already had a duplicate parses exactly as it always did.
        let thrice = try VPNConfig.fromINI(ini("mtu = 1400", "mtu = 1300", "mtu = 1200"))
        XCTAssertEqual(thrice.duplicateKeys, ["qeli.mtu"])
        XCTAssertEqual(thrice.mtu, 1200)
    }

    func testRepeatedRouteFilesAreAdditiveAndSurviveRoundTrip() throws {
        let config = try VPNConfig.fromINI(ini(
            "route_file = /tmp/cidrs.txt", "route_file = /tmp/openvpn.txt"))
        XCTAssertEqual(config.routeFiles, ["/tmp/cidrs.txt", "/tmp/openvpn.txt"])
        XCTAssertFalse(config.duplicateKeys.contains("qeli.route_file"))

        let roundTrip = try VPNConfig.fromINI(config.toINI())
        XCTAssertEqual(roundTrip.routeFiles, config.routeFiles)
    }

    /// A boolean nobody could parse must not read as `false`.
    ///
    /// Every unknown value used to be falsey, so `bind_static = ture` silently dropped the
    /// static-key binding and `gateway = ture` silently turned a full tunnel into a split one —
    /// a security downgrade with no message anywhere, and unrecoverable after parse because the
    /// original string is gone. (Audit 2026-07-31.)
    func testATypoInABooleanIsRefusedNotReadAsFalse() throws {
        for key in ["gateway", "bind_static", "reconnect", "padding", "heartbeat", "quic"] {
            let cfg = try VPNConfig.fromINI(ini("\(key) = ture"))
            XCTAssertTrue(cfg.unparsedBooleanKeys.contains(key), "\(key): the typo must be recorded")
            XCTAssertThrowsError(try cfg.validate(), "\(key): validate() must refuse") { error in
                XCTAssertTrue("\(error)".contains(key), "message must name \(key): \(error)")
            }
        }

        // A typo must NOT be resolved to the falsey reading it used to get.
        XCTAssertTrue(try VPNConfig.fromINI(ini("gateway = ture")).isFullTunnel,
                      "gateway = ture must not silently become split-tunnel")
        XCTAssertTrue(try VPNConfig.fromINI(ini("bind_static = ture")).bindStaticToSession,
                      "bind_static = ture must not silently disable key binding")

        // Every spelling the Rust client accepts must still work, both ways, and leave the
        // config valid.
        for yes in ["true", "1", "yes", "on", "TRUE", "On"] {
            let c = try VPNConfig.fromINI(ini("quic = \(yes)"))
            XCTAssertTrue(c.quicEnabled, "\(yes) must be true")
            XCTAssertTrue(c.unparsedBooleanKeys.isEmpty)
        }
        for no in ["false", "0", "no", "off", "FALSE", "Off"] {
            let c = try VPNConfig.fromINI(ini("quic = \(no)"))
            XCTAssertFalse(c.quicEnabled, "\(no) must be false")
            XCTAssertTrue(c.unparsedBooleanKeys.isEmpty)
        }
    }

    func testIncludeAndExcludeRequireStrictCIDRLiterals() throws {
        for bad in ["vpn.example.com/24", "10.0.0.1/33", "2001:db8::/129"] {
            var config = try VPNConfig.fromINI(ini())
            config.includeRoutes = [bad]
            XCTAssertThrowsError(try config.validate(), "must refuse \(bad)")
        }
        var valid = try VPNConfig.fromINI(ini())
        valid.includeRoutes = ["10.0.0.0/8"]
        valid.excludeRoutes = ["2001:db8::/32"]
        XCTAssertNoThrow(try valid.validate())
    }

    func testProfileArchiveRegeneratesDuplicateIdentifiers() throws {
        let repeatedID = UUID()
        let first = Profile(id: repeatedID, name: "first", configText: ini())
        let second = Profile(id: repeatedID, name: "second", configText: ini())
        var archive = ProfileArchive(activeProfileID: repeatedID, profiles: [first, second])

        archive.normalize()

        XCTAssertEqual(Set(archive.profiles.map(\.id)).count, 2)
        XCTAssertEqual(archive.activeProfileID, archive.profiles[0].id)
        XCTAssertNoThrow(try ProfileStore.validate(archive))
    }

    func testProfileArchiveLimitsAreEnforcedBeforePersistence() throws {
        let profile = Profile(name: "profile", configText: ini())
        let tooMany = ProfileArchive(
            activeProfileID: profile.id,
            profiles: (0...ProfileStore.maximumProfiles).map { index in
                Profile(name: "profile-\(index)", configText: ini())
            }
        )
        XCTAssertThrowsError(try ProfileStore.validate(tooMany)) { error in
            guard let storeError = error as? ProfileStoreError,
                  case .tooManyProfiles = storeError else {
                return XCTFail("unexpected error: \(error)")
            }
        }

        let oversized = Profile(
            name: "oversized",
            configText: String(repeating: "#", count: ProfileStore.maximumConfigBytes + 1)
        )
        XCTAssertThrowsError(try ProfileStore.validate(
            ProfileArchive(activeProfileID: oversized.id, profiles: [oversized])
        )) { error in
            guard let storeError = error as? ProfileStoreError,
                  case .profileTooLarge(1) = storeError else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }
}
