import XCTest
@testable import Qeli

final class VPNConfigTests: XCTestCase {
    func testINIRoundTripPreservesAndroidFields() throws {
        let source = """
        # Moscow
        [qeli]
        server = vpn.example.com:8443
        proto = udp
        user = alice
        pass = s3cret
        mode = obfs
        obfs_key = cover-key
        quic = true
        awg = true
        jc = 4
        jmin = 50
        jmax = 250
        gateway = false
        include = 10.20.0.0/16,192.0.2.0/24
        exclude = 192.168.0.0/16
        apps_mode = exclude
        apps = com.example.one,com.example.two
        """

        let first = try VPNConfig(parsing: source)
        let second = try VPNConfig(parsing: first.toINI(label: "Moscow"))

        XCTAssertEqual(first, second)
        XCTAssertTrue(second.quicEnabled)
        XCTAssertEqual(second.appsMode, "exclude")
        XCTAssertEqual(second.apps, ["com.example.one", "com.example.two"])
    }

    func testQeliLinkRoundTripAndUnicodeLabel() throws {
        var config = VPNConfig(serverAddress: "2001:db8::1", port: 443)
        config.username = "alice@example"
        config.password = "p@ss word"
        config.serverPublicKeyHex = String(repeating: "ab", count: 32)
        config.wireMode = "reality-tls"
        config.sni = "www.microsoft.com"
        config.realityShortID = "0123456789abcdef"
        config.mtu = 1320

        let link = config.toQeliURI(label: "Телефон")
        let decoded = try VPNConfig(parsing: link)

        XCTAssertEqual(decoded.serverAddress, config.serverAddress)
        XCTAssertEqual(decoded.port, config.port)
        XCTAssertEqual(decoded.username, config.username)
        XCTAssertEqual(decoded.password, config.password)
        XCTAssertEqual(decoded.serverPublicKeyHex, config.serverPublicKeyHex)
        XCTAssertEqual(decoded.realityShortID, config.realityShortID)
        XCTAssertEqual(decoded.mtu, 1320)
        XCTAssertEqual(VPNConfig.label(fromQeliURI: link), "Телефон")
    }

    func testRejectsInvalidPortAndMode() {
        XCTAssertThrowsError(try VPNConfig(parsing: "[qeli]\nserver = host:0"))
        XCTAssertThrowsError(try VPNConfig(parsing: "[qeli]\nserver = host:443\nmode = unknown"))
    }

    func testRejectsQeliLinkNewlineInjection() {
        let malicious = "qeli://alice:p%0Aserver%20%3D%20evil.example:443@vpn.example.com:443?proto=tcp&mode=plain"
        XCTAssertThrowsError(try VPNConfig(parsing: malicious))
    }

    func testCanonicalNativeBoundaryPreservesSemanticsAndForeignKeys() throws {
        let source = """
        [qeli]
        server = vpn.example.com:443
        timeout = 47
        dns = 1.1.1.1
        dns_servers = 9.9.9.9
        padding_min = 7
        heartbeat_jitter = 2345
        shaping = true
        kill_switch = true
        local = 192.0.2.7
        lport = 34567
        name = portable-profile
        allow_unpinned_tofu = true
        """
        let config = try VPNConfig(parsing: source)
        XCTAssertEqual(config.dnsServers, ["9.9.9.9"], "canonical dns_servers wins")
        XCTAssertTrue(config.allowUnpinnedTofu)

        let portable = try config.toINI()
        let back = try VPNConfig(parsing: portable)
        for key in ["kill_switch", "local", "lport", "name"] {
            XCTAssertEqual(back.carriedKeys[key], config.carriedKeys[key])
        }
        XCTAssertTrue(portable.contains("gateway = true"))
        XCTAssertTrue(portable.contains("dns_servers = 9.9.9.9"))
        XCTAssertTrue(portable.contains("padding = true"))
        XCTAssertTrue(portable.contains("allow_unpinned_tofu = true"))

        let native = try config.toTransportCoreINI()
        XCTAssertFalse(native.contains("kill_switch = true"))
        XCTAssertTrue(native.contains("gateway = true"))
        XCTAssertFalse(try VPNConfig(parsing: "[qeli]\nserver = vpn.example.com:443\n").allowUnpinnedTofu)
    }
}
