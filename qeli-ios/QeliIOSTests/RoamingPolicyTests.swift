import XCTest
@testable import QeliIOS

final class RoamingPolicyTests: XCTestCase {
    func testOrdinaryTCPAndEveryUDPCamouflageModeShareEligibility() {
        let profiles: [(String, String, Bool)] = [
            ("tcp", "fake-tls", false),
            ("tcp", "plain", false),
            ("udp", "fake-tls", false),
            ("udp", "fake-tls", true),
            ("udp", "obfs", false),
        ]
        for (proto, mode, quic) in profiles {
            var config = VPNConfig(serverAddress: "198.51.100.10", port: 443)
            config.protocolName = proto
            config.wireMode = mode
            config.quicEnabled = quic
            XCTAssertTrue(config.allowsNativePathRoaming, "\(proto)/\(mode)/quic=\(quic)")
        }
    }

    func testExplicitSourceContractRetainsReconnectFallback() {
        var local = VPNConfig(serverAddress: "198.51.100.10", port: 443)
        local.carriedKeys["local"] = "192.0.2.10"
        XCTAssertFalse(local.allowsNativePathRoaming)

        var port = VPNConfig(serverAddress: "198.51.100.10", port: 443)
        port.carriedKeys["lport"] = "41000"
        XCTAssertFalse(port.allowsNativePathRoaming)

        var automatic = VPNConfig(serverAddress: "198.51.100.10", port: 443)
        automatic.carriedKeys["lport"] = "0"
        XCTAssertTrue(automatic.allowsNativePathRoaming)
    }

    func testPolicyRoundTripAndRequiredSourcePins() throws {
        var disabled = VPNConfig(serverAddress: "198.51.100.10", port: 443)
        disabled.roamingPolicy = "off"
        XCTAssertFalse(disabled.allowsNativePathRoaming)
        let disabledBack = try VPNConfig(parsing: disabled.toINI())
        XCTAssertEqual(disabledBack.roamingPolicy, "off")
        XCTAssertFalse(disabledBack.allowsNativePathRoaming)

        var required = VPNConfig(serverAddress: "198.51.100.10", port: 443)
        required.roamingPolicy = "required"
        XCTAssertNoThrow(try required.toINI())
        XCTAssertEqual(try VPNConfig(parsing: required.toINI()).roamingPolicy, "required")

        required.carriedKeys["local"] = "192.0.2.10"
        XCTAssertThrowsError(try required.toINI())
        required.carriedKeys.removeValue(forKey: "local")
        required.carriedKeys["lport"] = "41000"
        XCTAssertThrowsError(try required.toINI())
    }

    func testPathContractRejectsMismatchedFamiliesAndUnknownCommandFields() throws {
        let update = QeliPathUpdate(
            generation: 7,
            updateID: 1,
            platformPathID: "ios:en0:4",
            reason: "network_changed",
            networkToken: "en0:4",
            interfaceIndex: 4,
            localAddresses: ["192.0.2.10"],
            resolvedAddresses: [QeliPathResolution(address: "2001:db8::1", ttlSeconds: 60)],
            flags: QeliPathFlags(
                defaultRouteChanged: false, wake: false, sameNetworkNatFailure: false)
        )
        XCTAssertThrowsError(try QeliRoamingPath.encode(update))

        let payload = """
        {"generation":7,"candidate_id":1,"action":"prepare_path","path":{},"extra":true}
        """
        let event = QeliTransportEvent(
            kind: 6, state: 3, payloadFormat: 1, sequence: 1,
            planGeneration: 7, errorCode: 0, payload: payload)
        XCTAssertThrowsError(try QeliRoamingPath.decodeCommand(event))
    }
}
