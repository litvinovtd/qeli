import XCTest
@testable import Qeli

final class ServerIdentityPolicyTests: XCTestCase {
    func testTransportScopesAndIPv6() throws {
        XCTAssertEqual(try ServerIdentityPolicy.endpointID(protocolName: "tcp", host: "vpn", port: 443), "tcp://vpn:443")
        XCTAssertEqual(try ServerIdentityPolicy.endpointID(protocolName: "udp", host: "vpn", port: 443), "udp://vpn:443")
        XCTAssertEqual(try ServerIdentityPolicy.endpointID(protocolName: "udp", host: "2001:db8::1", port: 443), "udp://[2001:db8::1]:443")
        XCTAssertEqual(ServerIdentityPolicy.legacyID("udp://[2001:db8::1]:443"), "2001:db8::1:443")
    }

    func testOldCoreEventsAreScopedButForeignEndpointsAreRefused() throws {
        XCTAssertEqual(try ServerIdentityPolicy.storageID(eventID: "vpn:443", protocolName: "tcp", host: "vpn", port: 443), "tcp://vpn:443")
        XCTAssertEqual(try ServerIdentityPolicy.storageID(eventID: "tcp://vpn:443", protocolName: "tcp", host: "vpn", port: 443), "tcp://vpn:443")
        XCTAssertThrowsError(try ServerIdentityPolicy.storageID(eventID: "udp://vpn:443", protocolName: "tcp", host: "vpn", port: 443))
        XCTAssertThrowsError(try ServerIdentityPolicy.storageID(eventID: "tcp://other:443", protocolName: "tcp", host: "vpn", port: 443))
        XCTAssertTrue(ServerIdentityPolicy.isKeyMismatch("REALITY authentication failed: SERVER KEY MISMATCH"))
        XCTAssertFalse(ServerIdentityPolicy.isKeyMismatch("transport disconnected"))
    }
}
