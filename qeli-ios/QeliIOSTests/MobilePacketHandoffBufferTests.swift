import XCTest
@testable import Qeli

final class MobilePacketHandoffBufferTests: XCTestCase {
    private func ipv4Packet(protocolNumber: UInt8, size: Int = 40) -> Data {
        var packet = Data(repeating: 0, count: size)
        packet[0] = 0x45
        packet[9] = protocolNumber
        return packet
    }

    func testTCPOutlivesShortUDPReplayWindow() {
        var buffer = MobilePacketHandoffBuffer()
        let tcp = ipv4Packet(protocolNumber: 6)
        let udp = ipv4Packet(protocolNumber: 17)
        XCTAssertEqual(
            buffer.retain([tcp, udp], continuityKey: "same", now: 100),
            .init(retained: 2, dropped: 0)
        )
        XCTAssertEqual(buffer.drain(continuityKey: "same", now: 103), [tcp])
    }

    func testChangedNetworkPlanCannotReplayOldPackets() {
        var buffer = MobilePacketHandoffBuffer()
        _ = buffer.retain([ipv4Packet(protocolNumber: 6)], continuityKey: "old", now: 10)
        XCTAssertTrue(buffer.drain(continuityKey: "new", now: 11).isEmpty)
        XCTAssertEqual(buffer.count, 0)
        XCTAssertEqual(buffer.bytes, 0)
    }

    func testPacketAndByteBoundsDropOldestEntries() {
        var buffer = MobilePacketHandoffBuffer(maximumPackets: 2, maximumBytes: 90)
        let first = ipv4Packet(protocolNumber: 6, size: 40)
        let second = ipv4Packet(protocolNumber: 6, size: 40)
        let newest = ipv4Packet(protocolNumber: 6, size: 50)
        let result = buffer.retain([first, second, newest], continuityKey: "same", now: 1)
        XCTAssertEqual(result, .init(retained: 2, dropped: 1))
        XCTAssertEqual(buffer.drain(continuityKey: "same", now: 2), [second, newest])
    }
}
