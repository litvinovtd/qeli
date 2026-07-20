import XCTest
@testable import Qeli

final class ProtocolPrimitiveTests: XCTestCase {
    func testPacketCodecTLSRoundTripAndReplayRejection() throws {
        let key = Data(repeating: 0x42, count: 32)
        let encoder = PacketCodec(cipher: try PacketCipher(key: key), paddingMin: 7, paddingMax: 7)
        let decoder = PacketCodec(cipher: try PacketCipher(key: key), paddingMin: 7, paddingMax: 7)
        let plaintext = Data("hello packet".utf8)
        let record = try encoder.encrypt(plaintext)

        XCTAssertEqual(try decoder.decrypt(record), plaintext)
        XCTAssertThrowsError(try decoder.decrypt(record))
    }

    func testPacketCodecRawRoundTrip() throws {
        let key = Data(repeating: 0x24, count: 32)
        let encoder = PacketCodec(cipher: try PacketCipher(key: key), paddingEnabled: false, rawFraming: true)
        let decoder = PacketCodec(cipher: try PacketCipher(key: key), paddingEnabled: false, rawFraming: true)
        let record = try encoder.encrypt(Data([1, 2, 3, 4]))
        XCTAssertEqual(try decoder.decrypt(record), Data([1, 2, 3, 4]))
    }

    func testUDPFragmentationReassemblesOutOfOrder() throws {
        let message = Data((0..<4_000).map { UInt8($0 & 0xff) })
        let fragments = try UDPFragmentation.fragment(messageID: UDPFragmentation.clientHello, message: message)
        let reassembler = UDPFragmentation.Reassembler()
        var output: Data?
        for fragment in fragments.reversed() { output = try reassembler.push(fragment) ?? output }
        XCTAssertEqual(output, message)
    }

    func testQUICMaskRoundTrip() throws {
        let connectionID = Data([1, 2, 3, 4])
        let payload = Data("qeli".utf8)
        XCTAssertEqual(
            QUICMask.unwrap(try QUICMask.wrapLong(payload, connectionID: connectionID, packetNumber: 7, packetType: 0)),
            payload
        )
        XCTAssertEqual(
            QUICMask.unwrap(try QUICMask.wrapShort(payload, connectionID: connectionID, packetNumber: 8)),
            payload
        )
    }
}
