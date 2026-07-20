import XCTest
@testable import Qeli

final class UDPDataPlaneTests: XCTestCase {
    func testFragmentQUICObfsRoundTripOutOfOrder() throws {
        let key = ObfsDatagramCipher.deriveKey("udp-test")
        let sender = try UDPDatagramCodec(
            quicEnabled: true,
            connectionID: Data([1, 2, 3, 4]),
            obfsKey: key
        )
        let receiver = try UDPDatagramCodec(
            quicEnabled: true,
            connectionID: Data([1, 2, 3, 4]),
            obfsKey: key
        )
        let record = tlsRecord(body: Data((0..<4_000).map { UInt8($0 & 0xff) }))
        let datagrams = try sender.encode(record: record, longHeader: true)
        XCTAssertGreaterThan(datagrams.count, 1)

        var received: [Data] = []
        for datagram in datagrams.reversed() {
            if case .records(let records) = try receiver.ingest(datagram: datagram) { received = records }
        }
        XCTAssertEqual(received, [record])
    }

    func testBundledRecordsAreSliced() throws {
        let codec = try UDPDatagramCodec(quicEnabled: false, connectionID: Data(repeating: 0, count: 4))
        let first = tlsRecord(body: Data("one".utf8))
        let second = tlsRecord(body: Data("two".utf8))
        XCTAssertEqual(try codec.ingest(datagram: first + second), .records([first, second]))
    }

    func testAWGPreambleUsesRecognizableJunkEnvelope() throws {
        let codec = try UDPDatagramCodec(quicEnabled: false, connectionID: Data(repeating: 0, count: 4))
        let datagrams = try codec.encodeAWGJunkPreamble(count: 3, minimumSize: 40, maximumSize: 40)
        XCTAssertEqual(datagrams.count, 3)
        for datagram in datagrams {
            XCTAssertEqual(datagram.count, UDPFragmentation.headerLength + 40)
            XCTAssertEqual(try codec.ingest(datagram: datagram), .junk)
        }
    }

    func testControlDatagramDoesNotPoisonHandshakeReassembly() throws {
        let sender = try UDPDatagramCodec(
            quicEnabled: false,
            connectionID: Data(repeating: 0, count: 4)
        )
        let receiver = try UDPDatagramCodec(
            quicEnabled: false,
            connectionID: Data(repeating: 0, count: 4)
        )
        let record = tlsRecord(body: Data(repeating: 0x5a, count: 2_000))
        let fragments = try sender.encode(record: record, longHeader: true)
        XCTAssertEqual(try receiver.ingest(datagram: fragments[0]), .fragmentPending)
        let junk = try sender.encodeAWGJunkPreamble(count: 1, minimumSize: 40, maximumSize: 40)[0]
        XCTAssertEqual(try receiver.ingest(datagram: junk), .junk)
        XCTAssertEqual(try receiver.ingest(datagram: fragments[1]), .records([record]))
    }

    func testUDPDataPlaneDropsCorruptRecordButAcceptsNextPacket() throws {
        let key = Data(repeating: 0x77, count: 32)
        let encoder = PacketCodec(cipher: try PacketCipher(key: key), paddingEnabled: false)
        let decoder = PacketCodec(cipher: try PacketCipher(key: key), paddingEnabled: false)
        var ipv4 = Data(repeating: 0, count: 20)
        ipv4[0] = 0x45
        let encrypted = try XCTUnwrap(UDPDataPlane.encodeUplink(ipv4, encoder: encoder, mtu: 1_400))
        XCTAssertEqual(UDPDataPlane.decodeDownlink(encrypted, decoder: decoder), ipv4)

        var corrupt = encrypted
        corrupt[corrupt.count - 1] ^= 1
        XCTAssertNil(UDPDataPlane.decodeDownlink(corrupt, decoder: decoder))

        var nextIPv4 = ipv4
        nextIPv4[19] = 1
        let next = try XCTUnwrap(UDPDataPlane.encodeUplink(nextIPv4, encoder: encoder, mtu: 1_400))
        XCTAssertEqual(UDPDataPlane.decodeDownlink(next, decoder: decoder), nextIPv4)
        XCTAssertNil(try UDPDataPlane.encodeUplink(Data([0x60]), encoder: encoder, mtu: 1_400))
    }

    func testPathMTULadder() {
        let policy = UDPPathMTUProbePolicy(ceiling: 1_400)
        XCTAssertEqual(policy.candidates, [1_400, 1_360, 1_320, 1_280])
        XCTAssertEqual(policy.outerProbeSize(for: 1_360), 1_408)
        XCTAssertTrue(policy.accepts(.mtuProbeAck(id: 7, outerSize: 1_408), id: 7))
        XCTAssertFalse(policy.accepts(.mtuProbeAck(id: 8, outerSize: 1_408), id: 7))
    }

    private func tlsRecord(body: Data) -> Data {
        var record = Data([0x16, 0x03, 0x03, UInt8((body.count >> 8) & 0xff), UInt8(body.count & 0xff)])
        record.append(body)
        return record
    }
}
