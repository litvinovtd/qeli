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
        // Bare IPv4 UDP over a 48-byte record: floor = 1280 - (48+8+20) = 1204.
        let plain = UDPPathMTUProbePolicy(ceiling: 1_400, outerOverhead: 48 + 8 + 20)
        XCTAssertEqual(plain.candidates, [1_400, 1_360, 1_320, 1_280, 1_204])
        XCTAssertEqual(plain.outerProbeSize(for: 1_360), 1_408)
        XCTAssertTrue(plain.accepts(.mtuProbeAck(id: 7, outerSize: 1_408), id: 7))
        XCTAssertFalse(plain.accepts(.mtuProbeAck(id: 8, outerSize: 1_408), id: 7))
    }

    /// The #12 defect: rungs are INNER tunnel MTUs, 1280 is an OUTER path limit. A floor pinned
    /// to 1280 asked a 1280-byte path for 1280 + overhead bytes, so every rung failed on exactly
    /// the narrow paths probing exists for and the caller silently kept the pushed MTU.
    func testLadderFloorFitsTheIPv6MinimumPath() {
        for overhead in [48 + 8 + 20, 48 + 13 + 9 + 8 + 40] {
            let policy = UDPPathMTUProbePolicy(ceiling: 1_400, outerOverhead: overhead)
            let rungs = policy.candidates
            XCTAssertFalse(rungs.isEmpty, "ladder must not be empty (overhead \(overhead))")
            guard let lowest = rungs.last else { continue }
            XCTAssertLessThanOrEqual(lowest + overhead, 1_280,
                                     "lowest rung's wire size must fit a 1280-byte path")
            XCTAssertEqual(rungs, rungs.sorted(by: >), "rungs must be strictly descending")
            XCTAssertEqual(rungs.count, Set(rungs).count, "rungs must be deduped")
        }

        // A ceiling already below the floor must still yield something to try, not an empty
        // ladder (which reports "no result" and silently keeps the pushed MTU).
        let tiny = UDPPathMTUProbePolicy(ceiling: 700, outerOverhead: 48 + 13 + 9 + 8 + 40)
        XCTAssertFalse(tiny.candidates.isEmpty, "a low ceiling still produces a rung")
        XCTAssertLessThanOrEqual(tiny.candidates.first ?? .max, 700)
    }

    /// A JUMBO ceiling must not fall straight to 1360.
    ///
    /// The ladder was written when the ceiling was an Ethernet-sized number, so the rung below
    /// it was 1360 and the gap was 140 bytes. Raising to the record-sized ceiling made that gap
    /// into 15278: a path carrying 9000 — an ordinary jumbo LAN, and precisely the setup where
    /// someone configures a large MTU — the ceiling failed, and the path was certified at 1360.
    /// (Audit 2026-08-01, §8.)
    func testAJumboCeilingHasRungsBetweenItAnd1360() {
        let overhead = 48 + 13 + 9 + 8 + 40
        let rungs = UDPPathMTUProbePolicy(ceiling: 16_638, outerOverhead: overhead).candidates
        XCTAssertGreaterThanOrEqual(rungs.filter { (1_360..<16_638).contains($0) }.count, 3,
                                    "a jumbo ceiling needs intermediate rungs, got \(rungs)")
        let bestUnder9000 = rungs.first { $0 + overhead <= 9_000 } ?? 0
        XCTAssertGreaterThanOrEqual(bestUnder9000, 4_000,
                                    "a 9000-byte path certified at \(bestUnder9000)")

        // ...and a normal path is probed exactly as before, so the jumbo rungs cost no extra
        // round-trips for the common case.
        XCTAssertEqual(
            UDPPathMTUProbePolicy(ceiling: 1_400, outerOverhead: overhead).candidates,
            [1_400, 1_360, 1_320, 1_280, 1_200, 1_280 - overhead])
    }

    /// Refinement finds the path's REAL MTU, not just the best rung that fits.
    ///
    /// A ladder can only ever land on its own numbers, so adding rungs moves the loss around
    /// instead of removing it: with rungs at 9000 and 6000 an 8999-byte path was pinned to 6000
    /// and threw away a third of every frame. This drives the same search the probe loop runs,
    /// against a simulated path. (Audit 2026-08-01, §8.)
    func testRefinementConvergesOnTheRealPathMTU() {
        // `real` is what the path actually carries; a probe succeeds iff it fits.
        func search(_ lo0: Int, _ hi0: Int, real: Int) -> (result: Int, probes: Int) {
            var lo = lo0, hi = hi0, probes = 0
            for _ in 0..<UDPPathMTUProbePolicy.refineMaxProbes {
                guard let mid = UDPPathMTUProbePolicy.refineStep(lo: lo, hi: hi) else { break }
                probes += 1
                if mid <= real { lo = mid } else { hi = mid }
            }
            return (lo, probes)
        }

        for (lo0, hi0, real) in [(6_000, 9_000, 8_999), (4_000, 6_000, 5_500), (1_500, 2_500, 2_000)] {
            let (got, probes) = search(lo0, hi0, real: real)
            XCTAssertLessThanOrEqual(got, real, "must never certify above the path")
            XCTAssertLessThanOrEqual(real - got, UDPPathMTUProbePolicy.refineStepBytes,
                                     "left \(real - got) bytes on the table")
            XCTAssertGreaterThan(got, lo0, "refinement must beat the coarse rung \(lo0)")
            XCTAssertLessThanOrEqual(probes, UDPPathMTUProbePolicy.refineMaxProbes)
        }

        // A path barely above the rung must not be made worse, and a narrow bracket must stop.
        XCTAssertNil(UDPPathMTUProbePolicy.refineStep(lo: 6_000, hi: 6_200))
        XCTAssertEqual(search(6_000, 9_000, real: 6_001).result, 6_000)
    }

    private func tlsRecord(body: Data) -> Data {
        var record = Data([0x16, 0x03, 0x03, UInt8((body.count >> 8) & 0xff), UInt8(body.count & 0xff)])
        record.append(body)
        return record
    }
}
