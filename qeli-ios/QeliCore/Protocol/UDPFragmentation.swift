import Foundation
import Security
@testable import QeliIOS

enum UDPFragmentation {
    static let magic: [UInt8] = [0xf0, 0x9b, 0x71]
    static let headerLength = 6

    /// IPv6 minimum link MTU (RFC 8200 §5) — the narrowest path the handshake must survive.
    static let ipv6MinMTU = 1_280
    // Worst-case outer headers around one fragment, inside out. Emitted sizes, not protocol
    // minimums: an IPv6 + obfs + QUIC-masked fragment really carries all of them at once.
    private static let outerQUIC = 1 + 4 + 1 + 4 + 1 + 1 + 2 + 4  // QUIC long header (Quic.wrapLong)
    private static let outerObfsSeal = 1 + 12                     // obfs flag byte + nonce
    private static let outerUDP = 8
    private static let outerIPv6 = 40
    // Headroom so adding one more outer layer cannot silently push the handshake back over
    // ipv6MinMTU — the exact regression the old hard-coded 1200 was.
    private static let outerReserve = 32

    /// Max payload bytes per fragment. **Derived**, not chosen: chunk + header + QUIC long
    /// header + obfs seal + UDP + IPv6 must fit ``ipv6MinMTU``.
    ///
    /// This was 1200 — QUIC's initial-packet floor, which budgets a whole datagram, not the
    /// payload inside four more layers. The handshake wraps each fragment in a QUIC **long**
    /// header (18 B; the data plane's short header is only 9 B), so the real worst case was
    /// 1200 + 6 + 18 + 13 + 8 + 40 = 1285 — five bytes over the IPv6 minimum, i.e. the PQ
    /// handshake could not complete on a 1280-MTU IPv6 path with obfs + QUIC masking on.
    ///
    /// This bounds only what we **emit**; ``maxChunkAccept`` bounds what we accept. Keeping the
    /// two separate is what makes the change compatible in both directions — see there.
    /// (Audit 2026-07-30, #14.)
    static let maxChunk =
        ipv6MinMTU - outerIPv6 - outerUDP - outerObfsSeal - outerQUIC - outerReserve - headerLength

    /// Largest chunk we **accept**, pinned to the historical 1200 that every build before the
    /// #14 fix emitted.
    ///
    /// Reassembly is size-agnostic — fragments are placed by index, with no offset or
    /// per-fragment length field — so the only thing a receiver does with a chunk size is bound
    /// it from above for anti-DoS. Shrinking ``maxChunk`` keeps our fragments readable by any
    /// peer; but shrinking the accept bound with it would have rejected every fragment from a
    /// pre-fix peer, breaking the handshake in the other direction. Must never drop below 1200.
    static let maxChunkAccept = 1_200
    static let maxFragments = 24
    static let clientHello: UInt8 = 1
    static let serverHello: UInt8 = 2
    static let junk: UInt8 = 3
    static let mtuProbe: UInt8 = 4
    static let mtuProbeAck: UInt8 = 5

    /// The **AuthOK** (server→client), fragmented for the same reason as the ServerHello.
    ///
    /// Unlike the two handshake messages this one has no fixed size: it carries the pushed
    /// route list, so a profile pushing enough routes puts it past what a fragment-dropping
    /// path (mobile, CGNAT) will carry — which is exactly the network this client runs on. The
    /// failure was indistinguishable from a dead server: the client retransmits AUTH, the
    /// network eats the reply every time, and it times out at the AUTHENTICATION step with
    /// nothing in either log to say why. (Audit 2026-08-02, §4.)
    ///
    /// The server fragments ONLY above ``maxChunk``; at or below it the AuthOK is still the
    /// single datagram it always was, byte for byte. So this changes nothing in any case that
    /// works today — fragments appear only where the reply was already being destroyed.
    ///
    /// The payload is the finished AEAD record, not plaintext: reassemble first, decrypt
    /// after. Nothing about the session cipher, the transcript or the replay window moves.
    ///
    /// There is no ambiguity against a real record, in either framing: TLS framing opens
    /// `0x17 0x03 0x03`, and raw framing opens with a UInt16 payload length bounded by
    /// MAX_RECORD_SIZE (0x4124), so its high byte is at most 0x41 — `0xF0` is unreachable both
    /// ways. Same property ``isFragment(_:)`` already relies on to tell a fragmented
    /// ClientHello from a legacy single-datagram one.
    static let authOK: UInt8 = 6
    static let probeBodyLength = 4

    static func isFragment(_ data: Data) -> Bool {
        data.count >= headerLength && Array(data.prefix(3)) == magic
    }

    static func isJunk(_ data: Data) -> Bool { isFragment(data) && data[3] == junk }
    /// True if `data` (after obfs/QUIC unwrap) is a fragment of the AuthOK.
    static func isAuthOKFragment(_ data: Data) -> Bool { isFragment(data) && data[3] == authOK }
    static func isMTUProbe(_ data: Data) -> Bool {
        isFragment(data) && data[3] == mtuProbe && data.count >= headerLength + probeBodyLength
    }
    static func isMTUProbeAck(_ data: Data) -> Bool {
        isFragment(data) && data[3] == mtuProbeAck && data.count >= headerLength + probeBodyLength
    }

    static func parseMTUProbe(_ data: Data) -> (id: Int, outerSize: Int)? {
        guard data.count >= headerLength + probeBodyLength else { return nil }
        let id = Int(data[headerLength]) | (Int(data[headerLength + 1]) << 8)
        let size = Int(data[headerLength + 2]) | (Int(data[headerLength + 3]) << 8)
        return (id, size)
    }

    static func mtuProbeDatagram(id: Int, outerSize: Int) throws -> Data? {
        let minimum = headerLength + probeBodyLength
        guard (minimum...65_535).contains(outerSize) else { return nil }
        var data = Data(repeating: 0, count: outerSize)
        writeHeader(&data, messageID: mtuProbe, index: 0, count: 1)
        writeProbeBody(&data, id: id, outerSize: outerSize)
        if outerSize > minimum {
            let paddingLength = outerSize - minimum
            var padding = Data(count: paddingLength)
            let status = padding.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, paddingLength, $0.baseAddress!)
            }
            guard status == errSecSuccess else { throw UDPFragmentationError.randomFailure(status) }
            data.replaceSubrange(minimum..<outerSize, with: padding)
        }
        return data
    }

    static func mtuProbeAckDatagram(id: Int, outerSize: Int) -> Data {
        var data = Data(repeating: 0, count: headerLength + probeBodyLength)
        writeHeader(&data, messageID: mtuProbeAck, index: 0, count: 1)
        writeProbeBody(&data, id: id, outerSize: outerSize)
        return data
    }

    static func fragment(messageID: UInt8, message: Data) throws -> [Data] {
        let count = max(1, (message.count + maxChunk - 1) / maxChunk)
        guard count <= maxFragments else { throw UDPFragmentationError.tooManyFragments(count) }
        return (0..<count).map { index in
            let start = index * maxChunk
            let end = min(message.count, start + maxChunk)
            var fragment = Data(magic + [messageID, UInt8(index), UInt8(count)])
            if start < end { fragment.append(message[start..<end]) }
            return fragment
        }
    }

    final class Reassembler {
        private var messageID: UInt8?
        private var expectedCount = 0
        private var parts: [Data?] = []

        func push(_ data: Data) throws -> Data? {
            guard UDPFragmentation.isFragment(data) else { throw UDPFragmentationError.notFragment }
            let incomingID = data[3]
            let index = Int(data[4])
            let count = Int(data[5])
            guard (1...UDPFragmentation.maxFragments).contains(count) else {
                throw UDPFragmentationError.invalidCount
            }
            guard index < count else { throw UDPFragmentationError.invalidIndex }
            // Deliberately the ACCEPT bound, not the send budget: a peer built before the
            // #14 fix emits 1200-byte chunks, and bounding by our smaller maxChunk would
            // reject every one of its handshakes.
            guard data.count - UDPFragmentation.headerLength <= UDPFragmentation.maxChunkAccept else {
                throw UDPFragmentationError.chunkTooLarge
            }
            if messageID == nil {
                messageID = incomingID
                expectedCount = count
                parts = Array(repeating: nil, count: count)
            } else if messageID != incomingID || expectedCount != count {
                throw UDPFragmentationError.inconsistentMessage
            }
            let chunk = Data(data.dropFirst(UDPFragmentation.headerLength))
            if let existing = parts[index] {
                guard existing == chunk else { throw UDPFragmentationError.conflictingDuplicate }
            } else {
                parts[index] = chunk
            }
            guard parts.allSatisfy({ $0 != nil }) else { return nil }
            return parts.compactMap { $0 }.reduce(into: Data()) { $0.append($1) }
        }
    }

    private static func writeHeader(_ data: inout Data, messageID: UInt8, index: UInt8, count: UInt8) {
        data[0] = magic[0]; data[1] = magic[1]; data[2] = magic[2]
        data[3] = messageID; data[4] = index; data[5] = count
    }

    private static func writeProbeBody(_ data: inout Data, id: Int, outerSize: Int) {
        data[headerLength] = UInt8(id & 0xff)
        data[headerLength + 1] = UInt8((id >> 8) & 0xff)
        data[headerLength + 2] = UInt8(outerSize & 0xff)
        data[headerLength + 3] = UInt8((outerSize >> 8) & 0xff)
    }
}

enum UDPFragmentationError: Error {
    case notFragment, invalidCount, invalidIndex, chunkTooLarge, inconsistentMessage
    case conflictingDuplicate
    case tooManyFragments(Int)
    case randomFailure(OSStatus)
}
