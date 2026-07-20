import XCTest
@testable import Qeli

final class ObfsPrimitivesTests: XCTestCase {
    func testKeyDerivationMatchesSharedRustLabel() {
        XCTAssertEqual(
            QeliObfs.deriveKey("secret").map { String(format: "%02x", $0) }.joined(),
            "22ee6d412bdc10275f59aa8d714f775311274988cf8d1108f77b9460e2c798cb"
        )
    }

    func testSharedWebSocketMaskingVector() throws {
        let frame = try QeliObfs.webSocketBinaryFrame(
            payload: Data([0x01, 0x02, 0x03]),
            mask: Data([0xaa, 0xbb, 0xcc, 0xdd])
        )
        XCTAssertEqual(frame, Data([0x82, 0x83, 0xaa, 0xbb, 0xcc, 0xdd, 0xab, 0xb9, 0xcf]))
    }

    func testRFC8439ChaCha20BlockVector() throws {
        let key = Data((0x00...0x1f).map { UInt8($0) })
        let nonce = Data([0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00])
        let expected = Data([
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
            0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
            0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
        ])
        XCTAssertEqual(try QeliChaCha20Keystream.block(key: key, counter: 1, nonce: nonce), expected)
    }

    func testStreamingCallsConsumeOneContinuousKeystream() throws {
        let key = QeliObfs.deriveKey("unit-test-psk")
        let nonce = Data(repeating: 0x5a, count: 12)
        let plaintext = Data((0..<257).map { UInt8($0 & 0xff) })
        var single = try QeliChaCha20Keystream(key: key, nonce: nonce)
        let expected = single.xor(plaintext)

        var split = try QeliChaCha20Keystream(key: key, nonce: nonce)
        var actual = split.xor(Data(plaintext.prefix(13)))
        actual.append(split.xor(Data(plaintext.dropFirst(13).prefix(64))))
        actual.append(split.xor(Data(plaintext.dropFirst(77))))
        XCTAssertEqual(actual, expected)
    }

    func testUDPDatagramRoundTrip() throws {
        let key = QeliObfs.deriveKey("udp-test")
        let plaintext = Data((0..<1_400).map { UInt8($0 & 0xff) })
        let sealed = try QeliObfs.datagramSeal(key: key, payload: plaintext)
        XCTAssertEqual(sealed[0] & 0xc0, 0x40)
        XCTAssertEqual(try QeliObfs.datagramOpen(key: key, datagram: sealed), plaintext)
    }
}
