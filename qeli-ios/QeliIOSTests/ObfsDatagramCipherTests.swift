import XCTest
@testable import Qeli

final class ObfsDatagramCipherTests: XCTestCase {
    func testKeyDerivationMatchesRustLabelAndPSK() {
        XCTAssertEqual(
            ObfsDatagramCipher.deriveKey("secret").hex,
            "22ee6d412bdc10275f59aa8d714f775311274988cf8d1108f77b9460e2c798cb"
        )
    }

    func testChaCha20CounterZeroInteroperabilityVector() throws {
        let key = Data((0..<32).map { UInt8($0) })
        let nonce = try XCTUnwrap(Data(hexadecimal: "000000090000004a00000000"))
        let sealed = try ObfsDatagramCipher.seal(
            Data(repeating: 0, count: 64),
            key: key,
            nonce: nonce,
            flag: 0
        )
        XCTAssertEqual(
            Data(sealed.dropFirst(13)).hex,
            "8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582c" +
            "d9833367d0a54d57d3c9e998f490ee69ca34c1ff9e939a75584c52d690a35d4"
        )
    }

    func testDatagramRoundTrip() throws {
        let key = ObfsDatagramCipher.deriveKey("round-trip")
        let plaintext = Data((0..<2_048).map { UInt8($0 & 0xff) })
        let datagram = try ObfsDatagramCipher.seal(plaintext, key: key)
        XCTAssertEqual(datagram[0] & 0xc0, 0x40)
        XCTAssertEqual(try ObfsDatagramCipher.open(datagram, key: key), plaintext)
    }
}

private extension Data {
    init?(hexadecimal: String) {
        guard hexadecimal.count.isMultiple(of: 2), hexadecimal.allSatisfy(\.isHexDigit) else { return nil }
        self.init(); reserveCapacity(hexadecimal.count / 2)
        var index = hexadecimal.startIndex
        while index < hexadecimal.endIndex {
            let next = hexadecimal.index(index, offsetBy: 2)
            guard let byte = UInt8(String(hexadecimal[index..<next]), radix: 16) else { return nil }
            append(byte); index = next
        }
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
