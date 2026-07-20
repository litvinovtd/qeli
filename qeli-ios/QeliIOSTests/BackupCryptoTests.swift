import XCTest
@testable import Qeli

final class BackupCryptoTests: XCTestCase {
    func testPBKDF2SHA256Vectors() {
        let first = BackupCrypto.pbkdf2SHA256(
            password: Data("password".utf8),
            salt: Data("salt".utf8),
            iterations: 1,
            outputLength: 32
        )
        let second = BackupCrypto.pbkdf2SHA256(
            password: Data("password".utf8),
            salt: Data("salt".utf8),
            iterations: 2,
            outputLength: 32
        )
        XCTAssertEqual(first.hex, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        XCTAssertEqual(second.hex, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
    }

    func testDecryptsAndroidCompatibleEnvelope() throws {
        let envelope = Data("""
        QELI-ENC-1
        2
        AAECAwQFBgcICQoLDA0ODw==
        AAECAwQFBgcICQoL
        eNrd+RktljXA08fiNH2BKjsnZlt8
        """.utf8)
        XCTAssertEqual(try BackupCrypto.decrypt(envelope, passphrase: "password"), Data("hello".utf8))
        XCTAssertThrowsError(try BackupCrypto.decrypt(envelope, passphrase: "wrong"))
    }

    func testRejectsUnboundedIterationCountBeforeDerivation() {
        let envelope = Data("""
        QELI-ENC-1
        2147483647
        AAECAwQFBgcICQoLDA0ODw==
        AAECAwQFBgcICQoL
        eNrd+RktljXA08fiNH2BKjsnZlt8
        """.utf8)
        XCTAssertThrowsError(try BackupCrypto.decrypt(envelope, passphrase: "password"))
    }
}

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
