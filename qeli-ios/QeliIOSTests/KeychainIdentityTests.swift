import CryptoKit
import Foundation
import Security
import XCTest
@testable import Qeli

final class KeychainIdentityTests: XCTestCase {
    private var service = ""
    private var store: KeychainStore!

    override func setUp() {
        super.setUp()
        service = "ru.qeli.tests.identity.\(UUID().uuidString)"
        store = KeychainStore(service: service, accessGroup: nil)
    }

    override func tearDown() {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service]
        let status = SecItemDelete(query as CFDictionary)
        XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
        store = nil
        super.tearDown()
    }

    func testInsertIfAbsentReturnsFirstWriterWithoutOverwritingIt() throws {
        let first = Data(repeating: 1, count: 32)
        let later = Data(repeating: 2, count: 32)
        XCTAssertEqual(try store.insertIfAbsent(first, account: "pin"), first)
        XCTAssertEqual(try store.insertIfAbsent(later, account: "pin"), first)
        XCTAssertEqual(try store.read(account: "pin"), first)
    }

    func testDistinctIdentityReadersUseTheSamePersistedDeviceID() throws {
        let first = try SecureIdentityStore(keychain: store).deviceID()
        let second = try SecureIdentityStore(keychain: store).deviceID()
        XCTAssertEqual(first.count, 16)
        XCTAssertTrue(first.contains(where: { $0 != 0 }))
        XCTAssertEqual(second, first)
    }

    func testCorruptDeviceIdentityIsRejectedWithoutSilentRotation() throws {
        for data in [Data(), Data(repeating: 0, count: 16), Data(repeating: 1, count: 15)] {
            let query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                kSecAttrAccount: "device-id-v1"
            ]
            let status = SecItemDelete(query as CFDictionary)
            XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
            XCTAssertEqual(try store.insertIfAbsent(data, account: "device-id-v1"), data)
            XCTAssertThrowsError(try SecureIdentityStore(keychain: store).deviceID())
            XCTAssertEqual(try store.read(account: "device-id-v1"), data)
        }
    }

    func testConflictingTOFUProposalReturnsTheExistingPin() throws {
        let identity = SecureIdentityStore(keychain: store)
        let original = Data(repeating: 3, count: 32)
        let conflicting = Data(repeating: 4, count: 32)
        XCTAssertEqual(try identity.rememberHostKey(original, endpoint: "vpn.example:443"), original)
        XCTAssertEqual(try identity.rememberHostKey(conflicting, endpoint: "vpn.example:443"), original)
        XCTAssertEqual(try identity.knownHostKey(endpoint: "vpn.example:443"), original)
        XCTAssertEqual(try identity.rememberHostKey(conflicting, endpoint: "other.example:443"), conflicting)
    }

    func testMasterKeyIsStableAndDoesNotOverwriteMalformedExistingKey() throws {
        let first = try store.loadOrCreateSymmetricKey(account: "master").withUnsafeBytes { Data($0) }
        let second = try store.loadOrCreateSymmetricKey(account: "master").withUnsafeBytes { Data($0) }
        XCTAssertEqual(first.count, 32)
        XCTAssertEqual(second, first)
        let corrupt = Data(repeating: 5, count: 4)
        XCTAssertEqual(try store.insertIfAbsent(corrupt, account: "bad-master"), corrupt)
        XCTAssertThrowsError(try store.loadOrCreateSymmetricKey(account: "bad-master"))
        XCTAssertEqual(try store.read(account: "bad-master"), corrupt)
    }

    func testInvalidRequestedAESKeySizeIsRejectedBeforeCreatingAnItem() throws {
        for size in [0, -1, 1, 17, 33, Int.max] {
            XCTAssertThrowsError(try store.loadOrCreateSymmetricKey(account: "bad-size", byteCount: size))
            XCTAssertNil(try store.read(account: "bad-size"))
        }
    }

    func testArchiveReadRejectsAKeyWithTheWrongMasterKeyLength() throws {
        let suite = "ru.qeli.tests.archive.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(Data(repeating: 0, count: 64).base64EncodedString(), forKey: "profiles.encrypted.v1")
        _ = try store.insertIfAbsent(Data(repeating: 6, count: 16), account: "profile-master-key-v1")
        XCTAssertThrowsError(try ProfileStore(suiteName: suite, keychain: store).load()) { error in
            guard let keyError = error as? KeychainError, case .invalidKeyLength = keyError else {
                XCTFail("Expected invalid master key length, got \(error)")
                return
            }
        }
    }

}
