import CryptoKit
import Foundation
import Security

final class KeychainStore: @unchecked Sendable {
    private let service: String
    private let accessGroup: String?

    init(service: String = "ru.autocash.qeli.secure", accessGroup: String? = AppConstants.keychainAccessGroup) {
        self.service = service
        self.accessGroup = accessGroup
    }

    func loadOrCreateSymmetricKey(account: String, byteCount: Int = 32) throws -> SymmetricKey {
        if let existing = try read(account: account) { return SymmetricKey(data: existing) }
        var bytes = Data(count: byteCount)
        let status = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, byteCount, buffer.baseAddress!)
        }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
        var item = baseQuery(account: account)
        item[kSecValueData] = bytes
        item[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let add = SecItemAdd(item as CFDictionary, nil)
        if add == errSecSuccess { return SymmetricKey(data: bytes) }
        // App and Packet Tunnel can start concurrently on first use. Never overwrite
        // the winner's new master key: an archive may already have been sealed with it.
        if add == errSecDuplicateItem, let existing = try read(account: account) {
            return SymmetricKey(data: existing)
        }
        throw KeychainError.status(add)
    }

    func read(account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError.status(status)
        }
        return data
    }

    func write(_ data: Data, account: String) throws {
        let query = baseQuery(account: account)
        let attributes: [CFString: Any] = [kSecValueData: data]
        let update = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw KeychainError.status(update) }

        var item = query
        item[kSecValueData] = data
        item[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let add = SecItemAdd(item as CFDictionary, nil)
        guard add == errSecSuccess else { throw KeychainError.status(add) }
    }

    private func baseQuery(account: String) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        if let accessGroup { query[kSecAttrAccessGroup] = accessGroup }
        return query
    }
}

enum KeychainError: LocalizedError {
    case status(OSStatus)

    var errorDescription: String? {
        switch self {
        case .status(let status):
            return SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error \(status)"
        }
    }
}
