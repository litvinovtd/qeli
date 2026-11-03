import CryptoKit
import Foundation
import Security

final class KeychainStore: @unchecked Sendable {
    private let service: String
    private let accessGroup: String?

    init(service: String = "ru.qeli.app.secure", accessGroup: String? = AppConstants.keychainAccessGroup) {
        self.service = service
        self.accessGroup = accessGroup
    }

    func loadOrCreateSymmetricKey(account: String, byteCount: Int = 32) throws -> SymmetricKey {
        guard [16, 24, 32].contains(byteCount) else { throw KeychainError.invalidKeyLength }
        if let existing = try read(account: account) {
            guard existing.count == byteCount else { throw KeychainError.invalidKeyLength }
            return SymmetricKey(data: existing)
        }
        var bytes = Data(count: byteCount)
        let status = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, byteCount, buffer.baseAddress!)
        }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
        let winner = try insertIfAbsent(bytes, account: account)
        guard winner.count == byteCount else { throw KeychainError.invalidKeyLength }
        return SymmetricKey(data: winner)
    }

    /// Keychain owns first-writer arbitration across app/extension processes. Never use
    /// update-then-add for an identity or TOFU pin: that would overwrite a concurrent winner.
    func insertIfAbsent(_ data: Data, account: String) throws -> Data {
        var item = baseQuery(account: account)
        item[kSecValueData] = data
        item[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let add = SecItemAdd(item as CFDictionary, nil)
        if add == errSecSuccess { return data }
        if add == errSecDuplicateItem, let existing = try read(account: account) {
            return existing
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

    /// Probes an access group without creating or changing a keychain item.
    /// A permitted group returns either an existing item or `errSecItemNotFound`;
    /// a re-signed build without the entitlement returns `errSecMissingEntitlement`.
    static func canAccess(group: String) -> Bool {
        guard !group.isEmpty, !group.contains("$(") else { return false }
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "ru.qeli.app.signing-diagnostics",
            kSecAttrAccount: "entitlement-probe",
            kSecAttrAccessGroup: group,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecItemNotFound
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
    case invalidKeyLength
    case invalidDeviceID

    var isMissingEntitlement: Bool {
        guard case .status(let status) = self else { return false }
        return status == errSecMissingEntitlement
    }

    var errorDescription: String? {
        switch self {
        case .invalidKeyLength: return "The stored encryption key has an invalid length."
        case .invalidDeviceID: return "The stored device identity is invalid."
        case .status(let status):
            return SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error \(status)"
        }
    }
}
