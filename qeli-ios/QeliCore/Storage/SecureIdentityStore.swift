import Foundation
import Security

final class SecureIdentityStore: @unchecked Sendable {
    private let keychain: KeychainStore

    init(keychain: KeychainStore = KeychainStore(service: "ru.qeli.app.identity")) {
        self.keychain = keychain
    }

    func deviceID() throws -> Data {
        if let existing = try keychain.read(account: "device-id-v1") {
            return try Self.validatedDeviceID(existing)
        }
        var value = Data(count: 16)
        let status = value.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
        _ = try Self.validatedDeviceID(value)
        return try Self.validatedDeviceID(
            keychain.insertIfAbsent(value, account: "device-id-v1")
        )
    }

    func knownHostKey(endpoint: String) throws -> Data? {
        try keychain.read(account: "known-host:\(endpoint)")
    }

    /// Returns the first persisted pin; the caller must compare it to the proven peer key.
    func rememberHostKey(_ key: Data, endpoint: String) throws -> Data {
        try keychain.insertIfAbsent(key, account: "known-host:\(endpoint)")
    }

    private static func validatedDeviceID(_ data: Data) throws -> Data {
        guard data.count == 16, data.contains(where: { $0 != 0 }) else {
            throw KeychainError.invalidDeviceID
        }
        return data
    }
}
