import Foundation
import Security

final class SecureIdentityStore: @unchecked Sendable {
    private let keychain = KeychainStore(service: "ru.qeli.app.identity")

    func deviceID() throws -> Data {
        if let existing = try keychain.read(account: "device-id-v1"),
           existing.count == 16,
           existing.contains(where: { $0 != 0 }) {
            return existing
        }
        var value = Data(count: 16)
        let status = value.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
        try keychain.write(value, account: "device-id-v1")
        return value
    }

    func knownHostKey(endpoint: String) throws -> Data? {
        try keychain.read(account: "known-host:\(endpoint)")
    }

    func rememberHostKey(_ key: Data, endpoint: String) throws {
        try keychain.write(key, account: "known-host:\(endpoint)")
    }
}
