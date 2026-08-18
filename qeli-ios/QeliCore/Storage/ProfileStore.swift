import CryptoKit
import Foundation

final class ProfileStore: @unchecked Sendable {
    static let maximumArchiveBytes = 8 * 1024 * 1024
    static let maximumBackupFileBytes = 12 * 1024 * 1024
    static let maximumConfigBytes = 1024 * 1024
    static let maximumProfiles = 256
    static let maximumProfileNameCharacters = 256

    private let defaults: UserDefaults
    private let keychain: KeychainStore
    private let blobKey = "profiles.encrypted.v1"
    private let masterKeyAccount = "profile-master-key-v1"

    init(
        suiteName: String? = AppConstants.appGroupIdentifier,
        keychain: KeychainStore = KeychainStore()
    ) {
        self.defaults = suiteName.flatMap(UserDefaults.init(suiteName:)) ?? .standard
        self.keychain = keychain
    }

    func load() throws -> ProfileArchive {
        guard let encoded = defaults.string(forKey: blobKey) else {
            let archive = ProfileArchive.initial
            try save(archive)
            return archive
        }
        let maximumStoredBase64Characters = ((Self.maximumArchiveBytes + 64 + 2) / 3) * 4
        guard encoded.utf8.count <= maximumStoredBase64Characters else {
            throw ProfileStoreError.corruptStore
        }
        guard let combined = Data(base64Encoded: encoded) else {
            throw ProfileStoreError.corruptStore
        }
        guard combined.count <= Self.maximumArchiveBytes + 64 else {
            throw ProfileStoreError.corruptStore
        }
        let key = try keychain.loadOrCreateSymmetricKey(account: masterKeyAccount)
        let sealed = try AES.GCM.SealedBox(combined: combined)
        let plaintext = try AES.GCM.open(sealed, using: key)
        guard plaintext.count <= Self.maximumArchiveBytes else {
            throw ProfileStoreError.archiveTooLarge
        }
        var archive = try JSONDecoder.qeli.decode(ProfileArchive.self, from: plaintext)
        archive.normalize()
        try Self.validate(archive)
        return archive
    }

    func save(_ input: ProfileArchive) throws {
        var archive = input
        archive.normalize()
        try Self.validate(archive)
        let plaintext = try JSONEncoder.qeli.encode(archive)
        guard plaintext.count <= Self.maximumArchiveBytes else {
            throw ProfileStoreError.archiveTooLarge
        }
        let key = try keychain.loadOrCreateSymmetricKey(account: masterKeyAccount)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else { throw ProfileStoreError.encryptionFailed }
        defaults.set(combined.base64EncodedString(), forKey: blobKey)
    }

    /// Android-compatible plaintext backup schema. Unknown `id` metadata is harmless to
    /// Android, while retaining it lets two iOS restores preserve profile identity.
    func exportJSON(_ archive: ProfileArchive) throws -> Data {
        var archive = archive
        archive.normalize()
        try Self.validate(archive)
        let active = archive.profiles.firstIndex(where: { $0.id == archive.activeProfileID }) ?? 0
        let profiles: [[String: Any]] = archive.profiles.map { profile in
            [
                "id": profile.id.uuidString,
                "name": profile.name,
                "cfg": profile.configText
            ]
        }
        let data = try JSONSerialization.data(
            withJSONObject: ["active": active, "profiles": profiles],
            options: [.prettyPrinted, .sortedKeys]
        )
        guard data.count <= Self.maximumArchiveBytes else {
            throw ProfileStoreError.archiveTooLarge
        }
        return data
    }

    func importJSON(_ data: Data) throws -> ProfileArchive {
        guard data.count <= Self.maximumArchiveBytes else {
            throw ProfileStoreError.archiveTooLarge
        }
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rawProfiles = root["profiles"] as? [[String: Any]] else {
            throw ProfileStoreError.notQeliBackup
        }
        guard (1...Self.maximumProfiles).contains(rawProfiles.count) else {
            throw ProfileStoreError.tooManyProfiles
        }
        let profiles = try rawProfiles.map { raw -> Profile in
            let name = (raw["name"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
            let configText: String
            if let cfg = raw["cfg"] as? String, !cfg.isEmpty {
                configText = cfg
            } else if let stored = raw["json"] as? String, !stored.isEmpty {
                // A profile written by an app version that stored the CONFIG as JSON. That
                // format is retired, so `parsing:` refuses it and names it — the restore fails
                // with "export the profile again" rather than with a syntax error. The BACKUP
                // envelope around it is still JSON and is unaffected; only the config text is.
                configText = try VPNConfig(parsing: stored).toINI(label: name)
            } else {
                // Legacy old-multi-profile entry: the fields sit directly on the row. It used
                // to be re-serialized to JSON and handed to the config parser purely to reuse
                // it; built through the model instead, so the key names come from `toINI` and
                // cannot drift from what the INI reader expects.
                guard let address = (raw["address"] as? String).nonEmpty else {
                    throw ProfileStoreError.notQeliBackup
                }
                var legacy = VPNConfig(serverAddress: address, port: raw["port"] as? Int ?? 443)
                legacy.username = (raw["username"] as? String).nonEmpty ?? "phone"
                configText = try legacy.toINI(label: name)
            }
            _ = try VPNConfig(parsing: configText)
            return Profile(
                id: (raw["id"] as? String).flatMap(UUID.init(uuidString:)) ?? UUID(),
                name: name.nonEmpty ?? "profile",
                configText: configText
            )
        }
        guard !profiles.isEmpty else { throw ProfileStoreError.notQeliBackup }
        let activeIndex = (root["active"] as? NSNumber)?.intValue ?? 0
        guard profiles.indices.contains(activeIndex) else {
            throw ProfileStoreError.invalidActiveProfile
        }
        var archive = ProfileArchive(activeProfileID: profiles[activeIndex].id, profiles: profiles)
        archive.normalize()
        try Self.validate(archive)
        return archive
    }

    /// Security-scoped providers are streams, not necessarily local files. Reading in
    /// bounded chunks prevents a malicious/accidental document from being materialized in
    /// memory before its size is known.
    static func readBounded(from url: URL, maximumBytes: Int) throws -> Data {
        guard maximumBytes > 0 else { throw ProfileStoreError.archiveTooLarge }
        if let declaredSize = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize,
           declaredSize > maximumBytes {
            throw ProfileStoreError.archiveTooLarge
        }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var result = Data()
        result.reserveCapacity(min(maximumBytes, 64 * 1024))
        while true {
            let remaining = maximumBytes - result.count
            let chunk = try handle.read(upToCount: min(64 * 1024, remaining + 1)) ?? Data()
            if chunk.isEmpty { break }
            guard chunk.count <= remaining else { throw ProfileStoreError.archiveTooLarge }
            result.append(chunk)
        }
        guard !result.isEmpty else { throw ProfileStoreError.notQeliBackup }
        return result
    }

    static func validate(_ archive: ProfileArchive) throws {
        guard (1...maximumProfiles).contains(archive.profiles.count) else {
            throw ProfileStoreError.tooManyProfiles
        }
        var ids = Set<UUID>()
        for (index, profile) in archive.profiles.enumerated() {
            let name = profile.name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !name.isEmpty, profile.name.count <= maximumProfileNameCharacters else {
                throw ProfileStoreError.invalidProfileName(index + 1)
            }
            guard profile.configText.utf8.count <= maximumConfigBytes else {
                throw ProfileStoreError.profileTooLarge(index + 1)
            }
            guard ids.insert(profile.id).inserted else {
                throw ProfileStoreError.duplicateProfileID(index + 1)
            }
            do { _ = try VPNConfig(parsing: profile.configText) }
            catch { throw ProfileStoreError.invalidProfile(index + 1, error.localizedDescription) }
        }
        guard let active = archive.activeProfileID,
              archive.profiles.contains(where: { $0.id == active }) else {
            throw ProfileStoreError.invalidActiveProfile
        }
    }
}

enum ProfileStoreError: LocalizedError {
    case corruptStore
    case encryptionFailed
    case notQeliBackup
    case archiveTooLarge
    case tooManyProfiles
    case profileTooLarge(Int)
    case invalidProfileName(Int)
    case invalidProfile(Int, String)
    case duplicateProfileID(Int)
    case invalidActiveProfile

    var errorDescription: String? {
        switch self {
        case .corruptStore: return "The encrypted profile store is corrupt."
        case .encryptionFailed: return "Could not encrypt the profile store."
        case .notQeliBackup: return "The file is not a Qeli profile backup."
        case .archiveTooLarge: return "The profile file exceeds the supported size limit."
        case .tooManyProfiles: return "A profile archive may contain at most \(ProfileStore.maximumProfiles) profiles."
        case .profileTooLarge(let index): return "Profile \(index) exceeds the config size limit."
        case .invalidProfileName(let index): return "Profile \(index) has an empty or overlong name."
        case .invalidProfile(let index, let message): return "Profile \(index) is invalid: \(message)"
        case .duplicateProfileID(let index): return "Profile \(index) repeats another profile identifier."
        case .invalidActiveProfile: return "The active profile identifier is invalid."
        }
    }
}

private extension JSONEncoder {
    static var qeli: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
}

private extension JSONDecoder {
    static var qeli: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

private extension Optional where Wrapped == String {
    var nonEmpty: String? {
        guard let self, !self.isEmpty else { return nil }
        return self
    }
}
