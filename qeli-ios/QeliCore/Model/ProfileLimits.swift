import Foundation

/// Shared import/storage bounds, independent of the encrypted storage backend.
enum ProfileLimits {
    static let maximumArchiveBytes = 8 * 1024 * 1024
    static let maximumBackupFileBytes = 12 * 1024 * 1024
    static let maximumConfigBytes = 256 * 1024 // shared editor/native core limit
    static let maximumProfiles = 256
    static let maximumProfileNameCharacters = 256
}

enum ProfileStoreError: LocalizedError {
    case corruptStore
    case missingStore
    case missingMasterKey
    case unavailableAfterLoadFailure
    case staleProfile
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
        case .missingStore: return "No saved profiles are available. Open Qeli to create a profile before connecting."
        case .missingMasterKey: return "The profile encryption key is missing. Restore a backup to recover your profiles."
        case .unavailableAfterLoadFailure: return "Saved profiles could not be read. Restart the app or restore a backup before making changes."
        case .staleProfile: return "Profile changed while the editor was open. Reopen it before saving."
        case .encryptionFailed: return "Could not encrypt the profile store."
        case .notQeliBackup: return "The file is not a Qeli profile backup."
        case .archiveTooLarge: return "The profile file exceeds the supported size limit."
        case .tooManyProfiles: return "A profile archive must contain 1 to \(ProfileLimits.maximumProfiles) profiles."
        case .profileTooLarge(let index): return "Profile \(index) exceeds the config size limit."
        case .invalidProfileName(let index): return "Profile \(index) has an empty or overlong name."
        case .invalidProfile(let index, let message): return "Profile \(index) is invalid: \(message)"
        case .duplicateProfileID(let index): return "Profile \(index) repeats another profile identifier."
        case .invalidActiveProfile: return "The active profile identifier is invalid."
        }
    }
}
