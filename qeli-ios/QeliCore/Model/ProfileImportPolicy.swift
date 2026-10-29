import Foundation

enum ProfileImportPolicy {
    /// Parse before saving, retaining the author's INI comments and ordering. A link is
    /// converted to INI, with its embedded label taking precedence over a generic filename.
    static func profile(rawText: String, suggestedName: String? = nil) throws -> Profile {
        guard rawText.utf8.count <= ProfileLimits.maximumConfigBytes else {
            throw ProfileStoreError.profileTooLarge(1)
        }
        let config = try VPNConfig(parsing: rawText)
        let content = rawText.trimmingCharacters(in: .whitespacesAndNewlines.union(
            CharacterSet(charactersIn: "\u{FEFF}")
        ))
        let isLink = content.hasPrefix("qeli://")
        let firstLine = content.components(separatedBy: .newlines).first ?? ""
        let comment = firstLine.hasPrefix("#") ? String(firstLine.dropFirst()) : nil
        func nonEmpty(_ value: String?) -> String? {
            let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed?.isEmpty == false ? trimmed : nil
        }
        let name = (isLink ? nonEmpty(config.carriedKeys["name"]) : nonEmpty(comment))
            ?? nonEmpty(suggestedName)
            ?? config.serverAddress
        return Profile(
            name: name,
            configText: isLink ? try config.toINI(label: name) : rawText
        )
    }
}
