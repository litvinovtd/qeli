import Foundation

struct Profile: Codable, Equatable, Identifiable, Sendable {
    var id: UUID
    var name: String
    var configText: String
    var createdAt: Date
    var modifiedAt: Date

    init(
        id: UUID = UUID(),
        name: String,
        configText: String,
        createdAt: Date = Date(),
        modifiedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.configText = configText
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
    }

    static let template = Profile(
        name: "My server",
        configText: """
        # My server
        [qeli]
        server = SERVER_IP_OR_HOST:443
        proto = tcp
        user = phone
        pass = changeme
        key =
        mode = fake-tls
        sni = www.microsoft.com
        """
    )

    var parsedConfig: VPNConfig? { try? VPNConfig(parsing: configText) }
}

struct ProfileArchive: Codable, Equatable, Sendable {
    var version: Int = 1
    var activeProfileID: UUID?
    var profiles: [Profile]

    static var initial: ProfileArchive {
        let profile = Profile.template
        return ProfileArchive(activeProfileID: profile.id, profiles: [profile])
    }

    mutating func normalize() {
        // A malformed/hand-edited backup may repeat an id. Keeping duplicate Identifiable
        // values makes SwiftUI rows alias each other and makes activeProfileID ambiguous.
        // Preserve the first occurrence (and therefore an active selection that points to
        // it), assigning fresh identities to later duplicates.
        var seen = Set<UUID>()
        for index in profiles.indices {
            if !seen.insert(profiles[index].id).inserted {
                var replacement = UUID()
                while seen.contains(replacement) { replacement = UUID() }
                profiles[index].id = replacement
                seen.insert(replacement)
            }
        }
        if profiles.isEmpty {
            let profile = Profile.template
            profiles = [profile]
            activeProfileID = profile.id
        } else if activeProfileID == nil || !profiles.contains(where: { $0.id == activeProfileID }) {
            activeProfileID = profiles[0].id
        }
    }
}
