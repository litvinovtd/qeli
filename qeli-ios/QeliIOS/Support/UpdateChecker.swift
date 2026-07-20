import Foundation

struct UpdateInfo: Equatable, Sendable {
    var latest: String
    var url: URL
    var isNewer: Bool
}

enum UpdateCheckState: Equatable {
    case idle
    case checking
    case current
    case available(UpdateInfo)
    case failed(String)
}

enum UpdateChecker {
    private static let releasesURL = URL(string: "https://api.github.com/repos/litvinovtd/qeli/releases")!
    private static let releasesPage = URL(string: "https://github.com/litvinovtd/qeli/releases")!

    static func check(currentVersion: String) async throws -> UpdateInfo {
        var request = URLRequest(url: releasesURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
        request.httpMethod = "GET"
        request.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 10
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw UpdateCheckerError.invalidResponse
        }
        let releases = try JSONDecoder().decode([Release].self, from: data)
        guard let release = releases.first(where: { !$0.draft && !$0.tagName.isEmpty }) else {
            throw UpdateCheckerError.noRelease
        }
        let latest = normalize(release.tagName)
        return UpdateInfo(
            latest: latest,
            url: URL(string: release.htmlURL ?? "") ?? releasesPage,
            isNewer: isNewer(latest, than: currentVersion)
        )
    }

    static func normalize(_ value: String) -> String {
        var value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.first == "v" || value.first == "V" { value.removeFirst() }
        if let suffix = value.firstIndex(where: { $0 == "-" || $0 == "+" }) {
            value = String(value[..<suffix])
        }
        return value.isEmpty ? "0" : value
    }

    static func isNewer(_ latest: String, than current: String) -> Bool {
        let lhs = normalize(latest).split(separator: ".").map { Int($0) ?? 0 }
        let rhs = normalize(current).split(separator: ".").map { Int($0) ?? 0 }
        for index in 0..<max(lhs.count, rhs.count) {
            let left = index < lhs.count ? lhs[index] : 0
            let right = index < rhs.count ? rhs[index] : 0
            if left != right { return left > right }
        }
        return false
    }

    private struct Release: Decodable {
        var tagName: String
        var htmlURL: String?
        var draft: Bool

        enum CodingKeys: String, CodingKey {
            case tagName = "tag_name"
            case htmlURL = "html_url"
            case draft
        }
    }
}

enum UpdateCheckerError: LocalizedError {
    case invalidResponse
    case noRelease

    var errorDescription: String? {
        switch self {
        case .invalidResponse: return "The release service returned an invalid response."
        case .noRelease: return "No published Qeli release was found."
        }
    }
}
