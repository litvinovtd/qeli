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
    static let maximumResponseBytes = 1024 * 1024
    private static let releasesURL = URL(string: "https://api.github.com/repos/litvinovtd/qeli/releases")!
    private static let releasesPage = URL(string: "https://github.com/litvinovtd/qeli/releases")!

    /// A DNS answer may select either family, so both missing-family escape hatches must be
    /// closed before the app can promise that release metadata is fetched through the VPN.
    /// Any custom exclude makes the destination path unknowable without resolving first and
    /// is therefore rejected conservatively.

    static func check(currentVersion: String) async throws -> UpdateInfo {
        var request = URLRequest(url: releasesURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
        request.httpMethod = "GET"
        request.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 10
        // A release check is permitted only while AppModel sees a private VPN path.
        // Never park it waiting for another network, and never let Multipath migrate it
        // after the tunnel disappears; AppModel also awaits cancellation before managed
        // tunnel teardown.
        configuration.waitsForConnectivity = false
        configuration.multipathServiceType = .none
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw UpdateCheckerError.invalidResponse
        }
        let data = try await boundedResponse(bytes, maximumBytes: maximumResponseBytes)
        let releases = try JSONDecoder().decode([Release].self, from: data)
        guard let release = releases.first(where: { !$0.draft && !$0.tagName.isEmpty }) else {
            throw UpdateCheckerError.noRelease
        }
        let latest = try normalize(release.tagName)
        return UpdateInfo(
            latest: latest,
            url: URL(string: release.htmlURL ?? "") ?? releasesPage,
            isNewer: try isNewer(latest, than: currentVersion)
        )
    }

    static func boundedResponse<S: AsyncSequence>(
        _ bytes: S, maximumBytes: Int
    ) async throws -> Data where S.Element == UInt8 {
        try Task.checkCancellation()
        guard maximumBytes > 0 else { throw UpdateCheckerError.responseTooLarge }
        var data = Data()
        data.reserveCapacity(min(maximumBytes, 16 * 1024))
        for try await byte in bytes {
            try Task.checkCancellation()
            guard data.count < maximumBytes else { throw UpdateCheckerError.responseTooLarge }
            data.append(byte)
        }
        return data
    }

    static func normalize(_ value: String) throws -> String {
        try ConfigCore.policy("version_normalize",["value":value])["value"] as! String
    }
    static func isNewer(_ latest: String, than current: String) throws -> Bool {
        (try ConfigCore.policy("version_compare",["a":latest,"b":current])["value"] as! Int) > 0
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
    case responseTooLarge

    var errorDescription: String? {
        switch self {
        case .invalidResponse: return "The release service returned an invalid response."
        case .noRelease: return "No published Qeli release was found."
        case .responseTooLarge: return "The release service response is too large."
        }
    }
}
