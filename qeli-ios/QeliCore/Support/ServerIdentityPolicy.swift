import Foundation

enum ServerIdentityPolicy {
    enum Failure: Error { case endpointMismatch }

    static func isKeyMismatch(_ message: String) -> Bool { message.contains("SERVER KEY MISMATCH") }

    static func endpointID(protocolName: String, host: String, port: Int) throws -> String {
        let transport = protocolName.lowercased()
        guard transport == "tcp" || transport == "udp" else { throw Failure.endpointMismatch }
        var address = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if address.contains(":") && !address.hasPrefix("[") { address = "[\(address)]" }
        return "\(transport)://\(address):\(port)"
    }

    static func storageID(eventID: String, protocolName: String, host: String, port: Int) throws -> String {
        let scoped = try endpointID(protocolName: protocolName, host: host, port: port)
        guard eventID == scoped || eventID == "\(host):\(port)" || eventID == legacyID(scoped) else { throw Failure.endpointMismatch }
        return scoped
    }

    static func legacyID(_ serverID: String) -> String? {
        guard serverID.hasPrefix("tcp://") || serverID.hasPrefix("udp://") else { return nil }
        let endpoint = String(serverID.dropFirst(6))
        if endpoint.hasPrefix("[") {
            return String(endpoint.dropFirst()).replacingOccurrences(of: "]:", with: ":")
        }
        return endpoint
    }
}
