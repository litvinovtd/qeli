import Darwin
import Foundation

struct QeliPathFlags: Codable, Equatable, Sendable {
    var defaultRouteChanged: Bool
    var wake: Bool
    var sameNetworkNatFailure: Bool

    enum CodingKeys: String, CodingKey {
        case defaultRouteChanged = "default_route_changed"
        case wake
        case sameNetworkNatFailure = "same_network_nat_failure"
    }
}

struct QeliPathResolution: Codable, Equatable, Sendable {
    var address: String
    var ttlSeconds: UInt32

    enum CodingKeys: String, CodingKey {
        case address
        case ttlSeconds = "ttl_secs"
    }
}

struct QeliPathUpdate: Codable, Equatable, Sendable {
    var generation: UInt64
    var updateID: UInt64
    var platformPathID: String
    var reason: String
    var networkToken: String?
    var interfaceIndex: UInt32?
    var localAddresses: [String]
    var resolvedAddresses: [QeliPathResolution]
    var flags: QeliPathFlags

    enum CodingKeys: String, CodingKey {
        case generation
        case updateID = "update_id"
        case platformPathID = "platform_path_id"
        case reason
        case networkToken = "network_token"
        case interfaceIndex = "interface_index"
        case localAddresses = "local_addresses"
        case resolvedAddresses = "resolved_addresses"
        case flags
    }
}

struct QeliPathCommand: Codable, Equatable, Sendable {
    var generation: UInt64
    var candidateID: UInt64
    var action: String
    var path: QeliPathUpdate
    var socketFD: Int64?
    var reason: String?

    enum CodingKeys: String, CodingKey {
        case generation
        case candidateID = "candidate_id"
        case action
        case path
        case socketFD = "socket_fd"
        case reason
    }
}

enum QeliRoamingPath {
    static let pathCommandEvent: UInt32 = 6
    static let pathRefreshEvent: UInt32 = 7
    static let payloadNone: UInt32 = 0
    static let payloadJSON: UInt32 = 1
    static let maximumPayloadBytes = 64 * 1024
    static let maximumAddresses = 16
    static let maximumTTLSeconds: UInt32 = 7 * 24 * 60 * 60
    static let actions = Set(["prepare_path", "bind_socket", "commit_path", "abort_path"])
    static let reasons = Set([
        "network_changed", "default_route_changed", "wake",
        "same_network_nat_failure", "manual_probe",
    ])

    static func encode(_ update: QeliPathUpdate) throws -> Data {
        try validate(update)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(update)
        guard data.count <= maximumPayloadBytes else {
            throw QeliNativeError.invalidInput("path update exceeds 64 KiB")
        }
        return data
    }

    static func decodeCommand(_ event: QeliTransportEvent) throws -> QeliPathCommand {
        guard event.kind == pathCommandEvent, event.payloadFormat == payloadJSON,
              event.sequence != 0, event.planGeneration != 0, event.errorCode == 0,
              !event.payload.isEmpty else {
            throw QeliNativeError.invalidInput("invalid path-command event envelope")
        }
        let data = Data(event.payload.utf8)
        guard data.count <= maximumPayloadBytes else {
            throw QeliNativeError.invalidInput("path-command payload exceeds 64 KiB")
        }
        try validateJSONShape(data)
        let command = try JSONDecoder().decode(QeliPathCommand.self, from: data)
        guard command.generation == event.planGeneration, command.candidateID != 0,
              actions.contains(command.action), command.path.generation == command.generation else {
            throw QeliNativeError.invalidInput("path-command correlation mismatch")
        }
        guard (command.action == "bind_socket") == (command.socketFD != nil),
              command.socketFD.map({ $0 >= 0 }) ?? true else {
            throw QeliNativeError.invalidInput("only BIND_SOCKET may carry a non-negative fd")
        }
        try validate(command.path)
        return command
    }

    static func decodeRefreshGeneration(_ event: QeliTransportEvent) throws -> UInt64 {
        guard event.kind == pathRefreshEvent, event.payloadFormat == payloadNone,
              event.sequence != 0, event.planGeneration != 0, event.errorCode == 0,
              event.payload.isEmpty else {
            throw QeliNativeError.invalidInput("invalid path-refresh event")
        }
        return event.planGeneration
    }

    static func validate(_ update: QeliPathUpdate) throws {
        guard update.generation != 0, update.updateID != 0 else {
            throw QeliNativeError.invalidInput("path generation and update id must be non-zero")
        }
        try validateIdentifier(update.platformPathID, label: "platform path id")
        if let token = update.networkToken { try validateIdentifier(token, label: "network token") }
        guard update.networkToken != nil || update.interfaceIndex != nil,
              update.interfaceIndex != 0 else {
            throw QeliNativeError.invalidInput("path requires a network token or interface index")
        }
        guard reasons.contains(update.reason) else {
            throw QeliNativeError.invalidInput("unsupported path-update reason")
        }
        let matchingFlag = switch update.reason {
        case "default_route_changed": update.flags.defaultRouteChanged
        case "wake": update.flags.wake
        case "same_network_nat_failure": update.flags.sameNetworkNatFailure
        default: true
        }
        guard matchingFlag else {
            throw QeliNativeError.invalidInput("path-update reason is missing its matching flag")
        }
        guard (1...maximumAddresses).contains(update.localAddresses.count),
              (1...maximumAddresses).contains(update.resolvedAddresses.count) else {
            throw QeliNativeError.invalidInput("path requires 1...16 local and resolved addresses")
        }
        let local = try Set(update.localAddresses.map { try usableAddress($0, label: "local path") })
        guard local.count == update.localAddresses.count else {
            throw QeliNativeError.invalidInput("path contains duplicate local addresses")
        }
        var resolved = Set<String>()
        var compatible = false
        for item in update.resolvedAddresses {
            let address = try usableAddress(item.address, label: "resolved path")
            guard resolved.insert(address.text).inserted else {
                throw QeliNativeError.invalidInput("path contains duplicate resolved addresses")
            }
            guard item.ttlSeconds <= maximumTTLSeconds else {
                throw QeliNativeError.invalidInput("resolved path TTL exceeds seven days")
            }
            compatible = compatible || local.contains(where: { $0.family == address.family })
        }
        guard compatible else {
            throw QeliNativeError.invalidInput("path has no family-compatible resolved address")
        }
    }

    private static func validateJSONShape(_ data: Data) throws {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw QeliNativeError.invalidInput("path-command payload is not an object")
        }
        try requireKeys(
            root, required: ["generation", "candidate_id", "action", "path"],
            optional: ["socket_fd", "reason"], label: "path command")
        guard let path = root["path"] as? [String: Any] else {
            throw QeliNativeError.invalidInput("path-command path is not an object")
        }
        try requireKeys(
            path,
            required: [
                "generation", "update_id", "platform_path_id", "reason",
                "local_addresses", "resolved_addresses", "flags",
            ],
            optional: ["network_token", "interface_index"], label: "path update")
        guard let flags = path["flags"] as? [String: Any] else {
            throw QeliNativeError.invalidInput("path flags are not an object")
        }
        try requireKeys(
            flags,
            required: ["default_route_changed", "wake", "same_network_nat_failure"],
            optional: [], label: "path flags")
        guard let resolutions = path["resolved_addresses"] as? [[String: Any]] else {
            throw QeliNativeError.invalidInput("resolved addresses are not objects")
        }
        for resolution in resolutions {
            try requireKeys(
                resolution, required: ["address", "ttl_secs"], optional: [],
                label: "path resolution")
        }
    }

    private static func requireKeys(
        _ object: [String: Any], required: Set<String>, optional: Set<String>, label: String
    ) throws {
        let keys = Set(object.keys)
        guard required.isSubset(of: keys), keys.isSubset(of: required.union(optional)) else {
            throw QeliNativeError.invalidInput("\(label) contains missing or unknown fields")
        }
    }

    private static func validateIdentifier(_ value: String, label: String) throws {
        let bytes = value.utf8.count
        guard (1...256).contains(bytes),
              !value.unicodeScalars.contains(where: {
                  CharacterSet.controlCharacters.contains($0)
              }) else {
            throw QeliNativeError.invalidInput("\(label) must be 1...256 bytes without controls")
        }
    }

    private struct ParsedAddress: Hashable {
        let family: Int32
        let text: String
    }

    private static func usableAddress(_ text: String, label: String) throws -> ParsedAddress {
        var ipv4 = in_addr()
        if text.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            let value = UInt32(bigEndian: ipv4.s_addr)
            guard value != 0, value != UInt32.max, value >> 24 != 127,
                  value >> 28 != 14 else {
                throw QeliNativeError.invalidInput("invalid \(label) address")
            }
            return ParsedAddress(family: AF_INET, text: text)
        }
        var ipv6 = in6_addr()
        if text.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            let bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
            let loopback = bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1
            guard bytes.contains(where: { $0 != 0 }), bytes.first != 0xff, !loopback else {
                throw QeliNativeError.invalidInput("invalid \(label) address")
            }
            return ParsedAddress(family: AF_INET6, text: text.lowercased())
        }
        throw QeliNativeError.invalidInput("invalid \(label) address")
    }
}
