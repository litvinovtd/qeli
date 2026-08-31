import Darwin
import Foundation
import Network

enum IOSRoamingError: LocalizedError {
    case unavailable(String)
    case invalidState(String)
    case platformStateUnknown(String)
    case systemCall(String, Int32)

    var errorDescription: String? {
        switch self {
        case .unavailable(let message), .invalidState(let message),
             .platformStateUnknown(let message): return message
        case .systemCall(let call, let code):
            return "\(call) failed: \(String(cString: strerror(code))) (\(code))"
        }
    }
}

private struct IOSPathProbeResult: Sendable {
    let interfaceName: String
    let interfaceIndex: UInt32
    let localAddress: String
    let remoteAddress: String

    var token: String { "\(interfaceName):\(interfaceIndex)" }
    var pathID: String {
        "ios:\(interfaceName):\(interfaceIndex):\(localAddress):\(remoteAddress)"
    }
}

private final class IOSPathProbeCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Result<IOSPathProbeResult, Error>, Never>?
    private var result: Result<IOSPathProbeResult, Error>?

    func park(_ value: CheckedContinuation<Result<IOSPathProbeResult, Error>, Never>) {
        let immediate = lock.withLock { () -> Result<IOSPathProbeResult, Error>? in
            if let result { return result }
            continuation = value
            return nil
        }
        if let immediate { value.resume(returning: immediate) }
    }

    func finish(_ value: Result<IOSPathProbeResult, Error>) {
        let pending = lock.withLock {
            () -> CheckedContinuation<Result<IOSPathProbeResult, Error>, Never>? in
            guard result == nil else { return nil }
            result = value
            defer { continuation = nil }
            return continuation
        }
        pending?.resume(returning: value)
    }
}

private enum IOSPathProbe {
    private static let timeoutMilliseconds = 10_000

    static func resolve(
        host: String, port: UInt16, interface: NWInterface
    ) async throws -> IOSPathProbeResult {
        guard port != 0 else { throw IOSRoamingError.invalidState("invalid server port") }
        let parameters = NWParameters.udp
        parameters.requiredInterface = interface
        parameters.prohibitedInterfaceTypes = [.loopback]
        let connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!,
            using: parameters)
        let queue = DispatchQueue(label: "ru.qeli.ios.roaming.probe")
        let completion = IOSPathProbeCompletion()
        return try await withTaskCancellationHandler {
            let outcome: Result<IOSPathProbeResult, Error> = await withCheckedContinuation {
                continuation in
                completion.park(continuation)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        do {
                            guard let path = connection.currentPath,
                                  path.status == .satisfied,
                                  path.availableInterfaces.contains(where: {
                                      $0.index == interface.index && $0.name == interface.name
                                  }),
                                  let local = endpointAddress(path.localEndpoint),
                                  let remote = endpointAddress(path.remoteEndpoint) else {
                                throw IOSRoamingError.unavailable(
                                    "physical DNS probe exposed no exact endpoints")
                            }
                            completion.finish(.success(IOSPathProbeResult(
                                interfaceName: interface.name,
                                interfaceIndex: UInt32(interface.index),
                                localAddress: local,
                                remoteAddress: remote)))
                        } catch { completion.finish(.failure(error)) }
                        connection.cancel()
                    case .waiting(let error), .failed(let error):
                        completion.finish(.failure(error))
                        connection.cancel()
                    case .cancelled:
                        completion.finish(.failure(CancellationError()))
                    default:
                        break
                    }
                }
                connection.start(queue: queue)
                queue.asyncAfter(deadline: .now() + .milliseconds(timeoutMilliseconds)) {
                    completion.finish(.failure(IOSRoamingError.unavailable(
                        "physical DNS/path probe timed out")))
                    connection.cancel()
                }
            }
            return try outcome.get()
        } onCancel: {
            connection.cancel()
        }
    }

    private static func endpointAddress(_ endpoint: NWEndpoint?) -> String? {
        guard case .hostPort(let host, _) = endpoint else { return nil }
        let text = String(describing: host)
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return IOSRoamingSocket.canonicalUsableAddress(text)
    }
}

enum IOSRoamingSocket {
    static let ipv4BoundInterfaceOption: Int32 = 25
    static let ipv6BoundInterfaceOption: Int32 = 125

    static func physicalInterface(for path: NWPath) -> NWInterface? {
        guard path.status == .satisfied else { return nil }
        let interfaces = path.availableInterfaces.filter { interface in
            let name = interface.name.lowercased()
            return interface.index > 0
                && !name.hasPrefix("utun")
                && !name.hasPrefix("ipsec")
                && !name.hasPrefix("lo")
                && !name.hasPrefix("awdl")
                && !name.hasPrefix("llw")
        }
        for type in [
            NWInterface.InterfaceType.wifi, .cellular, .wiredEthernet, .other,
        ] where path.usesInterfaceType(type) {
            if let selected = interfaces.first(where: { $0.type == type }) { return selected }
        }
        return interfaces.first
    }

    static func signature(for path: NWPath) -> String? {
        guard let interface = physicalInterface(for: path) else { return nil }
        let addresses = localAddresses(interfaceName: interface.name)
        return "\(interface.name):\(interface.index):\(addresses.joined(separator: ","))"
    }

    static func localAddresses(interfaceName: String) -> [String] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var output = Set<String>()
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let item = cursor {
            defer { cursor = item.pointee.ifa_next }
            guard let namePointer = item.pointee.ifa_name,
                  String(cString: namePointer) == interfaceName,
                  let address = item.pointee.ifa_addr else { continue }
            let flags = item.pointee.ifa_flags
            guard flags & UInt32(IFF_UP) != 0 else { continue }
            let family = Int32(address.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(
                address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count),
                nil, 0, NI_NUMERICHOST) == 0,
                let canonical = canonicalUsableAddress(String(cString: host)) else { continue }
            output.insert(canonical)
        }
        return output.sorted()
    }

    static func canonicalUsableAddress(_ text: String) -> String? {
        guard !text.contains("%") else { return nil }
        var ipv4 = in_addr()
        if text.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            let value = UInt32(bigEndian: ipv4.s_addr)
            guard value != 0, value != UInt32.max, value >> 24 != 127,
                  value >> 28 != 14, value & 0xffff_0000 != 0xa9fe_0000 else { return nil }
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &ipv4, &buffer, socklen_t(buffer.count)) != nil else {
                return nil
            }
            return String(cString: buffer)
        }
        var ipv6 = in6_addr()
        if text.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            let bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
            let loopback = bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1
            let linkLocal = bytes.count >= 2 && bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80
            guard bytes.contains(where: { $0 != 0 }), bytes.first != 0xff,
                  !loopback, !linkLocal else { return nil }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &ipv6, &buffer, socklen_t(buffer.count)) != nil else {
                return nil
            }
            return String(cString: buffer).lowercased()
        }
        return nil
    }

    static func bind(
        borrowedFD: Int64, interfaceName: String, interfaceIndex: UInt32,
        localAddresses: [String]
    ) throws {
        guard borrowedFD >= 0, borrowedFD <= Int64(Int32.max), interfaceIndex != 0 else {
            throw IOSRoamingError.invalidState("candidate socket descriptor is out of range")
        }
        let fd = Int32(borrowedFD)
        var storage = sockaddr_storage()
        var storageLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let nameStatus = withUnsafeMutablePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &storageLength)
            }
        }
        guard nameStatus == 0 else { throw IOSRoamingError.systemCall("getsockname", errno) }
        let family = Int32(storage.ss_family)
        guard family == AF_INET || family == AF_INET6 else {
            throw IOSRoamingError.invalidState("candidate socket has unsupported family")
        }
        let assigned = Set(Self.localAddresses(interfaceName: interfaceName))
        guard let source = localAddresses.compactMap(canonicalUsableAddress).first(where: {
            assigned.contains($0) && (($0.contains(":")) == (family == AF_INET6))
        }) else {
            throw IOSRoamingError.invalidState(
                "candidate source address is no longer assigned to \(interfaceName)")
        }
        var index = interfaceIndex
        let option = family == AF_INET ? ipv4BoundInterfaceOption : ipv6BoundInterfaceOption
        let level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6
        guard setsockopt(
            fd, level, option, &index, socklen_t(MemoryLayout<UInt32>.size)) == 0 else {
            throw IOSRoamingError.systemCall("setsockopt(bound interface)", errno)
        }
        if family == AF_INET {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            guard source.withCString({ inet_pton(AF_INET, $0, &address.sin_addr) }) == 1 else {
                throw IOSRoamingError.invalidState("invalid IPv4 candidate source")
            }
            let status = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard status == 0 else { throw IOSRoamingError.systemCall("bind", errno) }
        } else {
            var address = sockaddr_in6()
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            address.sin6_family = sa_family_t(AF_INET6)
            guard source.withCString({ inet_pton(AF_INET6, $0, &address.sin6_addr) }) == 1 else {
                throw IOSRoamingError.invalidState("invalid IPv6 candidate source")
            }
            let status = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
            guard status == 0 else { throw IOSRoamingError.systemCall("bind", errno) }
        }
    }
}

actor IOSRoamingController {
    private struct Active {
        let transport: QeliNativeTransport
        let generation: UInt64
        var carrierAddresses: [String]
    }

    private struct Candidate {
        let generation: UInt64
        let candidateID: UInt64
        let path: QeliPathUpdate
        let oldCarriers: [String]
        let newCarriers: [String]
        let unionCarriers: [String]
        var bound: Bool
    }

    private weak var engine: QeliNativeTunnelEngine?
    private let serverAddress: String
    private let serverPort: UInt16
    private let monitor = NWPathMonitor()
    private let monitorQueue = DispatchQueue(label: "ru.qeli.ios.roaming.monitor")
    private var monitoring = false
    private var latestPath: NWPath?
    private var baselineSignature: String?
    private var active: Active?
    private var updateID: UInt64 = 0
    private var observationRevision: UInt64 = 0
    private var pendingUpdate: Task<Void, Never>?
    private var observations: [UInt64: QeliPathUpdate] = [:]
    private var candidates: [UInt64: Candidate] = [:]
    private var rolledBack: [UInt64: QeliPathUpdate] = [:]

    init(engine: QeliNativeTunnelEngine, serverAddress: String, serverPort: UInt16) {
        self.engine = engine
        self.serverAddress = serverAddress
        self.serverPort = serverPort
    }

    func start() {
        guard !monitoring else { return }
        monitoring = true
        monitor.pathUpdateHandler = { [weak self] path in
            Task { await self?.observed(path) }
        }
        monitor.start(queue: monitorQueue)
    }

    func stop() {
        pendingUpdate?.cancel()
        pendingUpdate = nil
        active = nil
        observations.removeAll()
        candidates.removeAll()
        rolledBack.removeAll()
        latestPath = nil
        baselineSignature = nil
        if monitoring {
            monitor.pathUpdateHandler = nil
            monitor.cancel()
            monitoring = false
        }
    }

    func arm(
        transport: QeliNativeTransport, generation: UInt64, carrierAddresses: [String]
    ) {
        pendingUpdate?.cancel()
        pendingUpdate = nil
        active = Active(
            transport: transport, generation: generation,
            carrierAddresses: distinct(carrierAddresses))
        observations.removeAll()
        candidates.removeAll()
        rolledBack.removeAll()
        updateID = 0
        baselineSignature = latestPath.flatMap(IOSRoamingSocket.signature)
    }

    func disarm(transport: QeliNativeTransport) {
        guard active?.transport === transport else { return }
        pendingUpdate?.cancel()
        pendingUpdate = nil
        active = nil
        observations.removeAll()
        candidates.removeAll()
        rolledBack.removeAll()
    }

    private func observed(_ path: NWPath) {
        latestPath = path
        guard active != nil, let signature = IOSRoamingSocket.signature(for: path) else { return }
        guard let previous = baselineSignature else {
            baselineSignature = signature
            return
        }
        guard signature != previous else { return }
        baselineSignature = signature
        observationRevision &+= 1
        let revision = observationRevision
        pendingUpdate?.cancel()
        pendingUpdate = Task { [weak self] in
            do { try await Task.sleep(nanoseconds: 350_000_000) } catch { return }
            guard let self else { return }
            _ = await self.submit(
                path: path, reason: "default_route_changed", requiredGeneration: nil,
                reconnectOnFailure: true, revision: revision)
        }
    }

    func requestUpdate(
        reason: String, requiredGeneration: UInt64?, reconnectOnFailure: Bool
    ) async -> Bool {
        guard let path = latestPath else {
            if reconnectOnFailure, let state = active,
               requiredGeneration == nil || requiredGeneration == state.generation {
                engine?.requestRoamingReconnect(
                    transport: state.transport,
                    generation: state.generation,
                    reason: "No physical path snapshot is available for (reason)")
            }
            return false
        }
        observationRevision &+= 1
        return await submit(
            path: path, reason: reason, requiredGeneration: requiredGeneration,
            reconnectOnFailure: reconnectOnFailure, revision: observationRevision)
    }

    private func submit(
        path: NWPath, reason: String, requiredGeneration: UInt64?,
        reconnectOnFailure: Bool, revision: UInt64
    ) async -> Bool {
        guard let state = active,
              requiredGeneration == nil || requiredGeneration == state.generation else { return false }
        guard state.transport.pathTransactionsEnabled else {
            if reconnectOnFailure {
                engine?.requestRoamingReconnect(
                    transport: state.transport, generation: state.generation,
                    reason: "Physical path changed and this native core has no roaming executor")
            }
            return false
        }
        do {
            guard let interface = IOSRoamingSocket.physicalInterface(for: path) else {
                throw IOSRoamingError.unavailable("physical path has no usable interface")
            }
            let probe = try await IOSPathProbe.resolve(
                host: serverAddress, port: serverPort, interface: interface)
            guard revision == observationRevision,
                  let current = active,
                  current.transport === state.transport,
                  current.generation == state.generation,
                  engine?.isActiveRoamingGeneration(
                    transport: state.transport, generation: state.generation) == true else {
                throw CancellationError()
            }
            updateID &+= 1
            guard updateID != 0 else {
                throw IOSRoamingError.invalidState("path update id overflow")
            }
            let flags = QeliPathFlags(
                defaultRouteChanged: reason == "default_route_changed",
                wake: reason == "wake",
                sameNetworkNatFailure: reason == "same_network_nat_failure")
            let update = QeliPathUpdate(
                generation: state.generation,
                updateID: updateID,
                platformPathID: probe.pathID,
                reason: reason,
                networkToken: probe.token,
                interfaceIndex: probe.interfaceIndex,
                localAddresses: [probe.localAddress],
                resolvedAddresses: [QeliPathResolution(
                    address: probe.remoteAddress, ttlSeconds: 0)],
                flags: flags)
            if observations.count >= 16, let oldest = observations.keys.min() {
                observations.removeValue(forKey: oldest)
            }
            observations[update.updateID] = update
            let candidate = try state.transport.pathUpdate(update)
            engine?.roamingLog(
                "Submitted iOS roaming candidate \(candidate): \(reason), \(update.platformPathID)")
            return true
        } catch is CancellationError {
            return false
        } catch {
            engine?.roamingLog("WARN: iOS roaming path observation failed: \(error.localizedDescription)")
            if reconnectOnFailure {
                engine?.requestRoamingReconnect(
                    transport: state.transport, generation: state.generation,
                    reason: "Soft roaming failed (\(error.localizedDescription))")
            }
            return false
        }
    }

    func apply(command: QeliPathCommand, transport: QeliNativeTransport) async throws {
        guard let state = active, state.transport === transport,
              state.generation == command.generation,
              engine?.isActiveRoamingGeneration(
                transport: transport, generation: command.generation) == true else {
            throw IOSRoamingError.invalidState("stale iOS roaming command")
        }
        switch command.action {
        case "prepare_path": try await prepare(command, state: state)
        case "bind_socket": try bind(command)
        case "commit_path": try await commit(command, transport: transport)
        case "abort_path": try await abort(command, transport: transport)
        default: throw IOSRoamingError.invalidState("unsupported iOS roaming action")
        }
    }

    private func prepare(_ command: QeliPathCommand, state: Active) async throws {
        guard candidates.isEmpty else {
            throw IOSRoamingError.invalidState("another iOS roaming candidate is active")
        }
        guard observations[command.path.updateID] == command.path else {
            throw IOSRoamingError.invalidState("iOS PREPARE does not match its observation")
        }
        let next = distinct(command.path.resolvedAddresses.map(\.address))
        let union = distinct(state.carrierAddresses + next)
        let candidate = Candidate(
            generation: command.generation, candidateID: command.candidateID,
            path: command.path, oldCarriers: state.carrierAddresses,
            newCarriers: next, unionCarriers: union, bound: false)
        candidates[command.candidateID] = candidate
        do {
            try await requireEngine().applyRoamingCarrierExclusions(
                union, transport: state.transport, generation: state.generation)
            engine?.roamingLog(
                "iOS roaming PREPARE \(command.candidateID): \(union.joined(separator: ", "))")
        } catch {
            do {
                try await requireEngine().applyRoamingCarrierExclusions(
                    state.carrierAddresses, transport: state.transport, generation: state.generation)
                candidates.removeValue(forKey: command.candidateID)
                rolledBack[command.candidateID] = command.path
            } catch let rollbackError {
                throw IOSRoamingError.platformStateUnknown(
                    "iOS PREPARE failed (\(error.localizedDescription)); rollback failed "
                        + "(\(rollbackError.localizedDescription))")
            }
            throw error
        }
    }

    private func bind(_ command: QeliPathCommand) throws {
        var candidate = try candidate(for: command)
        guard !candidate.bound, let fd = command.socketFD,
              let index = command.path.interfaceIndex,
              let name = command.path.networkToken?.split(separator: ":").first.map(String.init)
        else { throw IOSRoamingError.invalidState("invalid or repeated iOS BIND") }
        try IOSRoamingSocket.bind(
            borrowedFD: fd, interfaceName: name, interfaceIndex: index,
            localAddresses: command.path.localAddresses)
        candidate.bound = true
        candidates[command.candidateID] = candidate
        engine?.roamingLog(
            "iOS roaming BIND \(command.candidateID): fd \(fd) -> \(name)/\(index)")
    }

    private func commit(
        _ command: QeliPathCommand, transport: QeliNativeTransport
    ) async throws {
        let candidate = try candidate(for: command)
        guard candidate.bound else {
            throw IOSRoamingError.invalidState("iOS COMMIT arrived before BIND")
        }
        do {
            try await requireEngine().applyRoamingCarrierExclusions(
                candidate.newCarriers, transport: transport, generation: command.generation)
            try requireEngine().commitRoamingCarriers(
                candidate.newCarriers, transport: transport, generation: command.generation)
        } catch {
            do {
                try await requireEngine().applyRoamingCarrierExclusions(
                    candidate.unionCarriers, transport: transport, generation: command.generation)
            } catch let rollbackError {
                throw IOSRoamingError.platformStateUnknown(
                    "iOS COMMIT failed (\(error.localizedDescription)); policy rollback failed "
                        + "(\(rollbackError.localizedDescription))")
            }
            throw error
        }
        if var state = active, state.transport === transport {
            state.carrierAddresses = candidate.newCarriers
            active = state
        }
        candidates.removeValue(forKey: command.candidateID)
        observations.removeValue(forKey: command.path.updateID)
        engine?.roamingLog("iOS roaming COMMIT \(command.candidateID)")
    }

    private func abort(
        _ command: QeliPathCommand, transport: QeliNativeTransport
    ) async throws {
        if rolledBack[command.candidateID] == command.path {
            rolledBack.removeValue(forKey: command.candidateID)
            observations.removeValue(forKey: command.path.updateID)
            return
        }
        let candidate = try candidate(for: command)
        try await requireEngine().applyRoamingCarrierExclusions(
            candidate.oldCarriers, transport: transport, generation: command.generation)
        candidates.removeValue(forKey: command.candidateID)
        observations.removeValue(forKey: command.path.updateID)
        engine?.roamingLog("iOS roaming ABORT \(command.candidateID)")
    }

    private func candidate(for command: QeliPathCommand) throws -> Candidate {
        guard let candidate = candidates[command.candidateID],
              candidate.generation == command.generation,
              candidate.path == command.path else {
            throw IOSRoamingError.invalidState("stale or mismatched iOS roaming candidate")
        }
        return candidate
    }

    private func requireEngine() throws -> QeliNativeTunnelEngine {
        guard let engine else { throw IOSRoamingError.unavailable("iOS tunnel engine is gone") }
        return engine
    }

    private func distinct(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }
}
