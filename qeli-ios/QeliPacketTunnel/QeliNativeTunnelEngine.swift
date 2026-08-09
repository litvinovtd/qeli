import Darwin
import Foundation
import NetworkExtension

private struct NativeNetworkPlan: Decodable, Sendable {
    var generation: UInt64
    var tunnelAddress: String
    var prefixLen: Int
    var mtu: Int
    var tunnelGateway: String
    var carrierAddress: String?
    var routes: [NativeNetworkRoute]
    var pushedRoutes: [String]
    var dnsServers: [NativeNetworkDNS]
    var fullTunnel: Bool
    var killSwitch: Bool
    var maxStreams: Int
    var adaptive: Bool
    var dataPlane: NativeDataPlaneFacts
    var connectionLog: [String]?
}

private struct NativeNetworkRoute: Decodable, Sendable {
    var cidr: String
    var gateway: String
    var metric: UInt32
}

private struct NativeNetworkDNS: Decodable, Sendable {
    var address: String
    var port: Int
}

private struct NativeDataPlaneFacts: Decodable, Sendable {
    var paddingEnabled: Bool
    var paddingMin: Int
    var paddingMax: Int
    var heartbeatEnabled: Bool
    var heartbeatIntervalMs: Int
    var shapingEnabled: Bool
}

private struct NativeServerIdentity: Decodable, Sendable {
    var serverId: String
    var publicKey: String
}

private actor NativeSettingsGate {
    private var held = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !held { held = true; return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        if waiters.isEmpty { held = false } else { waiters.removeFirst().resume() }
    }
}

private final class NativeSettingsCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Result<Void, Error>, Never>?
    private var finished = false

    func park(_ value: CheckedContinuation<Result<Void, Error>, Never>) {
        let immediate = lock.withLock { () -> Bool in
            if finished { return true }
            continuation = value
            return false
        }
        if immediate { value.resume(returning: .failure(NativeTunnelError.networkSettingsTimedOut)) }
    }

    func finish(_ result: Result<Void, Error>) {
        let pending = lock.withLock { () -> CheckedContinuation<Result<Void, Error>, Never>? in
            guard !finished else { return nil }
            finished = true
            defer { continuation = nil }
            return continuation
        }
        pending?.resume(returning: result)
    }
}

/// NetworkExtension adapter for the shared Rust transport core.
///
/// The adapter owns no wire protocol. It applies authenticated network plans, enforces the
/// iOS trust store and copies bounded IP batches between `NEPacketTunnelFlow` and ABI 1.8.
final class QeliNativeTunnelEngine: @unchecked Sendable {
    private static let settingsTimeoutMilliseconds = 15_000
    private static let pollNanoseconds: UInt64 = 10_000_000
    private static let emptyPullNanoseconds: UInt64 = 1_000_000

    private unowned let provider: PacketTunnelProvider
    private let profile: Profile
    private let config: VPNConfig
    private let sharedStore: SharedTunnelStore
    private let stateLock = NSLock()
    private let packetWriteLock = NSLock()
    private let settingsGate = NativeSettingsGate()

    private var native: QeliNativeTransport?
    private var supervisorTask: Task<Void, Never>?
    private var runnerTask: Task<Void, Never>?
    private var uplinkTask: Task<Void, Never>?
    private var downlinkTask: Task<Void, Never>?
    private var statsTask: Task<Void, Never>?
    private var runnerResult: Int32?
    private var activePlan: NativeNetworkPlan?
    private var stopped = false
    private var networkSettingsGeneration: UInt64 = 0
    private var snapshot: TunnelSnapshot
    private var sampledUpload: UInt64 = 0
    private var sampledDownload: UInt64 = 0
    private var lastStatsDate = Date()

    init(
        provider: PacketTunnelProvider,
        profile: Profile,
        config: VPNConfig,
        sharedStore: SharedTunnelStore
    ) {
        self.provider = provider
        self.profile = profile
        self.config = config
        self.sharedStore = sharedStore
        var initial = TunnelSnapshot()
        initial.phase = .preparing
        initial.profileID = profile.id
        initial.message = "Preparing native transport…"
        initial.updatedAt = Date()
        snapshot = initial
        sharedStore.save(initial)
    }

    func start() async throws {
        // Re-serialize through the iOS model so platform-unsupported keys (notably the
        // Linux/desktop `kill_switch`) keep their documented iOS semantics instead of making
        // the Rust plan require a capability NetworkExtension cannot provide.
        let transport = try QeliNativeTransport(config: try config.toINI())
        try transport.setDeviceID(try SecureIdentityStore().deviceID())
        try await applyBootstrapSettings()
        try transport.start()

        let installed = stateLock.withLock { () -> Bool in
            guard !stopped else { return false }
            native = transport
            return true
        }
        guard installed else { transport.stop(); throw CancellationError() }

        update(phase: .connecting, message: "Opening native Rust transport…")
        let runner = Task.detached(priority: .userInitiated) { [weak self, transport] in
            let result = transport.run(runtimeInput: self?.runtimeInput() ?? "{}")
            if let self { self.stateLock.withLock { self.runnerResult = result } }
        }
        let supervisor = Task { [weak self, transport] in
            guard let self else { return }
            await self.supervise(transport)
        }
        let retained = stateLock.withLock { () -> Bool in
            guard !stopped else { return false }
            runnerTask = runner
            supervisorTask = supervisor
            return true
        }
        if !retained {
            runner.cancel()
            supervisor.cancel()
            transport.stop()
            throw CancellationError()
        }
        sharedStore.appendLog("Native ABI 1.8 transport started; TUN remains fail-closed until NetworkPlan ACK")
    }

    func stop() async {
        let resources = stateLock.withLock { () -> (
            QeliNativeTransport?, Task<Void, Never>?, Task<Void, Never>?,
            Task<Void, Never>?, Task<Void, Never>?, Task<Void, Never>?, Bool, Bool
        ) in
            guard !stopped else {
                return (nil, nil, nil, nil, nil, nil, snapshot.phase == .error, false)
            }
            stopped = true
            networkSettingsGeneration &+= 1
            let value = (native, supervisorTask, runnerTask, uplinkTask, downlinkTask, statsTask,
                         snapshot.phase == .error, true)
            native = nil
            supervisorTask = nil
            runnerTask = nil
            uplinkTask = nil
            downlinkTask = nil
            statsTask = nil
            activePlan = nil
            return value
        }
        guard resources.7 else { return }
        provider.reasserting = false
        resources.1?.cancel()
        resources.3?.cancel()
        resources.4?.cancel()
        resources.5?.cancel()
        resources.0?.stop()
        resources.2?.cancel()
        if !resources.6 { resetSnapshot(phase: .disconnected, message: "", error: nil) }
        sharedStore.appendLog("Native tunnel stopped")
    }

    func wake() {
        guard !stateLock.withLock({ stopped }) else { return }
        sharedStore.appendLog("Device woke; Rust transport liveness remains active")
    }

    func currentSnapshot() -> TunnelSnapshot { stateLock.withLock { snapshot } }

    func reloadNetworkSettings() async throws {
        guard let plan = stateLock.withLock({ stopped ? nil : activePlan }) else {
            throw NativeTunnelError.sessionUnavailable
        }
        try await applyNetworkSettings(plan)
        sharedStore.appendLog("Native NetworkPlan settings reloaded")
    }

    private func runtimeInput() -> String {
        guard config.isFullTunnel else { return "{}" }
        return #"{"fallback_dns_servers":["1.1.1.1","8.8.8.8"]}"#
    }

    private func supervise(_ transport: QeliNativeTransport) async {
        var nativeError: String?
        do {
            while !Task.isCancelled, !stateLock.withLock({ stopped }) {
                var drained = false
                while let event = try transport.pollEvent() {
                    drained = true
                    switch event.kind {
                    case 1:
                        if event.state == 3, let plan = stateLock.withLock({ activePlan }) {
                            provider.reasserting = false
                            publishConnected(plan)
                        }
                    case 2:
                        try await acceptNetworkPlan(event, transport: transport)
                    case 3:
                        nativeError = event.payload.isEmpty
                            ? "Native transport error \(event.errorCode)"
                            : event.payload
                        sharedStore.appendLog(
                            "ERROR: native transport \(event.errorCode): \(nativeError ?? "unknown error")"
                        )
                    case 5:
                        try acceptServerIdentity(event, transport: transport)
                    default:
                        break
                    }
                }
                if let result = stateLock.withLock({ runnerResult }), !drained {
                    if stateLock.withLock({ stopped }) { return }
                    throw NativeTunnelError.transportStopped(
                        nativeError ?? "Native transport stopped (\(result))"
                    )
                }
                try await Task.sleep(nanoseconds: Self.pollNanoseconds)
            }
        } catch is CancellationError {
            return
        } catch {
            terminalFailure(error)
            transport.stop()
        }
    }

    private func acceptNetworkPlan(
        _ event: QeliTransportEvent,
        transport: QeliNativeTransport
    ) async throws {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let plan = try decoder.decode(NativeNetworkPlan.self, from: Data(event.payload.utf8))
        guard plan.generation != 0, plan.generation == event.planGeneration else {
            throw NativeTunnelError.invalidNetworkPlan
        }
        sharedStore.appendLog("Auth OK, IP \(plan.tunnelAddress)")
        (plan.connectionLog ?? []).forEach { sharedStore.appendLog($0) }
        do {
            try await applyNetworkSettings(plan)
            try transport.networkPlanResult(generation: plan.generation, accepted: true)
            stateLock.withLock { activePlan = plan }
            startPacketPumps(transport: transport, generation: plan.generation)
            let dns = plan.dnsServers.isEmpty
                ? "system unchanged"
                : plan.dnsServers.map { "\($0.address):\($0.port)" }.joined(separator: ", ")
            sharedStore.appendLog(
                "Native NetworkPlan \(plan.generation) APPLIED: " +
                "mode=\(plan.fullTunnel ? "full" : "split") " +
                "address=\(plan.tunnelAddress)/\(plan.prefixLen) mtu=\(plan.mtu) " +
                "dns=\(dns) plan_routes=\(plan.routes.count) " +
                "pushed_routes=\(plan.pushedRoutes.count)"
            )
        } catch {
            sharedStore.appendLog(
                "ERROR: Native NetworkPlan \(plan.generation) REJECTED: \(error.localizedDescription)"
            )
            try? transport.networkPlanResult(
                generation: plan.generation,
                accepted: false,
                reason: error.localizedDescription
            )
            throw error
        }
    }

    private func acceptServerIdentity(
        _ event: QeliTransportEvent,
        transport: QeliNativeTransport
    ) throws {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        do {
            let identity = try decoder.decode(NativeServerIdentity.self, from: Data(event.payload.utf8))
            let expectedEndpoint = "\(config.serverAddress):\(config.port)"
            guard identity.serverId == expectedEndpoint,
                  let received = Self.normalizedKey(identity.publicKey) else {
                throw NativeTunnelError.invalidServerIdentity
            }
            if let pinnedText = config.serverPublicKeyHex, !pinnedText.isEmpty {
                guard Self.normalizedKey(pinnedText) == received else {
                    throw NativeTunnelError.serverKeyMismatch
                }
            } else {
                let store = SecureIdentityStore()
                let bytes = Self.decodeHex(received)
                if let remembered = try store.knownHostKey(endpoint: identity.serverId) {
                    guard remembered == bytes else { throw NativeTunnelError.serverKeyMismatch }
                } else {
                    try store.rememberHostKey(bytes, endpoint: identity.serverId)
                }
            }
            try transport.serverIdentityResult(sequence: event.sequence, accepted: true)
        } catch {
            try? transport.serverIdentityResult(
                sequence: event.sequence,
                accepted: false,
                reason: error.localizedDescription
            )
            throw error
        }
    }

    private func startPacketPumps(transport: QeliNativeTransport, generation: UInt64) {
        let previous = stateLock.withLock { () -> (Task<Void, Never>?, Task<Void, Never>?, Task<Void, Never>?) in
            let value = (uplinkTask, downlinkTask, statsTask)
            uplinkTask = nil
            downlinkTask = nil
            statsTask = nil
            return value
        }
        previous.0?.cancel()
        previous.1?.cancel()
        previous.2?.cancel()

        let uplink = Task { [weak self, transport] in
            guard let self else { return }
            while !Task.isCancelled, !self.stateLock.withLock({ self.stopped }) {
                let (packets, protocols) = await self.readPackets()
                if Task.isCancelled { return }
                let ipv4 = zip(packets, protocols).compactMap { pair in
                    pair.1.int32Value == AF_INET ? pair.0 : nil
                }
                var offset = 0
                while offset < ipv4.count, !Task.isCancelled {
                    do {
                        let accepted = try transport.pushPackets(ipv4[offset...], generation: generation)
                        if accepted == 0 {
                            try await Task.sleep(nanoseconds: Self.emptyPullNanoseconds)
                        } else {
                            offset += accepted
                        }
                    } catch {
                        if !Task.isCancelled { self.terminalFailure(error); transport.stop() }
                        return
                    }
                }
            }
        }
        let downlink = Task { [weak self, transport] in
            guard let self else { return }
            while !Task.isCancelled, !self.stateLock.withLock({ self.stopped }) {
                do {
                    let packets = try transport.pullPackets(generation: generation)
                    if packets.isEmpty {
                        try await Task.sleep(nanoseconds: Self.emptyPullNanoseconds)
                        continue
                    }
                    let protocols = packets.map { packet in
                        NSNumber(value: packet.first.map { $0 >> 4 == 6 ? AF_INET6 : AF_INET } ?? AF_INET)
                    }
                    let accepted = self.packetWriteLock.withLock {
                        self.provider.packetFlow.writePackets(packets, withProtocols: protocols)
                    }
                    guard accepted else { throw NativeTunnelError.packetInjectionFailed }
                } catch is CancellationError {
                    return
                } catch {
                    self.terminalFailure(error)
                    transport.stop()
                    return
                }
            }
        }
        let stats = Task { [weak self, transport] in
            guard let self else { return }
            while !Task.isCancelled, !self.stateLock.withLock({ self.stopped }) {
                do { self.publishStats(try transport.stats()) } catch { return }
                try? await Task.sleep(nanoseconds: 250_000_000)
            }
        }
        let retained = stateLock.withLock { () -> Bool in
            guard !stopped, activePlan?.generation == generation else { return false }
            uplinkTask = uplink
            downlinkTask = downlink
            statsTask = stats
            return true
        }
        if !retained { uplink.cancel(); downlink.cancel(); stats.cancel() }
    }

    private func applyBootstrapSettings() async throws {
        let plan = NativeNetworkPlan(
            generation: 0,
            tunnelAddress: "198.18.0.1",
            prefixLen: 32,
            mtu: config.mtu > 0 ? config.mtu : 1_400,
            tunnelGateway: "198.18.0.1",
            carrierAddress: nil,
            routes: [],
            pushedRoutes: [],
            dnsServers: [],
            fullTunnel: config.isFullTunnel,
            killSwitch: false,
            maxStreams: 1,
            adaptive: false,
            dataPlane: NativeDataPlaneFacts(
                paddingEnabled: false,
                paddingMin: 0,
                paddingMax: 0,
                heartbeatEnabled: false,
                heartbeatIntervalMs: 0,
                shapingEnabled: false
            ),
            connectionLog: []
        )
        try await applyNetworkSettings(plan, publishFacts: false)
    }

    private func applyNetworkSettings(
        _ plan: NativeNetworkPlan,
        publishFacts: Bool = true
    ) async throws {
        guard (0...32).contains(plan.prefixLen),
              Self.isIPv4Address(plan.tunnelAddress),
              Self.isIPv4Address(plan.tunnelGateway),
              (VPNConfig.mtuMin...VPNConfig.mtuMax).contains(plan.mtu) else {
            throw NativeTunnelError.invalidNetworkPlan
        }
        let requestGeneration = stateLock.withLock { () -> UInt64 in
            networkSettingsGeneration &+= 1
            return networkSettingsGeneration
        }
        let network = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: plan.carrierAddress ?? config.serverAddress
        )
        let ipv4 = NEIPv4Settings(
            addresses: [plan.tunnelAddress],
            subnetMasks: [Self.ipv4Mask(prefixLength: plan.prefixLen)]
        )
        let plannedRoutes = plan.routes.compactMap { Self.ipv4Route($0.cidr) }
        guard plannedRoutes.count == plan.routes.count else {
            throw NativeTunnelError.invalidNetworkPlan
        }
        var included = plannedRoutes
        if plan.fullTunnel { included.append(.default()) }
        ipv4.includedRoutes = Self.deduplicated(included)

        var excluded = config.excludeRoutes.compactMap(Self.ipv4Route)
        if config.allowLAN || SettingsStore().load().allowLAN {
            excluded += [
                NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
                NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
                NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
                NEIPv4Route(destinationAddress: "169.254.0.0", subnetMask: "255.255.0.0"),
                NEIPv4Route(destinationAddress: "224.0.0.0", subnetMask: "240.0.0.0")
            ]
        }
        ipv4.excludedRoutes = Self.deduplicated(excluded)
        network.ipv4Settings = ipv4

        if plan.fullTunnel && !config.allowIPv6Leak {
            let ipv6 = NEIPv6Settings(
                addresses: ["fd00:7165:6c69::2"],
                networkPrefixLengths: [64]
            )
            ipv6.includedRoutes = [.default()]
            if config.allowLAN || SettingsStore().load().allowLAN {
                ipv6.excludedRoutes = [
                    NEIPv6Route(destinationAddress: "fe80::", networkPrefixLength: NSNumber(value: 10)),
                    NEIPv6Route(destinationAddress: "fc00::", networkPrefixLength: NSNumber(value: 7)),
                    NEIPv6Route(destinationAddress: "ff00::", networkPrefixLength: NSNumber(value: 8))
                ]
            }
            network.ipv6Settings = ipv6
        }

        if let unsupportedDNS = plan.dnsServers.first(where: { $0.port != 53 }) {
            throw NativeTunnelError.unsupportedDNSPort(
                address: unsupportedDNS.address,
                port: unsupportedDNS.port
            )
        }
        if config.dnsMode == "tunnel", !plan.dnsServers.isEmpty {
            network.dnsSettings = NEDNSSettings(servers: plan.dnsServers.map(\.address))
        }
        network.mtu = NSNumber(value: plan.mtu)

        await settingsGate.acquire()
        do {
            guard stateLock.withLock({ !stopped && networkSettingsGeneration == requestGeneration }) else {
                throw CancellationError()
            }
            let completion = NativeSettingsCompletion()
            let outcome: Result<Void, Error> = await withCheckedContinuation { continuation in
                completion.park(continuation)
                provider.setTunnelNetworkSettings(network) { error in
                    completion.finish(error.map { Result<Void, Error>.failure($0) } ?? .success(()))
                }
                DispatchQueue.global().asyncAfter(
                    deadline: .now() + .milliseconds(Self.settingsTimeoutMilliseconds)
                ) {
                    completion.finish(.failure(NativeTunnelError.networkSettingsTimedOut))
                }
            }
            try outcome.get()
            guard stateLock.withLock({ !stopped && networkSettingsGeneration == requestGeneration }) else {
                throw CancellationError()
            }
            await settingsGate.release()
        } catch {
            await settingsGate.release()
            throw error
        }

        if publishFacts {
            stateLock.withLock {
                snapshot.clientAddress = plan.tunnelAddress
                snapshot.pushedDNS = plan.dnsServers.first?.address
                snapshot.appliedMTU = plan.mtu
                snapshot.maxStreams = max(1, plan.maxStreams)
                snapshot.pushedRoutes = plan.pushedRoutes.count
                snapshot.pushed = PushedFacts(
                    routes: Array(plan.pushedRoutes.prefix(PushedFacts.routeSample)),
                    routeCount: plan.pushedRoutes.count,
                    routesInstalled: plan.pushedRoutes.count,
                    multipathAdaptive: plan.adaptive,
                    paddingEnabled: plan.dataPlane.paddingEnabled,
                    paddingMin: plan.dataPlane.paddingMin,
                    paddingMax: plan.dataPlane.paddingMax,
                    heartbeatEnabled: plan.dataPlane.heartbeatEnabled,
                    heartbeatIntervalMilliseconds: plan.dataPlane.heartbeatIntervalMs,
                    shapingEnabled: plan.dataPlane.shapingEnabled
                )
                snapshot.updatedAt = Date()
                sharedStore.save(snapshot)
            }
        }
    }

    private func readPackets() async -> ([Data], [NSNumber]) {
        final class ReadBox: @unchecked Sendable {
            private let lock = NSLock()
            private var continuation: CheckedContinuation<([Data], [NSNumber]), Never>?
            private var resumed = false

            func park(_ value: CheckedContinuation<([Data], [NSNumber]), Never>) -> Bool {
                lock.withLock {
                    if resumed { return false }
                    continuation = value
                    return true
                }
            }

            func finish(_ value: ([Data], [NSNumber])) {
                let pending = lock.withLock { () -> CheckedContinuation<([Data], [NSNumber]), Never>? in
                    guard !resumed else { return nil }
                    resumed = true
                    defer { continuation = nil }
                    return continuation
                }
                pending?.resume(returning: value)
            }
        }

        let box = ReadBox()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard box.park(continuation) else {
                    continuation.resume(returning: ([], []))
                    return
                }
                provider.packetFlow.readPackets { box.finish(($0, $1)) }
            }
        } onCancel: {
            box.finish(([], []))
        }
    }

    private func publishConnected(_ plan: NativeNetworkPlan) {
        stateLock.withLock {
            guard !stopped else { return }
            snapshot.phase = .connected
            snapshot.message = "Connected — Rust transport core"
            snapshot.error = nil
            snapshot.clientAddress = plan.tunnelAddress
            if snapshot.connectedAt == nil { snapshot.connectedAt = Date() }
            snapshot.updatedAt = Date()
            sharedStore.save(snapshot)
        }
    }

    private func publishStats(_ stats: QeliTransportStats) {
        let now = Date()
        stateLock.withLock {
            guard !stopped else { return }
            let elapsed = max(now.timeIntervalSince(lastStatsDate), 0.001)
            snapshot.bytesUploaded = stats.txBytes
            snapshot.bytesDownloaded = stats.rxBytes
            let uploaded = stats.txBytes >= sampledUpload ? stats.txBytes - sampledUpload : 0
            let downloaded = stats.rxBytes >= sampledDownload ? stats.rxBytes - sampledDownload : 0
            snapshot.uploadBytesPerSecond = UInt64(Double(uploaded) / elapsed)
            snapshot.downloadBytesPerSecond = UInt64(Double(downloaded) / elapsed)
            sampledUpload = stats.txBytes
            sampledDownload = stats.rxBytes
            lastStatsDate = now
            snapshot.updatedAt = now
            sharedStore.save(snapshot)
        }
    }

    private func update(phase: TunnelPhase, message: String, error: String? = nil) {
        stateLock.withLock {
            guard !stopped else { return }
            snapshot.phase = phase
            snapshot.message = message
            snapshot.error = error
            snapshot.updatedAt = Date()
            sharedStore.save(snapshot)
        }
        if !message.isEmpty { sharedStore.appendLog(message) }
    }

    private func terminalFailure(_ error: Error) {
        let changed = stateLock.withLock { () -> Bool in
            guard !stopped, snapshot.phase != .error else { return false }
            snapshot.phase = .error
            snapshot.message = error.localizedDescription
            snapshot.error = error.localizedDescription
            snapshot.updatedAt = Date()
            sharedStore.save(snapshot)
            return true
        }
        guard changed else { return }
        provider.reasserting = false
        sharedStore.appendLog("ERROR: \(error.localizedDescription)")
        provider.cancelTunnelWithError(error)
    }

    private func resetSnapshot(phase: TunnelPhase, message: String, error: String?) {
        stateLock.withLock {
            snapshot.phase = phase
            snapshot.message = message
            snapshot.error = error
            snapshot.clientAddress = nil
            snapshot.connectedAt = nil
            snapshot.bytesUploaded = 0
            snapshot.bytesDownloaded = 0
            snapshot.uploadBytesPerSecond = 0
            snapshot.downloadBytesPerSecond = 0
            snapshot.pushedDNS = nil
            snapshot.appliedMTU = nil
            snapshot.maxStreams = 1
            snapshot.pushedRoutes = 0
            snapshot.pushed = nil
            snapshot.updatedAt = Date()
            sharedStore.save(snapshot)
        }
    }

    private static func normalizedKey(_ text: String) -> String? {
        let value = text.filter { !$0.isWhitespace && $0 != ":" && $0 != "-" }.lowercased()
        guard value.count == 64, value.allSatisfy({ $0.isHexDigit }) else { return nil }
        return value
    }

    private static func decodeHex(_ text: String) -> Data {
        var output = Data(capacity: text.count / 2)
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            output.append(UInt8(text[index..<next], radix: 16)!)
            index = next
        }
        return output
    }

    private static func ipv4Mask(prefixLength: Int) -> String {
        let prefix = min(max(prefixLength, 0), 32)
        let bits = prefix == 0 ? UInt32(0) : UInt32.max << UInt32(32 - prefix)
        return [24, 16, 8, 0].map { String((bits >> UInt32($0)) & 0xff) }.joined(separator: ".")
    }

    private static func ipv4Route(_ cidr: String) -> NEIPv4Route? {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        let destination = parts.first.map(String.init) ?? ""
        guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix),
              isIPv4Address(destination) else {
            return nil
        }
        return NEIPv4Route(
            destinationAddress: destination,
            subnetMask: ipv4Mask(prefixLength: prefix)
        )
    }

    private static func isIPv4Address(_ text: String) -> Bool {
        var address = in_addr()
        return text.withCString { inet_pton(AF_INET, $0, &address) } == 1
    }

    private static func deduplicated(_ routes: [NEIPv4Route]) -> [NEIPv4Route] {
        var seen = Set<String>()
        return routes.filter {
            seen.insert("\($0.destinationAddress)/\($0.destinationSubnetMask)").inserted
        }
    }
}

private enum NativeTunnelError: LocalizedError {
    case invalidNetworkPlan
    case invalidServerIdentity
    case serverKeyMismatch
    case unsupportedDNSPort(address: String, port: Int)
    case networkSettingsTimedOut
    case sessionUnavailable
    case packetInjectionFailed
    case transportStopped(String)

    var errorDescription: String? {
        switch self {
        case .invalidNetworkPlan: return "The native core returned an invalid NetworkPlan."
        case .invalidServerIdentity: return "The native core returned an invalid server identity."
        case .serverKeyMismatch: return "SERVER KEY MISMATCH — possible MITM."
        case .unsupportedDNSPort(let address, let port):
            return "iOS cannot apply DNS \(address):\(port); only port 53 is supported."
        case .networkSettingsTimedOut: return "Applying iOS tunnel settings timed out."
        case .sessionUnavailable: return "No authenticated native tunnel session is active."
        case .packetInjectionFailed: return "iOS rejected a native downlink packet batch."
        case .transportStopped(let reason): return reason
        }
    }
}
