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
/// iOS trust store and copies bounded IP batches between `NEPacketTunnelFlow` and the current
/// ABI 1.10 contract (using the packet seam introduced in ABI 1.7).
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
    private var attemptFailureMessage: String?
    private var carrierAddresses: [String] = []
    private var activePlan: NativeNetworkPlan?
    private var stopped = false
    private var networkSettingsGeneration: UInt64 = 0
    private var snapshot: TunnelSnapshot
    private var sampledUpload: UInt64 = 0
    private var sampledDownload: UInt64 = 0
    private var lastStatsDate = Date()
    private var udpKernelDrops: UInt64 = 0
    private var udpInternalDrops: UInt64 = 0
    private var udpBufferGrows: UInt64 = 0
    private var udpRecvBufferBytes: UInt64 = 0

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
        // Resolve all A records before installing even the bootstrap TUN. Each reconnect also
        // refreshes this set; a temporarily unavailable resolver falls back to these last-known
        // addresses so DDNS support never makes an ordinary outage less recoverable.
        let resolvedCarriers = try Self.resolveIPv4Candidates(config.serverAddress)
        let transport = try QeliNativeTransport(config: try config.toTransportCoreINI())
        try transport.setDeviceID(try SecureIdentityStore().deviceID())
        try await applyBootstrapSettings()
        try transport.start()

        let installed = stateLock.withLock { () -> Bool in
            guard !stopped else { return false }
            native = transport
            carrierAddresses = resolvedCarriers
            runnerResult = nil
            attemptFailureMessage = nil
            return true
        }
        guard installed else { transport.stop(); throw CancellationError() }

        update(phase: .connecting, message: "Opening native Rust transport…")
        let runtimeInput = try runtimeInput(carrierAddresses: resolvedCarriers)
        let runner = Task.detached(priority: .userInitiated) { [weak self, transport] in
            let result = transport.run(runtimeInput: runtimeInput)
            if let self {
                self.stateLock.withLock {
                    if self.native === transport { self.runnerResult = result }
                }
            }
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
        sharedStore.appendLog("Native ABI 1.10 transport started; TUN remains fail-closed until NetworkPlan ACK")
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

    private func runtimeInput(carrierAddresses: [String]) throws -> String {
        // Explicit dns_servers or the authenticated server push are the only DNS sources.
        let envelope: [String: Any] = [
            "fallback_dns_servers": [String](),
            "carrier_addresses": carrierAddresses,
        ]
        let data = try JSONSerialization.data(withJSONObject: envelope, options: [])
        guard let text = String(data: data, encoding: .utf8) else {
            throw QeliNativeError.invalidInput("Could not serialize native runtime input.")
        }
        return text
    }

    private func supervise(_ initialTransport: QeliNativeTransport) async {
        var transport: QeliNativeTransport? = initialTransport
        var pendingFailure: Error?
        var failureCount = 0
        var carrierGeneration = 0
        var attemptStarted = Date()
        let policy = ReconnectPolicy(config: config)
        while !Task.isCancelled, !stateLock.withLock({ stopped }) {
            var failure = pendingFailure
            var sessionWasEstablished = false
            pendingFailure = nil

            if let active = transport {
                do {
                    try await monitorAttempt(active)
                    return
                } catch is CancellationError {
                    return
                } catch {
                    failure = error
                    sessionWasEstablished = stateLock.withLock({ snapshot.phase == .connected })
                    cleanupAttempt(active)
                    transport = nil
                }
            }

            guard let failure else { return }
            if Self.isTerminalReconnectError(failure) {
                terminalFailure(failure)
                return
            }

            failureCount = policy.nextFailureCount(
                previous: failureCount,
                sessionWasEstablished: sessionWasEstablished
            )
            let elapsed = max(0, Int(Date().timeIntervalSince(attemptStarted) * 1_000))
            switch policy.decision(
                failureCount: failureCount,
                millisecondsSinceAttemptStarted: elapsed
            ) {
            case .stop(.disabled):
                terminalFailure(NativeTunnelError.transportStopped(
                    "Native transport stopped and reconnect is disabled."
                ))
                return
            case .stop(.retryLimitReached):
                terminalFailure(NativeTunnelError.transportStopped(
                    "Maximum reconnect retries reached."
                ))
                return
            case .retry(let attempt, let delayMilliseconds):
                provider.reasserting = true
                update(
                    phase: .connecting,
                    message: "Reconnect attempt \(max(1, attempt)) in \(delayMilliseconds) ms"
                )
                if delayMilliseconds > 0 {
                    do {
                        try await Task.sleep(
                            nanoseconds: UInt64(delayMilliseconds) * 1_000_000
                        )
                    } catch { return }
                }
            }

            do {
                carrierGeneration &+= 1
                let latest: [String]
                do {
                    latest = try Self.resolveIPv4Candidates(config.serverAddress)
                    let previous = stateLock.withLock { carrierAddresses }
                    if latest != previous {
                        sharedStore.appendLog(
                            "Physical carrier DNS refreshed: "
                                + "\(previous.joined(separator: ", ")) -> "
                                + latest.joined(separator: ", ")
                        )
                    }
                    stateLock.withLock { carrierAddresses = latest }
                } catch {
                    latest = stateLock.withLock { carrierAddresses }
                    guard !latest.isEmpty else { throw error }
                    sharedStore.appendLog(
                        "WARN: carrier DNS refresh failed (\(error.localizedDescription)); "
                            + "retaining last known \(latest.joined(separator: ", "))"
                    )
                }
                let rotated = Self.rotated(latest, by: carrierGeneration)
                transport = try launchReconnectTransport(carrierAddresses: rotated)
                attemptStarted = Date()
                sharedStore.appendLog(
                    "Native reconnect uses carrier candidates: \(rotated.joined(separator: ", "))"
                )
            } catch is CancellationError {
                return
            } catch {
                // Creating a new native generation can itself fail transiently. Feed that error
                // through the same retry budget instead of turning the first failed restart into
                // a provider-terminal failure.
                pendingFailure = error
                attemptStarted = Date()
            }
        }
    }

    private func monitorAttempt(_ transport: QeliNativeTransport) async throws {
        var nativeError: String?
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
                    stateLock.withLock({ attemptFailureMessage })
                        ?? nativeError ?? "Native transport stopped (\(result))"
                )
            }
            try await Task.sleep(nanoseconds: Self.pollNanoseconds)
        }
    }

    private func launchReconnectTransport(carrierAddresses: [String]) throws -> QeliNativeTransport {
        let next = try QeliNativeTransport(config: try config.toTransportCoreINI())
        try next.setDeviceID(try SecureIdentityStore().deviceID())
        let input = try runtimeInput(carrierAddresses: carrierAddresses)
        try next.start()
        let installed = stateLock.withLock { () -> Bool in
            guard !stopped else { return false }
            native = next
            runnerResult = nil
            attemptFailureMessage = nil
            return true
        }
        guard installed else {
            next.stop()
            throw CancellationError()
        }

        // Install the handle before launching run(): a fast synchronous failure must still be
        // observable by the supervisor rather than being lost before `native === next` is true.
        let runner = Task.detached(priority: .userInitiated) { [weak self, next] in
            let result = next.run(runtimeInput: input)
            if let self {
                self.stateLock.withLock {
                    if self.native === next { self.runnerResult = result }
                }
            }
        }
        let retained = stateLock.withLock { () -> Bool in
            guard !stopped, native === next else { return false }
            runnerTask = runner
            return true
        }
        guard retained else {
            runner.cancel()
            next.stop()
            throw CancellationError()
        }
        return next
    }

    private func cleanupAttempt(_ transport: QeliNativeTransport) {
        let tasks = stateLock.withLock { () -> (
            Task<Void, Never>?, Task<Void, Never>?, Task<Void, Never>?, Task<Void, Never>?
        ) in
            let ownsTransport = native === transport
            let value = (
                uplinkTask,
                downlinkTask,
                statsTask,
                ownsTransport ? runnerTask : nil
            )
            uplinkTask = nil
            downlinkTask = nil
            statsTask = nil
            activePlan = nil
            runnerResult = nil
            attemptFailureMessage = nil
            if ownsTransport {
                native = nil
                runnerTask = nil
            }
            sampledUpload = 0
            sampledDownload = 0
            return value
        }
        tasks.0?.cancel()
        tasks.1?.cancel()
        tasks.2?.cancel()
        transport.stop()
        tasks.3?.cancel()
    }

    private static func isTerminalReconnectError(_ error: Error) -> Bool {
        guard let native = error as? NativeTunnelError else { return false }
        switch native {
        case .invalidNetworkPlan, .invalidServerIdentity, .serverKeyMismatch,
             .unsupportedDNSPort:
            return true
        case .networkSettingsTimedOut, .sessionUnavailable, .packetInjectionFailed,
             .transportStopped:
            return false
        }
    }

    private static func rotated(_ values: [String], by generation: Int) -> [String] {
        guard !values.isEmpty else { return values }
        let offset = generation % values.count
        return Array(values[offset...]) + Array(values[..<offset])
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
        guard plan.fullTunnel == config.isFullTunnel else {
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
                    do {
                        try store.rememberHostKey(bytes, endpoint: identity.serverId)
                    } catch {
                        guard config.allowUnpinnedTofu else { throw error }
                        sharedStore.appendLog(
                            "WARN: could not persist the proven server key; continuing " +
                            "unpinned because allow_unpinned_tofu = true"
                        )
                    }
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
                        if !Task.isCancelled { self.failAttempt(error, transport: transport) }
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
                    self.failAttempt(error, transport: transport)
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

    /// Packet-pump failures are generation failures, not provider-terminal failures. Recording
    /// the message and stopping this native handle wakes the supervisor, which applies the same
    /// reconnect policy as a carrier/heartbeat disconnect while NetworkExtension stays
    /// fail-closed.
    private func failAttempt(_ error: Error, transport: QeliNativeTransport) {
        stateLock.withLock {
            guard !stopped, native === transport else { return }
            attemptFailureMessage = error.localizedDescription
        }
        sharedStore.appendLog("Native generation failed: \(error.localizedDescription)")
        transport.stop()
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
        let plannedIPv4Routes = plan.routes.compactMap { Self.ipv4Route($0.cidr) }
        let plannedIPv6Routes = plan.routes.compactMap { Self.ipv6Route($0.cidr) }
        guard plannedIPv4Routes.count + plannedIPv6Routes.count == plan.routes.count else {
            throw NativeTunnelError.invalidNetworkPlan
        }
        var included = plannedIPv4Routes
        if plan.fullTunnel { included.append(.default()) }
        ipv4.includedRoutes = Self.deduplicated(included)

        var excluded = config.excludeRoutes.compactMap(Self.ipv4Route)
        var excludedIPv6 = config.excludeRoutes.compactMap(Self.ipv6Route)
        guard excluded.count + excludedIPv6.count == config.excludeRoutes.count else {
            throw NativeTunnelError.invalidNetworkPlan
        }
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

        if (plan.fullTunnel && !config.allowIPv6Leak) || !plannedIPv6Routes.isEmpty {
            let ipv6 = NEIPv6Settings(
                addresses: ["fd00:7165:6c69::2"],
                networkPrefixLengths: [64]
            )
            var includedIPv6 = plannedIPv6Routes
            if plan.fullTunnel && !config.allowIPv6Leak { includedIPv6.append(.default()) }
            ipv6.includedRoutes = Self.deduplicated(includedIPv6)
            if config.allowLAN || SettingsStore().load().allowLAN {
                excludedIPv6 += [
                    NEIPv6Route(destinationAddress: "fe80::", networkPrefixLength: NSNumber(value: 10)),
                    NEIPv6Route(destinationAddress: "fc00::", networkPrefixLength: NSNumber(value: 7)),
                    NEIPv6Route(destinationAddress: "ff00::", networkPrefixLength: NSNumber(value: 8))
                ]
            }
            ipv6.excludedRoutes = Self.deduplicated(excludedIPv6)
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
        var udpLog: String?
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
            if stats.udpRecvBufferBytes != udpRecvBufferBytes
                || stats.udpKernelDrops != udpKernelDrops
                || stats.udpInternalDrops != udpInternalDrops
                || stats.udpBufferGrows != udpBufferGrows {
                udpLog = "UDP buffers: granted=\(stats.udpRecvBufferBytes / 1024) KiB "
                    + "kernel_drops=\(stats.udpKernelDrops) "
                    + "internal_drops=\(stats.udpInternalDrops) "
                    + "grows=\(stats.udpBufferGrows)"
                udpRecvBufferBytes = stats.udpRecvBufferBytes
                udpKernelDrops = stats.udpKernelDrops
                udpInternalDrops = stats.udpInternalDrops
                udpBufferGrows = stats.udpBufferGrows
            }
            snapshot.updatedAt = now
            sharedStore.save(snapshot)
        }
        if let udpLog { sharedStore.appendLog(udpLog) }
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
        let parts = cidr.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let destination = parts.first.map(String.init) ?? ""
        let prefix = parts.count == 1 ? 32 : Int(parts[1])
        guard let prefix, (0...32).contains(prefix), isIPv4Address(destination) else {
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

    private static func ipv6Route(_ cidr: String) -> NEIPv6Route? {
        let parts = cidr.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let destination = parts.first.map(String.init) ?? ""
        let prefix = parts.count == 1 ? 128 : Int(parts[1])
        guard let prefix, (0...128).contains(prefix), isIPv6Address(destination) else {
            return nil
        }
        return NEIPv6Route(
            destinationAddress: destination,
            networkPrefixLength: NSNumber(value: prefix)
        )
    }

    private static func isIPv6Address(_ text: String) -> Bool {
        var address = in6_addr()
        return text.withCString { inet_pton(AF_INET6, $0, &address) } == 1
    }

    private static func resolveIPv4Candidates(_ host: String) throws -> [String] {
        var hints = addrinfo()
        hints.ai_flags = AI_ADDRCONFIG
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var head: UnsafeMutablePointer<addrinfo>?
        let status = host.withCString { getaddrinfo($0, nil, &hints, &head) }
        guard status == 0, let first = head else {
            let reason = status == 0 ? "no IPv4 result" : String(cString: gai_strerror(status))
            throw NativeTunnelError.transportStopped(
                "Could not resolve \(host) on the physical network: \(reason)"
            )
        }
        defer { freeaddrinfo(first) }
        var output: [String] = []
        var seen = Set<String>()
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let item = cursor {
            if item.pointee.ai_family == AF_INET, let raw = item.pointee.ai_addr {
                var address = UnsafeRawPointer(raw)
                    .assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &address, &buffer, socklen_t(buffer.count)) != nil {
                    let value = String(cString: buffer)
                    if seen.insert(value).inserted { output.append(value) }
                }
            }
            cursor = item.pointee.ai_next
        }
        guard !output.isEmpty else {
            throw NativeTunnelError.transportStopped("\(host) has no IPv4 carrier address.")
        }
        return output
    }

    private static func deduplicated(_ routes: [NEIPv4Route]) -> [NEIPv4Route] {
        var seen = Set<String>()
        return routes.filter {
            seen.insert("\($0.destinationAddress)/\($0.destinationSubnetMask)").inserted
        }
    }

    private static func deduplicated(_ routes: [NEIPv6Route]) -> [NEIPv6Route] {
        var seen = Set<String>()
        return routes.filter {
            seen.insert("\($0.destinationAddress)/\($0.destinationNetworkPrefixLength)").inserted
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
