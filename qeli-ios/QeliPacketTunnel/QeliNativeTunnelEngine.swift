import Darwin
import Foundation
import Network
import NetworkExtension

private struct NativeNetworkPlan: Decodable, Sendable {
    var generation: UInt64
    var familyMode: String
    var addresses: [NativeNetworkAddress]
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
    var allowIpv4Leak: Bool
    var allowIpv6Leak: Bool
    var maxStreams: Int
    var adaptive: Bool
    var dataPlane: NativeDataPlaneFacts
    var connectionLog: [String]?
}

private struct NativeNetworkAddress: Decodable, Sendable {
    var family: String
    var address: String
    var prefixLen: Int
    var onLinkPrefixLen: Int
    var gateway: String?
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

private final class NativeDNSCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Result<[String], Error>, Never>?
    private var finished = false

    func park(_ value: CheckedContinuation<Result<[String], Error>, Never>) {
        let immediate = lock.withLock { () -> Bool in
            if finished { return true }
            continuation = value
            return false
        }
        if immediate {
            value.resume(returning: .failure(NativeTunnelError.dnsResolutionTimedOut))
        }
    }

    func finish(_ result: Result<[String], Error>) {
        let pending = lock.withLock {
            () -> CheckedContinuation<Result<[String], Error>, Never>? in
            guard !finished else { return nil }
            finished = true
            defer { continuation = nil }
            return continuation
        }
        pending?.resume(returning: result)
    }
}

/// `getaddrinfo` is blocking and cannot be cancelled. Without a process-wide gate every
/// reconnect timeout launched another global-queue worker while the previous resolver was
/// still wedged. The late call is allowed to finish, but only one may exist at a time.
private final class NativeDNSLimiter: @unchecked Sendable {
    private let lock = NSLock()
    private var active = false

    func begin() -> Bool {
        lock.withLock {
            guard !active else { return false }
            active = true
            return true
        }
    }

    func finish() { lock.withLock { active = false } }
}

/// NetworkExtension adapter for the shared Rust transport core.
///
/// The adapter owns no wire protocol. It applies authenticated network plans, enforces the
/// iOS trust store and copies bounded IP batches between `NEPacketTunnelFlow` and the current
/// ABI 1.15 core through the ABI 1.11 compatibility floor (using the packet seam introduced
/// in ABI 1.7).
final class QeliNativeTunnelEngine: @unchecked Sendable {
    private static let settingsTimeoutMilliseconds = 15_000
    private static let pollNanoseconds: UInt64 = 10_000_000
    private static let emptyPullNanoseconds: UInt64 = 1_000_000
    private static let dnsLimiter = NativeDNSLimiter()

    private unowned let provider: PacketTunnelProvider
    private let profile: Profile
    private let config: VPNConfig
    private let detailedLogging: Bool
    private let sharedStore: SharedTunnelStore
    private let stateLock = NSLock()
    private let packetWriteLock = NSLock()
    private let settingsGate = NativeSettingsGate()
    private lazy var roamingController = IOSRoamingController(
        engine: self,
        serverAddress: config.serverAddress,
        serverPort: UInt16(config.port))

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
    private var wakeGeneration: UInt64 = 0
    // A full-tunnel server-identity failure keeps NetworkExtension alive with the
    // already-installed blackhole/TUN routes. Cancelling the provider here removed
    // those routes and turned a detected MITM into a physical-network fail-open.
    private var failClosedSecurityHold = false
    private var networkSettingsGeneration: UInt64 = 0
    private var snapshot: TunnelSnapshot
    private var sampledUpload: UInt64 = 0
    private var sampledDownload: UInt64 = 0
    private var lastStatsDate = Date()
    private var udpKernelDrops: UInt64 = 0
    private var udpInternalDrops: UInt64 = 0
    private var udpBufferGrows: UInt64 = 0
    private var udpRecvBufferBytes: UInt64 = 0
    private var udpReportedKernelDrops: UInt64 = 0
    private var udpReportedInternalDrops: UInt64 = 0
    private var udpLastReportDate = Date()
    private var udpReadyLogged = false

    init(
        provider: PacketTunnelProvider,
        profile: Profile,
        config: VPNConfig,
        logLevel: String,
        sharedStore: SharedTunnelStore
    ) {
        self.provider = provider
        self.profile = profile
        self.config = config
        detailedLogging = ["debug", "trace"].contains(logLevel.lowercased())
        self.sharedStore = sharedStore
        var initial = TunnelSnapshot()
        initial.phase = .preparing
        initial.profileID = profile.id
        let globalAllowLAN = SettingsStore().load().allowLAN
        initial.privateUpdatePath = config.hasPrivateUpdatePath(
            globalAllowLAN: globalAllowLAN
        )
        initial.liveConnectionProperties = LiveConnectionProperties(
            config: config, globalAllowLAN: globalAllowLAN)
        initial.message = "Preparing native transport…"
        initial.updatedAt = Date()
        snapshot = initial
        sharedStore.save(initial)
    }

    func start() async throws {
        let transportName = config.protocolName.uppercased() + "/" + config.wireMode
            + (config.isUDP && config.quicEnabled ? "+QUIC" : "")
        sharedStore.appendLog("Service started: \(transportName)")
        sharedStore.appendLog(
            "Connecting to \(Self.logValue(config.serverAddress)):\(config.port) "
                + "as user '\(Self.logValue(config.username))'"
        )
        // Re-serialize through the iOS model so platform-unsupported keys (notably the
        // Linux/desktop `kill_switch`) keep their documented iOS semantics instead of making
        // the Rust plan require a capability NetworkExtension cannot provide.
        // Resolve all A/AAAA records before installing even the bootstrap TUN. Each reconnect also
        // refreshes this set; a temporarily unavailable resolver falls back to these last-known
        // addresses so DDNS support never makes an ordinary outage less recoverable.
        let resolvedCarriers = try await Self.resolveIPCandidates(config.serverAddress)
        let transport = try QeliNativeTransport(
            config: try config.toTransportCoreINI(), roamingEnabled: config.allowsNativePathRoaming)
        try transport.setDeviceID(try SecureIdentityStore().deviceID())
        await roamingController.start()
        try await applyBootstrapSettings(carrierAddresses: resolvedCarriers)
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
        if detailedLogging {
            sharedStore.appendLog(
                "Native transport active: \(QeliNativeTransport.loadedABIDescription()); "
                    + "TUN remains fail-closed until NetworkPlan ACK"
            )
        }
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
            wakeGeneration &+= 1
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
        await roamingController.stop()
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
        let state = stateLock.withLock { () -> (UInt64, QeliNativeTransport, UInt64)? in
            guard !stopped else { return nil }
            wakeGeneration &+= 1
            guard let native, let generation = activePlan?.generation,
                  snapshot.phase == .connected else { return nil }
            return (wakeGeneration, native, generation)
        }
        guard let state else { return }
        sharedStore.appendLog("Device woke; waiting briefly for the physical link")
        Task { [weak self] in
            do { try await Task.sleep(nanoseconds: 750_000_000) } catch { return }
            guard let self else { return }
            let active = self.stateLock.withLock { () -> Bool in
                guard !self.stopped,
                      self.wakeGeneration == state.0,
                      self.native === state.1,
                      self.activePlan?.generation == state.2,
                      self.snapshot.phase == .connected else { return false }
                return true
            }
            guard active else { return }
            if await self.roamingController.requestUpdate(
                reason: "wake", requiredGeneration: state.2, reconnectOnFailure: true) {
                self.sharedStore.appendLog("Device wake: submitted an in-process roaming path")
            }
        }
    }

    func currentSnapshot() -> TunnelSnapshot { stateLock.withLock { snapshot } }

    func isFailClosedSecurityHold() -> Bool {
        stateLock.withLock { failClosedSecurityHold && !stopped }
    }

    func reloadNetworkSettings() async throws {
        guard let state = stateLock.withLock({ () -> (NativeNetworkPlan, [String])? in
            guard !stopped, let activePlan else { return nil }
            return (activePlan, carrierAddresses)
        }) else {
            throw NativeTunnelError.sessionUnavailable
        }
        try await applyNetworkSettings(state.0, carrierExclusions: state.1)
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
                    await cleanupAttempt(active)
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
                        latest = try await Self.resolveIPCandidates(config.serverAddress)
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
                case QeliRoamingPath.pathCommandEvent:
                    let command = try QeliRoamingPath.decodeCommand(event)
                    var outcome = QeliPathCommandOutcome.rejected
                    var reason = ""
                    do {
                        try await roamingController.apply(command: command, transport: transport)
                        outcome = .accepted
                    } catch {
                        reason = error.localizedDescription
                        if let roamingError = error as? IOSRoamingError,
                           case .platformStateUnknown = roamingError {
                            outcome = .platformStateUnknown
                        }
                        let disposition = outcome == .platformStateUnknown
                            ? "left platform state unknown" : "rejected"
                        sharedStore.appendLog(
                            "WARN: iOS roaming \(command.action) candidate "
                                + "\(command.candidateID) \(disposition): \(reason)"
                        )
                    }
                    try transport.pathCommandResult(
                        event: event, command: command, outcome: outcome, reason: reason)
                    if outcome != .accepted && command.action == "abort_path" {
                        throw NativeTunnelError.transportStopped(
                            "iOS roaming rollback failed: \(reason)")
                    }
                case QeliRoamingPath.pathRefreshEvent:
                    let generation = try QeliRoamingPath.decodeRefreshGeneration(event)
                    _ = await roamingController.requestUpdate(
                        reason: "same_network_nat_failure", requiredGeneration: generation,
                        reconnectOnFailure: false)
                case QeliNativeTransport.noticeEvent:
                    let management = try Self.decodeManagement(event, expectedType: "notice")
                    sharedStore.appendLog("NOTICE: \(management.message)")
                case QeliNativeTransport.kickEvent:
                    let management = try Self.decodeManagement(event, expectedType: "kick")
                    sharedStore.appendLog("KICK: \(management.message)")
                    transport.stop()
                    if !management.reconnectAllowed {
                        throw NativeTunnelError.serverKick(management.message)
                    }
                    throw NativeTunnelError.transportStopped(management.message)
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
        let next = try QeliNativeTransport(
            config: try config.toTransportCoreINI(), roamingEnabled: config.allowsNativePathRoaming)
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

    private func cleanupAttempt(_ transport: QeliNativeTransport) async {
        await roamingController.disarm(transport: transport)
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

    private struct ManagementEnvelope {
        let message: String
        let reconnectAllowed: Bool
    }

    private static func decodeManagement(
        _ event: QeliTransportEvent,
        expectedType: String
    ) throws -> ManagementEnvelope {
        guard let data = event.payload.data(using: .utf8),
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["type"] as? String == expectedType,
              let message = object["message"] as? String,
              !message.isEmpty, message.utf8.count <= 512,
              !message.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else { throw NativeTunnelError.transportStopped("Invalid server management event.") }
        return ManagementEnvelope(
            message: message,
            reconnectAllowed: object["reconnect_allowed"] as? Bool ?? true
        )
    }

    private static func isTerminalReconnectError(_ error: Error) -> Bool {
        guard let native = error as? NativeTunnelError else { return false }
        switch native {
        case .invalidNetworkPlan, .invalidServerIdentity, .serverKeyMismatch,
             .unsupportedDNSPort, .serverKick:
            return true
        case .networkSettingsTimedOut, .dnsResolutionTimedOut, .sessionUnavailable,
             .packetInjectionFailed, .transportStopped:
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
        sharedStore.appendLog(
            "Auth OK: user='\(Self.logValue(config.username))', addresses " +
                plan.addresses.map { "\($0.address)/\($0.prefixLen)" }.joined(separator: ", ")
        )
        (plan.connectionLog ?? []).forEach { sharedStore.appendLog($0) }
        do {
            let carriers = stateLock.withLock { carrierAddresses }
            try await applyNetworkSettings(plan, carrierExclusions: carriers)
            try transport.networkPlanResult(generation: plan.generation, accepted: true)
            stateLock.withLock { activePlan = plan }
            await roamingController.arm(
                transport: transport,
                generation: plan.generation,
                carrierAddresses: carriers)
            startPacketPumps(transport: transport, generation: plan.generation)
            let dns = plan.dnsServers.isEmpty
                ? "system unchanged"
                : plan.dnsServers.map { "\($0.address):\($0.port)" }.joined(separator: ", ")
            sharedStore.appendLog(
                "Native NetworkPlan \(plan.generation) APPLIED: " +
                "mode=\(plan.fullTunnel ? "full" : "split") " +
                "family=\(plan.familyMode) addresses=" +
                "\(plan.addresses.map { "\($0.address)/\($0.prefixLen)" }.joined(separator: ", ")) " +
                "mtu=\(plan.mtu) " +
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
                let ipPackets = zip(packets, protocols).compactMap { pair in
                    pair.1.int32Value == AF_INET || pair.1.int32Value == AF_INET6
                        ? pair.0 : nil
                }
                var offset = 0
                while offset < ipPackets.count, !Task.isCancelled {
                    do {
                        let accepted = try transport.pushPackets(ipPackets[offset...], generation: generation)
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

    private func applyBootstrapSettings(carrierAddresses: [String]) async throws {
        let plan = NativeNetworkPlan(
            generation: 0,
            familyMode: "ipv4",
            addresses: [NativeNetworkAddress(
                family: "ipv4", address: "198.18.0.1", prefixLen: 32,
                onLinkPrefixLen: 32, gateway: "198.18.0.1"
            )],
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
            allowIpv4Leak: config.allowIPv4Leak,
            allowIpv6Leak: config.allowIPv6Leak,
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
        try await applyNetworkSettings(
            plan, publishFacts: false, carrierExclusions: carrierAddresses)
    }

    private func applyNetworkSettings(
        _ plan: NativeNetworkPlan,
        publishFacts: Bool = true,
        carrierExclusions: [String] = []
    ) async throws {
        let ipv4Addresses = plan.addresses.filter { $0.family == "ipv4" }
        let ipv6Addresses = plan.addresses.filter { $0.family == "ipv6" }
        let familyMatches = switch plan.familyMode {
        case "ipv4": ipv4Addresses.count == 1 && ipv6Addresses.isEmpty
        case "ipv6": ipv4Addresses.isEmpty && ipv6Addresses.count == 1
        case "dual": ipv4Addresses.count == 1 && ipv6Addresses.count == 1
        default: false
        }
        guard familyMatches, plan.addresses.count == ipv4Addresses.count + ipv6Addresses.count,
              plan.routes.count <= 256, plan.pushedRoutes.count <= 256,
              plan.dnsServers.count <= 8, (plan.connectionLog?.count ?? 0) <= 280,
              (VPNConfig.mtuMin...VPNConfig.mtuMax).contains(plan.mtu),
              (ipv6Addresses.isEmpty || plan.mtu >= 1_280),
              let projection = plan.addresses.first(where: { $0.address == plan.tunnelAddress }),
              projection.onLinkPrefixLen == plan.prefixLen,
              projection.gateway == plan.tunnelGateway,
              (projection.family == "ipv4"
                ? Self.isIPv4Address(plan.tunnelGateway)
                : Self.isUsableTunnelIPv6(plan.tunnelGateway)) else {
            throw NativeTunnelError.invalidNetworkPlan
        }
        if let carrier = plan.carrierAddress,
           !Self.isIPv4Address(carrier) && !Self.isIPv6Address(carrier) {
            throw NativeTunnelError.invalidNetworkPlan
        }
        for assigned in plan.addresses {
            let ipv4 = assigned.family == "ipv4"
            let maximum = ipv4 ? 32 : 128
            guard (1...maximum).contains(assigned.prefixLen),
                  (1...maximum).contains(assigned.onLinkPrefixLen),
                  assigned.onLinkPrefixLen <= assigned.prefixLen,
                  ipv4 ? Self.isIPv4Address(assigned.address)
                       : Self.isUsableTunnelIPv6(assigned.address)
            else { throw NativeTunnelError.invalidNetworkPlan }
            if let gateway = assigned.gateway {
                guard ipv4 ? Self.isIPv4Address(gateway) : Self.isUsableTunnelIPv6(gateway)
                else { throw NativeTunnelError.invalidNetworkPlan }
            }
        }
        guard plan.pushedRoutes.allSatisfy({
            Self.ipv4Route($0) != nil || Self.ipv6Route($0) != nil
        }), (plan.connectionLog ?? []).allSatisfy({ line in
            line.utf8.count <= 1_024 && !line.unicodeScalars.contains(where: {
                CharacterSet.controlCharacters.contains($0)
            })
        }) else { throw NativeTunnelError.invalidNetworkPlan }
        let requestGeneration = stateLock.withLock { () -> UInt64 in
            networkSettingsGeneration &+= 1
            return networkSettingsGeneration
        }
        let network = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: plan.carrierAddress ?? config.serverAddress
        )
        guard plan.routes.allSatisfy({
            Self.ipv4Route($0.cidr) != nil || Self.ipv6Route($0.cidr) != nil
        }) else { throw NativeTunnelError.invalidNetworkPlan }
        for route in plan.routes {
            let routeIsIPv4 = Self.ipv4Route(route.cidr) != nil
            let routeIsIPv6 = Self.ipv6Route(route.cidr) != nil
            guard (routeIsIPv4 && !ipv4Addresses.isEmpty && Self.isIPv4Address(route.gateway))
                    || (routeIsIPv6 && !ipv6Addresses.isEmpty
                        && Self.isUsableTunnelIPv6(route.gateway))
            else { throw NativeTunnelError.invalidNetworkPlan }
        }
        let allowLAN = config.allowLAN || SettingsStore().load().allowLAN
        let privateUpdatePath = config.hasPrivateUpdatePath(globalAllowLAN: allowLAN)
        let liveConnectionProperties = LiveConnectionProperties(
            config: config, globalAllowLAN: allowLAN)
        let effectiveExcludes = RouteExclusionPlanner.effectiveExcludes(
            configured: config.excludeRoutes,
            fullTunnel: plan.fullTunnel,
            allowLAN: allowLAN
        )
        let uniqueCarrierExclusions = Array(Set(carrierExclusions))
        guard uniqueCarrierExclusions.count <= QeliRoamingPath.maximumAddresses * 2,
              uniqueCarrierExclusions.allSatisfy({
                  Self.isIPv4Address($0) || Self.isIPv6Address($0)
              }) else { throw NativeTunnelError.invalidNetworkPlan }
        var excluded = effectiveExcludes.compactMap(Self.ipv4Route)
        var excludedIPv6 = effectiveExcludes.compactMap(Self.ipv6Route)
        guard excluded.count + excludedIPv6.count == effectiveExcludes.count else {
            throw NativeTunnelError.invalidNetworkPlan
        }
        let carrierIPv4 = uniqueCarrierExclusions.compactMap { address in
            Self.isIPv4Address(address) ? Self.ipv4Route("\(address)/32") : nil
        }
        let carrierIPv6 = uniqueCarrierExclusions.compactMap { address in
            Self.isIPv6Address(address) ? Self.ipv6Route("\(address)/128") : nil
        }
        guard carrierIPv4.count + carrierIPv6.count == uniqueCarrierExclusions.count else {
            throw NativeTunnelError.invalidNetworkPlan
        }
        excluded += carrierIPv4
        excludedIPv6 += carrierIPv6
        let protectedDNSRoutes = Set(plan.dnsServers.map { dns in
            "\(dns.address)/\(Self.isIPv4Address(dns.address) ? 32 : 128)"
        })
        for assigned in plan.addresses {
            guard let gateway = assigned.gateway else { continue }
            for excludedRoute in effectiveExcludes {
                guard let overrides = RouteExclusionPlanner.overridesOnLinkGateway(
                    excludedRoute,
                    gateway: gateway,
                    onLinkPrefixLength: assigned.onLinkPrefixLen
                ), !overrides else { throw NativeTunnelError.invalidNetworkPlan }
            }
        }
        var effectivePlanCIDRs: [String] = []
        for route in plan.routes {
            let fragments: [String]?
            if protectedDNSRoutes.contains(route.cidr) {
                fragments = [route.cidr]
            } else {
                fragments = RouteExclusionPlanner.subtract(
                    route.cidr,
                    excludes: effectiveExcludes
                )
            }
            guard let fragments else { throw NativeTunnelError.invalidNetworkPlan }
            effectivePlanCIDRs += fragments
            guard effectivePlanCIDRs.count <= RouteExclusionPlanner.maximumRoutes else {
                throw NativeTunnelError.invalidNetworkPlan
            }
        }
        let plannedIPv4Routes = effectivePlanCIDRs.compactMap(Self.ipv4Route)
        let plannedIPv6Routes = effectivePlanCIDRs.compactMap(Self.ipv6Route)
        guard plannedIPv4Routes.count + plannedIPv6Routes.count == effectivePlanCIDRs.count else {
            throw NativeTunnelError.invalidNetworkPlan
        }
        if let assigned = ipv4Addresses.first {
            let ipv4 = NEIPv4Settings(
                addresses: [assigned.address],
                subnetMasks: [Self.ipv4Mask(prefixLength: assigned.prefixLen)]
            )
            var included = plannedIPv4Routes
            if assigned.onLinkPrefixLen < assigned.prefixLen {
                guard let destination = Self.networkAddress(
                    assigned.address,
                    prefixLength: assigned.onLinkPrefixLen,
                    family: AF_INET
                ) else { throw NativeTunnelError.invalidNetworkPlan }
                included.append(NEIPv4Route(
                    destinationAddress: destination,
                    subnetMask: Self.ipv4Mask(prefixLength: assigned.onLinkPrefixLen)
                ))
            }
            if plan.fullTunnel { included.append(.default()) }
            ipv4.includedRoutes = Self.deduplicated(included)
            ipv4.excludedRoutes = Self.deduplicated(excluded)
            network.ipv4Settings = ipv4
        } else if plan.fullTunnel && !plan.allowIpv4Leak {
            let sink = NEIPv4Settings(
                addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.255"]
            )
            sink.includedRoutes = [.default()]
            sink.excludedRoutes = Self.deduplicated(excluded)
            network.ipv4Settings = sink
        }

        if let assigned = ipv6Addresses.first {
            let ipv6 = NEIPv6Settings(
                addresses: [assigned.address],
                networkPrefixLengths: [NSNumber(value: assigned.prefixLen)]
            )
            var includedIPv6 = plannedIPv6Routes
            if assigned.onLinkPrefixLen < assigned.prefixLen {
                guard let destination = Self.networkAddress(
                    assigned.address,
                    prefixLength: assigned.onLinkPrefixLen,
                    family: AF_INET6
                ) else { throw NativeTunnelError.invalidNetworkPlan }
                includedIPv6.append(NEIPv6Route(
                    destinationAddress: destination,
                    networkPrefixLength: NSNumber(value: assigned.onLinkPrefixLen)
                ))
            }
            if plan.fullTunnel { includedIPv6.append(.default()) }
            ipv6.includedRoutes = Self.deduplicated(includedIPv6)
            ipv6.excludedRoutes = Self.deduplicated(excludedIPv6)
            network.ipv6Settings = ipv6
        } else if plan.fullTunnel && !plan.allowIpv6Leak {
            let sink = NEIPv6Settings(
                addresses: ["fd00:7165:6c69::2"], networkPrefixLengths: [128]
            )
            sink.includedRoutes = [.default()]
            sink.excludedRoutes = Self.deduplicated(excludedIPv6)
            network.ipv6Settings = sink
        }

        guard plan.dnsServers.allSatisfy({ dns in
            (Self.isIPv4Address(dns.address) && !ipv4Addresses.isEmpty)
                || (Self.isIPv6Address(dns.address) && !ipv6Addresses.isEmpty)
        }) else { throw NativeTunnelError.invalidNetworkPlan }
        if let unsupportedDNS = plan.dnsServers.first(where: { $0.port != 53 }) {
            throw NativeTunnelError.unsupportedDNSPort(
                address: unsupportedDNS.address,
                port: unsupportedDNS.port
            )
        }
        if config.dnsMode == "tunnel", !plan.dnsServers.isEmpty {
            let dns = NEDNSSettings(servers: plan.dnsServers.map(\.address))
            // Route every DNS query through these tunnel resolvers. Supplying only
            // `servers` lets iOS keep using scoped physical-interface resolvers.
            dns.matchDomains = [""]
            network.dnsSettings = dns
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
            let effectiveRouteSet = Set(effectivePlanCIDRs)
            let pushedRoutesInstalled = RouteExclusionPlanner.countInstalledOriginals(
                plan.pushedRoutes,
                installedFragments: effectiveRouteSet,
                excludes: effectiveExcludes,
                protectedCidrs: protectedDNSRoutes
            )
            stateLock.withLock {
                snapshot.clientAddress = plan.tunnelAddress
                snapshot.tunnelAddresses = plan.addresses.map { "\($0.address)/\($0.prefixLen)" }
                snapshot.tunnelGateway = plan.tunnelGateway
                snapshot.pushedDNS = plan.dnsServers.first?.address
                snapshot.appliedMTU = plan.mtu
                snapshot.maxStreams = max(1, plan.maxStreams)
                snapshot.pushedRoutes = plan.pushedRoutes.count
                snapshot.pushed = PushedFacts(
                    routes: Array(plan.pushedRoutes.prefix(PushedFacts.routeSample)),
                    routeCount: plan.pushedRoutes.count,
                    routesInstalled: pushedRoutesInstalled,
                    multipathAdaptive: plan.adaptive,
                    paddingEnabled: plan.dataPlane.paddingEnabled,
                    paddingMin: plan.dataPlane.paddingMin,
                    paddingMax: plan.dataPlane.paddingMax,
                    heartbeatEnabled: plan.dataPlane.heartbeatEnabled,
                    heartbeatIntervalMilliseconds: plan.dataPlane.heartbeatIntervalMs,
                    shapingEnabled: plan.dataPlane.shapingEnabled
                )
                snapshot.privateUpdatePath = privateUpdatePath
                snapshot.liveConnectionProperties = liveConnectionProperties
                snapshot.updatedAt = Date()
                sharedStore.save(snapshot)
            }
            if pushedRoutesInstalled < plan.pushedRoutes.count {
                sharedStore.appendLog(
                    "WARNING: \(plan.pushedRoutes.count - pushedRoutesInstalled) of "
                        + "\(plan.pushedRoutes.count) pushed route(s) were fully or partially "
                        + "excluded by client/LAN routing policy"
                )
            }
        } else {
            // Settings reloads use publishFacts=false because negotiated DNS/MTU/routes did
            // not change, but an effective global allowLAN toggle still changes whether an
            // app-owned update request is guaranteed to remain inside the tunnel.
            stateLock.withLock {
                snapshot.privateUpdatePath = privateUpdatePath
                snapshot.liveConnectionProperties = liveConnectionProperties
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
            snapshot.tunnelAddresses = plan.addresses.map { "\($0.address)/\($0.prefixLen)" }
            snapshot.tunnelGateway = plan.tunnelGateway
            if snapshot.connectedAt == nil { snapshot.connectedAt = Date() }
            snapshot.updatedAt = Date()
            sharedStore.save(snapshot)
        }
    }

    private func publishStats(_ stats: QeliTransportStats) {
        let now = Date()
        var udpLogs: [String] = []
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
            if stats.udpKernelDrops < udpKernelDrops
                || stats.udpInternalDrops < udpInternalDrops
                || stats.udpBufferGrows < udpBufferGrows {
                udpKernelDrops = 0
                udpInternalDrops = 0
                udpBufferGrows = 0
                udpReportedKernelDrops = 0
                udpReportedInternalDrops = 0
                udpLastReportDate = now
                udpReadyLogged = false
            }
            let changed = stats.udpRecvBufferBytes != udpRecvBufferBytes
                || stats.udpKernelDrops != udpKernelDrops
                || stats.udpInternalDrops != udpInternalDrops
                || stats.udpBufferGrows != udpBufferGrows
            let grew = stats.udpBufferGrows > udpBufferGrows
            if !udpReadyLogged, stats.udpRecvBufferBytes > 0 {
                udpLogs.append("UDP ready: receive buffer \(stats.udpRecvBufferBytes / 1024) KiB")
                udpReadyLogged = true
            } else if grew {
                udpLogs.append(
                    "UDP receive buffer grew to \(stats.udpRecvBufferBytes / 1024) KiB "
                        + "(growths=\(stats.udpBufferGrows))"
                )
            }
            let pendingKernel = stats.udpKernelDrops - udpReportedKernelDrops
            let pendingInternal = stats.udpInternalDrops - udpReportedInternalDrops
            let sinceReport = now.timeIntervalSince(udpLastReportDate)
            let reportDetailed = detailedLogging && changed && sinceReport >= 5
            let reportCompact = !detailedLogging && (pendingKernel > 0 || pendingInternal > 0)
                && (pendingKernel + pendingInternal >= 32 || sinceReport >= 30)
            if reportDetailed || reportCompact {
                let prefix = detailedLogging ? "UDP telemetry" : "WARN: UDP packet loss"
                udpLogs.append(
                    "\(prefix): kernel +\(pendingKernel) (\(stats.udpKernelDrops) total), "
                        + "internal +\(pendingInternal) (\(stats.udpInternalDrops) total), "
                        + "buffer=\(stats.udpRecvBufferBytes / 1024) KiB, "
                        + "grows=\(stats.udpBufferGrows)"
                )
                udpReportedKernelDrops = stats.udpKernelDrops
                udpReportedInternalDrops = stats.udpInternalDrops
                udpLastReportDate = now
            }
            udpRecvBufferBytes = stats.udpRecvBufferBytes
            udpKernelDrops = stats.udpKernelDrops
            udpInternalDrops = stats.udpInternalDrops
            udpBufferGrows = stats.udpBufferGrows
            snapshot.updatedAt = now
            sharedStore.save(snapshot)
        }
        udpLogs.forEach { sharedStore.appendLog($0) }
    }

    func applyRoamingCarrierExclusions(
        _ addresses: [String], transport: QeliNativeTransport, generation: UInt64
    ) async throws {
        guard let plan = stateLock.withLock({ () -> NativeNetworkPlan? in
            guard !stopped, native === transport, activePlan?.generation == generation else {
                return nil
            }
            return activePlan
        }) else { throw NativeTunnelError.sessionUnavailable }
        try await applyNetworkSettings(
            plan, publishFacts: false, carrierExclusions: addresses)
        guard stateLock.withLock({
            !stopped && native === transport && activePlan?.generation == generation
        }) else { throw NativeTunnelError.sessionUnavailable }
    }

    func commitRoamingCarriers(
        _ addresses: [String], transport: QeliNativeTransport, generation: UInt64
    ) throws {
        let committed = stateLock.withLock { () -> Bool in
            guard !stopped, native === transport, activePlan?.generation == generation else {
                return false
            }
            carrierAddresses = addresses
            return true
        }
        guard committed else { throw NativeTunnelError.sessionUnavailable }
    }

    func isActiveRoamingGeneration(
        transport: QeliNativeTransport, generation: UInt64
    ) -> Bool {
        stateLock.withLock {
            !stopped && native === transport && activePlan?.generation == generation
        }
    }

    func requestRoamingReconnect(
        transport: QeliNativeTransport, generation: UInt64, reason: String
    ) {
        let shouldStop = stateLock.withLock {
            !stopped && native === transport && activePlan?.generation == generation
        }
        guard shouldStop else { return }
        provider.reasserting = true
        sharedStore.appendLog("\(reason); using full reconnect fallback")
        transport.stop()
    }

    func roamingLog(_ message: String) { sharedStore.appendLog(message) }

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
        let holdFailClosed = config.isFullTunnel && Self.isServerIdentityFailure(error)
        let changed = stateLock.withLock { () -> Bool in
            guard !stopped, snapshot.phase != .error else { return false }
            failClosedSecurityHold = holdFailClosed
            snapshot.phase = .error
            snapshot.message = error.localizedDescription
            snapshot.error = error.localizedDescription
            snapshot.privateUpdatePath = nil
            snapshot.liveConnectionProperties = nil
            snapshot.updatedAt = Date()
            sharedStore.save(snapshot)
            return true
        }
        guard changed else { return }
        sharedStore.appendLog("ERROR: \(error.localizedDescription)")
        if holdFailClosed {
            provider.reasserting = true
            sharedStore.appendLog(
                "SECURITY: full-tunnel routes remain fail-closed; disconnect explicitly after investigating the server identity."
            )
        } else {
            provider.reasserting = false
            provider.cancelTunnelWithError(error)
        }
    }

    private static func isServerIdentityFailure(_ error: Error) -> Bool {
        guard let native = error as? NativeTunnelError else { return false }
        switch native {
        case .invalidServerIdentity, .serverKeyMismatch:
            return true
        default:
            return false
        }
    }

    private func resetSnapshot(phase: TunnelPhase, message: String, error: String?) {
        stateLock.withLock {
            snapshot.phase = phase
            snapshot.message = message
            snapshot.error = error
            snapshot.clientAddress = nil
            snapshot.tunnelAddresses = nil
            snapshot.tunnelGateway = nil
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
            snapshot.privateUpdatePath = nil
            snapshot.liveConnectionProperties = nil
            snapshot.updatedAt = Date()
            sharedStore.save(snapshot)
        }
    }

    private static func logValue(_ text: String) -> String {
        let cleaned = text
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\t", with: " ")
        let bounded = String(cleaned.prefix(128))
        return bounded.isEmpty ? "?" : bounded
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
        let prefix = parts.count == 2 ? Int(parts[1]) : nil
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
        let prefix = parts.count == 2 ? Int(parts[1]) : nil
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

    private static func isUsableTunnelIPv6(_ text: String) -> Bool {
        var address = in6_addr()
        guard text.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else {
            return false
        }
        let bytes = withUnsafeBytes(of: address) { Array($0) }
        let unspecified = bytes.allSatisfy { $0 == 0 }
        let loopback = bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1
        let multicast = bytes[0] == 0xff
        let linkLocal = bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80
        let ipv4Mapped = bytes.prefix(10).allSatisfy { $0 == 0 }
            && bytes[10] == 0xff && bytes[11] == 0xff
        return !unspecified && !loopback && !multicast && !linkLocal && !ipv4Mapped
    }

    private static func networkAddress(
        _ text: String,
        prefixLength: Int,
        family: Int32
    ) -> String? {
        let byteCount = family == AF_INET ? 4 : 16
        guard (0...(byteCount * 8)).contains(prefixLength) else { return nil }
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let parsed = text.withCString { source in
            bytes.withUnsafeMutableBytes { storage in
                inet_pton(family, source, storage.baseAddress)
            }
        }
        guard parsed == 1 else { return nil }
        let wholeBytes = prefixLength / 8
        let remainingBits = prefixLength % 8
        if remainingBits != 0 {
            bytes[wholeBytes] &= UInt8((0xff << (8 - remainingBits)) & 0xff)
        }
        let zeroFrom = wholeBytes + (remainingBits == 0 ? 0 : 1)
        if zeroFrom < bytes.count {
            for index in zeroFrom..<bytes.count { bytes[index] = 0 }
        }
        var output = [CChar](repeating: 0, count: family == AF_INET
            ? Int(INET_ADDRSTRLEN) : Int(INET6_ADDRSTRLEN))
        let rendered = bytes.withUnsafeBytes { storage in
            inet_ntop(family, storage.baseAddress, &output, socklen_t(output.count))
        }
        return rendered == nil ? nil : String(cString: output)
    }

    private static func resolveIPCandidates(_ host: String) async throws -> [String] {
        if isIPv4Address(host) || isIPv6Address(host) { return [host] }
        guard Self.dnsLimiter.begin() else {
            throw NativeTunnelError.transportStopped(
                "A previous physical-network DNS lookup is still in progress."
            )
        }
        let completion = NativeDNSCompletion()
        let outcome: Result<[String], Error> = await withCheckedContinuation { continuation in
            completion.park(continuation)
            DispatchQueue.global(qos: .utility).async {
                defer { Self.dnsLimiter.finish() }
                completion.finish(Result { try resolveIPCandidatesBlocking(host) })
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(5)) {
                completion.finish(.failure(NativeTunnelError.dnsResolutionTimedOut))
            }
        }
        return try outcome.get()
    }

    private static func resolveIPCandidatesBlocking(_ host: String) throws -> [String] {
        var hints = addrinfo()
        hints.ai_flags = AI_ADDRCONFIG
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var head: UnsafeMutablePointer<addrinfo>?
        let status = host.withCString { getaddrinfo($0, nil, &hints, &head) }
        guard status == 0, let first = head else {
            let reason = status == 0 ? "no IP result" : String(cString: gai_strerror(status))
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
            } else if item.pointee.ai_family == AF_INET6, let raw = item.pointee.ai_addr {
                var address = UnsafeRawPointer(raw)
                    .assumingMemoryBound(to: sockaddr_in6.self).pointee.sin6_addr
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count)) != nil {
                    let value = String(cString: buffer)
                    if seen.insert(value).inserted { output.append(value) }
                }
            }
            cursor = item.pointee.ai_next
        }
        guard !output.isEmpty else {
            throw NativeTunnelError.transportStopped("\(host) has no IPv4 or IPv6 carrier address.")
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
    case dnsResolutionTimedOut
    case sessionUnavailable
    case packetInjectionFailed
    case transportStopped(String)
    case serverKick(String)

    var errorDescription: String? {
        switch self {
        case .invalidNetworkPlan: return "The native core returned an invalid NetworkPlan."
        case .invalidServerIdentity: return "The native core returned an invalid server identity."
        case .serverKeyMismatch: return "SERVER KEY MISMATCH — possible MITM."
        case .unsupportedDNSPort(let address, let port):
            return "iOS cannot apply DNS \(address):\(port); only port 53 is supported."
        case .networkSettingsTimedOut: return "Applying iOS tunnel settings timed out."
        case .dnsResolutionTimedOut:
            return "Resolving the VPN server on the physical network timed out."
        case .sessionUnavailable: return "No authenticated native tunnel session is active."
        case .packetInjectionFailed: return "iOS rejected a native downlink packet batch."
        case .transportStopped(let reason): return reason
        case .serverKick(let reason): return reason
        }
    }
}
