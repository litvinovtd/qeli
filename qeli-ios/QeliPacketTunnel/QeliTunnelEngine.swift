import Darwin
import Foundation
import Network
import NetworkExtension
import Security

struct TunnelSessionConfiguration: Sendable {
    var clientAddress: String
    var prefixLength: Int
    var pushedDNS: [String]
    var pushedRoutes: [String]
    var mtu: Int
    var sessionToken: String = ""
    var maxStreams: Int = 1
    var multipathAdaptive: Bool = false
}

final class QeliTunnelEngine: @unchecked Sendable {
    private unowned let provider: NEPacketTunnelProvider
    private let profile: Profile
    private let baseConfig: VPNConfig
    private var config: VPNConfig
    private let sharedStore: SharedTunnelStore

    private let stateLock = NSLock()
    private let packetWriteLock = NSLock()
    private let networkSettingsGate = AsyncOperationGate()
    private var snapshot: TunnelSnapshot
    private var activeSession: TunnelSessionConfiguration?
    private var activePool: TunnelStreamPool?
    private var supervisorTask: Task<Void, Never>?
    private var uplinkTask: Task<Void, Never>?
    private var statsTask: Task<Void, Never>?
    private var stopped = false
    private var networkSettingsGeneration: UInt64 = 0

    private var lastStatsDate = Date()
    private var sampledUpload: UInt64 = 0
    private var sampledDownload: UInt64 = 0

    init(
        provider: NEPacketTunnelProvider,
        profile: Profile,
        config: VPNConfig,
        sharedStore: SharedTunnelStore
    ) {
        self.provider = provider
        self.profile = profile
        baseConfig = config
        self.config = config
        self.sharedStore = sharedStore
        snapshot = TunnelSnapshot(
            phase: .connecting,
            message: "Starting…",
            profileID: profile.id
        )
    }

    func start() async throws {
        try Task.checkCancellation()
        update(phase: .connecting, message: "Preparing fail-closed tunnel…")
        try await applyNetworkSettings(Self.bootstrapSession(for: baseConfig), config: baseConfig)
        try Task.checkCancellation()
        guard !stateLock.withLock({ stopped }) else { throw CancellationError() }

        provider.reasserting = true
        startUplinkIfNeeded()
        startStatsIfNeeded()
        let supervisor = Task<Void, Never> { [weak self] in
            await self?.establishInitialThenSupervise()
        }
        let retained = stateLock.withLock { () -> Bool in
            guard !stopped else { return false }
            supervisorTask = supervisor
            return true
        }
        if !retained {
            provider.reasserting = false
            supervisor.cancel()
            throw CancellationError()
        }
        sharedStore.appendLog("TUN installed fail-closed; connection supervisor started")
    }

    func stop() async {
        let resources = stateLock.withLock { () -> (
            pool: TunnelStreamPool?,
            supervisor: Task<Void, Never>?,
            uplink: Task<Void, Never>?,
            stats: Task<Void, Never>?,
            preserveError: Bool,
            changed: Bool
        ) in
            guard !stopped else {
                return (nil, nil, nil, nil, snapshot.phase == .error, false)
            }
            stopped = true
            networkSettingsGeneration &+= 1
            let value = (
                activePool,
                supervisorTask,
                uplinkTask,
                statsTask,
                snapshot.phase == .error,
                true
            )
            activePool = nil
            supervisorTask = nil
            uplinkTask = nil
            statsTask = nil
            return value
        }
        guard resources.changed else { return }
        provider.reasserting = false
        resources.supervisor?.cancel()
        resources.uplink?.cancel()
        resources.stats?.cancel()
        resources.pool?.cancel()
        if !resources.preserveError {
            resetSnapshot(phase: .disconnected, message: "", error: nil)
        }
        sharedStore.appendLog("Tunnel stopped")
    }

    func wake() {
        guard let pool = stateLock.withLock({ stopped ? nil : activePool }) else {
            sharedStore.appendLog("Device woke while the tunnel is reconnecting")
            return
        }
        if pool.hasSatisfiedPath {
            sharedStore.appendLog("Device woke; heartbeat liveness remains active")
        } else {
            sharedStore.appendLog("Device woke without a viable transport path; reconnecting")
            pool.forceFailure(TunnelEngineError.networkPathUnavailable)
        }
    }

    func currentSnapshot() -> TunnelSnapshot { stateLock.withLock { snapshot } }

    func reloadNetworkSettings() async throws {
        guard let state = stateLock.withLock({
            () -> (TunnelSessionConfiguration, VPNConfig, TunnelStreamPool, UInt64)? in
            guard !stopped,
                  snapshot.phase == .connected,
                  let activeSession,
                  let activePool else { return nil }
            return (activeSession, config, activePool, networkSettingsGeneration)
        }) else {
            throw TunnelEngineError.sessionUnavailable
        }
        try await applyNetworkSettings(
            state.0,
            config: state.1,
            expectedGeneration: state.3,
            expectedPool: state.2
        )
        sharedStore.appendLog("Network settings reloaded")
    }

    /// Applies the authenticated address and route push while keeping the virtual
    /// interface installed across reconnect attempts (fail-closed reassertion).
    func applyNetworkSettings(
        _ session: TunnelSessionConfiguration,
        config effectiveConfig: VPNConfig,
        expectedGeneration: UInt64? = nil,
        expectedPool: TunnelStreamPool? = nil
    ) async throws {
        let requestGeneration = stateLock.withLock { () -> UInt64 in
            if let expectedGeneration { return expectedGeneration }
            networkSettingsGeneration &+= 1
            return networkSettingsGeneration
        }
        let network = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: effectiveConfig.serverAddress)
        let ipv4 = NEIPv4Settings(
            addresses: [session.clientAddress],
            subnetMasks: [Self.ipv4Mask(prefixLength: session.prefixLength)]
        )

        var included: [NEIPv4Route] = []
        if effectiveConfig.isFullTunnel {
            included.append(.default())
        } else {
            included += effectiveConfig.includeRoutes.compactMap(Self.ipv4Route)
        }
        included += session.pushedRoutes.compactMap(Self.ipv4Route)
        if effectiveConfig.routeLocalNetworks {
            included += [
                NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
                NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
                NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0")
            ]
        }
        ipv4.includedRoutes = Self.deduplicated(included)

        var excluded = effectiveConfig.excludeRoutes.compactMap(Self.ipv4Route)
        if effectiveConfig.allowLAN || SettingsStore().load().allowLAN {
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

        if effectiveConfig.isFullTunnel && !effectiveConfig.allowIPv6Leak {
            let ipv6 = NEIPv6Settings(addresses: ["fd00:7165:6c69::2"], networkPrefixLengths: [64])
            ipv6.includedRoutes = [.default()]
            network.ipv6Settings = ipv6
        }

        let dns = !effectiveConfig.dnsServers.isEmpty
            ? effectiveConfig.dnsServers
            : (!session.pushedDNS.isEmpty
                ? session.pushedDNS
                : (effectiveConfig.isFullTunnel ? ["1.1.1.1", "8.8.8.8"] : []))
        if !dns.isEmpty { network.dnsSettings = NEDNSSettings(servers: dns) }
        let effectiveMTU = effectiveConfig.mtu > 0
            ? effectiveConfig.mtu
            : (session.mtu > 0 ? session.mtu : 1_400)
        network.mtu = NSNumber(value: max(576, effectiveMTU))

        await networkSettingsGate.acquire()
        do {
            try Task.checkCancellation()
            let validity = stateLock.withLock { () -> Bool? in
                guard !stopped else { return nil }
                guard networkSettingsGeneration == requestGeneration else { return false }
                guard let expectedPool else { return true }
                guard let current = activePool else { return false }
                return current === expectedPool
            }
            guard let validity else { throw CancellationError() }
            guard validity else { throw TunnelEngineError.staleNetworkSettings }
            try await withCheckedThrowingContinuation { continuation in
                provider.setTunnelNetworkSettings(network) { error in
                    if let error { continuation.resume(throwing: error) }
                    else { continuation.resume(returning: ()) }
                }
            }
            let stillCurrent = stateLock.withLock { () -> Bool? in
                guard !stopped else { return nil }
                guard networkSettingsGeneration == requestGeneration else { return false }
                guard let expectedPool else { return true }
                guard let current = activePool else { return false }
                return current === expectedPool
            }
            guard let stillCurrent else { throw CancellationError() }
            guard stillCurrent else { throw TunnelEngineError.staleNetworkSettings }
            await networkSettingsGate.release()
        } catch {
            await networkSettingsGate.release()
            throw error
        }
    }

    private func establishInitialThenSupervise() async {
        let policy = ReconnectPolicy(config: baseConfig)
        var firstAttempt = true
        var failureCount = 0
        var elapsed = ReconnectPolicy.minimumInterAttemptMilliseconds
        var lastError: Error = TunnelEngineError.transportUnavailable

        while !Task.isCancelled, !stateLock.withLock({ stopped }) {
            if !firstAttempt {
                switch policy.decision(
                    failureCount: failureCount,
                    millisecondsSinceAttemptStarted: elapsed
                ) {
                case .stop(let reason):
                    terminalFailure(
                        TunnelEngineError.reconnectStopped(reason, lastError.localizedDescription)
                    )
                    return
                case .retry(let attempt, let delayMilliseconds):
                    if delayMilliseconds > 0 {
                        update(
                            phase: .reconnecting,
                            message: "Reconnect attempt \(max(attempt, 1)) in \(Self.delayDescription(delayMilliseconds))…",
                            error: lastError.localizedDescription
                        )
                        do {
                            try await Task.sleep(
                                nanoseconds: UInt64(delayMilliseconds) * 1_000_000
                            )
                        } catch { return }
                    }
                }
            } else {
                update(
                    phase: .connecting,
                    message: "Opening \(baseConfig.protocolName.uppercased())/\(baseConfig.wireMode) transport…"
                )
            }

            let attemptStartedAt = Date()
            do {
                let established = try await establishPrimary(using: baseConfig)
                let pool = try await activateEstablished(established)
                sharedStore.appendLog("Encrypted transport established")
                await supervise(startingWith: pool)
                return
            } catch is CancellationError {
                return
            } catch {
                guard !Task.isCancelled, !stateLock.withLock({ stopped }) else { return }
                lastError = error
                if isFatalConnectionError(error) {
                    terminalFailure(error)
                    return
                }
                failureCount = policy.nextFailureCount(
                    previous: failureCount,
                    sessionWasEstablished: false
                )
                elapsed = max(0, Int(Date().timeIntervalSince(attemptStartedAt) * 1_000))
                firstAttempt = false
                provider.reasserting = true
                update(
                    phase: .reconnecting,
                    message: "Connection failed; retrying…",
                    error: error.localizedDescription
                )
                sharedStore.appendLog("Connection attempt failed: \(error.localizedDescription)")
            }
        }
    }

    private func activateEstablished(
        _ established: EstablishedTunnelRuntime
    ) async throws -> TunnelStreamPool {
        do {
            try await applyNetworkSettings(established.session, config: established.config)
        } catch {
            established.primary.cancel()
            throw error
        }
        let pool = makePool(from: established)
        guard install(pool) else {
            pool.cancel()
            throw CancellationError()
        }
        guard activate(established.primary, in: pool) else {
            clear(pool)
            pool.cancel()
            if stateLock.withLock({ stopped }) { throw CancellationError() }
            throw TunnelEngineError.transportUnavailable
        }
        guard commitConnected(
            session: established.session,
            config: established.config,
            pool: pool
        ) else {
            clear(pool)
            pool.cancel()
            throw CancellationError()
        }
        provider.reasserting = false
        startMultipath(in: pool)
        return pool
    }

    private func establishPrimary(using inputConfig: VPNConfig) async throws -> EstablishedTunnelRuntime {
        guard inputConfig.isUDP, inputConfig.mtu == 0, inputConfig.mtuProbe else {
            return try await establishPrimaryAttempt(using: inputConfig)
        }
        do {
            return try await establishPrimaryAttempt(using: inputConfig)
        } catch UDPPathMTUProbeError.noResult(let ceiling) {
            // NWProtocolIP options are immutable for a running connection. Android
            // clears DF on the same socket after a missed probe window; iOS must
            // transparently re-authenticate a new socket with fragmentation allowed.
            sharedStore.appendLog(
                "UDP path-MTU probe: no ACK at ceiling \(ceiling); reconnecting without DF"
            )
            var fallbackConfig = inputConfig
            fallbackConfig.mtuProbe = false
            var established = try await establishPrimaryAttempt(using: fallbackConfig)
            established.config.mtuProbe = inputConfig.mtuProbe
            return established
        }
    }

    private func establishPrimaryAttempt(
        using inputConfig: VPNConfig
    ) async throws -> EstablishedTunnelRuntime {
        let raw = try NetworkTransport(config: inputConfig)
        let timeoutSeconds = inputConfig.connectionTimeoutSeconds
        let deadline = StartupDeadline()
        let attemptStartedAt = Date()
        do {
            var established = try await withThrowingTaskGroup(of: EstablishedTunnelRuntime.self) { group in
                group.addTask { [self] in
                    try await raw.connect()
                    sharedStore.appendLog(
                        "Transport connected to \(inputConfig.serverAddress):\(inputConfig.port)"
                    )
                    return try await performPrimaryHandshake(
                        raw: raw,
                        config: inputConfig,
                        attemptStartedAt: attemptStartedAt
                    )
                }
                group.addTask {
                    try await Task.sleep(nanoseconds: UInt64(timeoutSeconds) * 1_000_000_000)
                    deadline.expire()
                    raw.cancel()
                    throw TunnelEngineError.startTimedOut(timeoutSeconds)
                }
                defer { group.cancelAll() }
                guard let result = try await group.next() else {
                    throw TunnelEngineError.transportUnavailable
                }
                return result
            }
            // The configured connection timeout applies to connect/authentication.
            // PMTU has its own bounded 4 x 2 x 220 ms window after AuthOK.
            if inputConfig.isUDP, inputConfig.mtu == 0, inputConfig.mtuProbe {
                guard let records = established.primary.records as? UDPRecordTransport else {
                    throw TunnelEngineError.unsupportedCombination("UDP path-MTU adapter")
                }
                let ceiling = established.config.mtu
                let discovered = try await probeUDPPathMTU(
                    records: records,
                    ceiling: ceiling
                )
                established.config.mtu = discovered
                established.session.mtu = discovered
                await established.primary.sender.updateMTU(discovered)
            }
            return established
        } catch {
            raw.cancel()
            if deadline.didExpire { throw TunnelEngineError.startTimedOut(timeoutSeconds) }
            throw error
        }
    }

    private func performPrimaryHandshake(
        raw: QeliTransport,
        config inputConfig: VPNConfig,
        attemptStartedAt: Date
    ) async throws -> EstablishedTunnelRuntime {
        if inputConfig.isUDP {
            guard inputConfig.wireMode.caseInsensitiveCompare("plain") != .orderedSame,
                  inputConfig.wireMode.caseInsensitiveCompare("reality-tls") != .orderedSame else {
                throw TunnelEngineError.unsupportedCombination(
                    "\(inputConfig.protocolName)/\(inputConfig.wireMode)"
                )
            }
            let records = try UDPRecordTransport(underlying: raw, config: inputConfig)
            if inputConfig.awgEnabled,
               inputConfig.awgJunkCount > 0 {
                try await records.sendAWGJunkPreamble(
                    count: inputConfig.awgJunkCount,
                    minimumSize: inputConfig.awgJunkMin,
                    maximumSize: inputConfig.awgJunkMax
                )
                sharedStore.appendLog("UDP AWG junk preamble sent")
            }
            let result = try await MaskedModeHandshake.run(
                recordTransport: records,
                config: inputConfig,
                sharedStore: sharedStore
            )
            var session = result.session
            session.sessionToken = Self.hex(result.metadata.sessionToken)
            session.maxStreams = result.metadata.maxStreams
            session.multipathAdaptive = result.metadata.adaptive
            return EstablishedTunnelRuntime(
                config: result.config,
                session: session,
                primary: TunnelStreamRuntime(
                    index: 0,
                    records: result.recordTransport,
                    encoder: result.encoder,
                    decoder: result.decoder,
                    config: result.config
                ),
                multipath: nil,
                attemptStartedAt: attemptStartedAt
            )
        }

        if inputConfig.wireMode.caseInsensitiveCompare("plain") == .orderedSame {
            let result = try await PlainHandshake.run(
                transport: raw,
                config: inputConfig,
                sharedStore: sharedStore
            )
            let records = PlainRecordTransport(underlyingTransport: raw, reader: result.reader)
            return EstablishedTunnelRuntime(
                config: result.config,
                session: result.session,
                primary: TunnelStreamRuntime(
                    index: 0,
                    records: records,
                    encoder: result.encoder,
                    decoder: result.decoder,
                    config: result.config
                ),
                multipath: Self.multipath(from: result.session),
                attemptStartedAt: attemptStartedAt
            )
        }

        let result = try await MaskedModeHandshake.run(
            transport: raw,
            config: inputConfig,
            sharedStore: sharedStore
        )
        var session = result.session
        session.sessionToken = Self.hex(result.metadata.sessionToken)
        session.maxStreams = result.metadata.maxStreams
        session.multipathAdaptive = result.metadata.adaptive
        return EstablishedTunnelRuntime(
            config: result.config,
            session: session,
            primary: TunnelStreamRuntime(
                index: 0,
                records: result.recordTransport,
                encoder: result.encoder,
                decoder: result.decoder,
                config: result.config
            ),
            multipath: Self.multipath(from: session),
            attemptStartedAt: attemptStartedAt
        )
    }

    /// Mirrors the Android MTU ladder while keeping all reads on the UDP message
    /// inbox. A timed miss never cancels the already-authenticated NWConnection.
    private func probeUDPPathMTU(
        records: UDPRecordTransport,
        ceiling: Int
    ) async throws -> Int {
        let policy = UDPPathMTUProbePolicy(ceiling: ceiling)
        guard !policy.candidates.isEmpty else {
            throw UDPPathMTUProbeError.noResult(ceiling: ceiling)
        }

        for candidate in policy.candidates {
            let probeID = try Self.secureRandomProbeID()
            let outerSize = policy.outerProbeSize(for: candidate)

            for _ in 0..<2 {
                do {
                    try await records.sendMTUProbe(id: probeID, outerSize: outerSize)
                } catch is CancellationError {
                    throw CancellationError()
                } catch {
                    guard Self.isDatagramTooLarge(error) else { throw error }
                    break // EMSGSIZE/DF is a negative probe result; step down.
                }
                if try await waitForMTUProbeAck(
                    records: records,
                    policy: policy,
                    id: probeID,
                    outerSize: outerSize,
                    timeoutMilliseconds: 220
                ) {
                    sharedStore.appendLog(
                        "UDP path-MTU probe: tunnel MTU \(candidate) (ceiling \(ceiling))"
                    )
                    return candidate
                }
            }
        }
        throw UDPPathMTUProbeError.noResult(ceiling: ceiling)
    }

    private func waitForMTUProbeAck(
        records: UDPRecordTransport,
        policy: UDPPathMTUProbePolicy,
        id: Int,
        outerSize: Int,
        timeoutMilliseconds: Int
    ) async throws -> Bool {
        let deadline = Date().addingTimeInterval(Double(timeoutMilliseconds) / 1_000)
        while !Task.isCancelled {
            let remaining = max(0, Int(deadline.timeIntervalSinceNow * 1_000))
            guard remaining > 0,
                  let event = try await records.receiveControlEvent(
                    timeoutMilliseconds: remaining
                  ) else { return false }
            guard policy.accepts(event, id: id) else { continue }
            guard case .mtuProbeAck(_, let echoedSize) = event else { continue }
            return echoedSize == outerSize
        }
        throw CancellationError()
    }

    private static func secureRandomProbeID() throws -> Int {
        var bytes = [UInt8](repeating: 0, count: 2)
        let status = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw UDPPathMTUProbeError.randomFailure(status)
        }
        return (Int(bytes[0]) << 8) | Int(bytes[1])
    }

    private static func isDatagramTooLarge(_ error: Error) -> Bool {
        if let recordError = error as? UDPRecordTransportError,
           case .datagramExceedsTransportLimit = recordError {
            return true
        }
        if let networkError = error as? NWError,
           case .posix(let code) = networkError {
            return code == .EMSGSIZE
        }
        let native = error as NSError
        return native.domain == NSPOSIXErrorDomain && native.code == Int(EMSGSIZE)
    }

    private func makePool(from established: EstablishedTunnelRuntime) -> TunnelStreamPool {
        TunnelStreamPool(
            primary: established.primary,
            config: established.config,
            session: established.session,
            multipath: established.multipath,
            attemptStartedAt: established.attemptStartedAt,
            trafficBaseline: 0
        )
    }

    private func install(_ pool: TunnelStreamPool) -> Bool {
        stateLock.withLock {
            guard !stopped, activePool == nil else { return false }
            activePool = pool
            return true
        }
    }

    private func clear(_ pool: TunnelStreamPool) {
        stateLock.withLock {
            guard let current = activePool, current === pool else { return }
            activePool = nil
            networkSettingsGeneration &+= 1
        }
    }

    private func commitConnected(
        session: TunnelSessionConfiguration,
        config effectiveConfig: VPNConfig,
        pool: TunnelStreamPool
    ) -> Bool {
        let committed = stateLock.withLock { () -> Bool in
            guard !stopped, let current = activePool, current === pool else { return false }
            config = effectiveConfig
            activeSession = session
            snapshot.phase = .connected
            snapshot.message = "Tunnel active"
            snapshot.error = nil
            snapshot.clientAddress = session.clientAddress
            snapshot.connectedAt = Date()
            snapshot.bytesUploaded = 0
            snapshot.bytesDownloaded = 0
            snapshot.uploadBytesPerSecond = 0
            snapshot.downloadBytesPerSecond = 0
            sampledUpload = 0
            sampledDownload = 0
            lastStatsDate = Date()
            snapshot.updatedAt = lastStatsDate
            sharedStore.save(snapshot)
            return true
        }
        guard committed else { return false }
        sharedStore.appendLog("Tunnel active")
        return true
    }

    @discardableResult
    private func activate(_ stream: TunnelStreamRuntime, in pool: TunnelStreamPool) -> Bool {
        let pathMonitor = UnderlyingPathMonitor(initialPath: stream.records.underlyingTransport.currentPath)
        guard stream.begin(
            pathUpdate: { [weak pool, weak stream] path in
                guard pathMonitor.requiresReconnect(for: path), let pool, let stream else { return }
                pool.lose(stream, error: TunnelEngineError.networkPathUnavailable)
            },
            sendHeartbeat: { [weak stream] emission in
                guard let stream else { throw CancellationError() }
                try await stream.sender.sendHeartbeat(emission)
            },
            onHeartbeatFailure: { [weak pool, weak stream] error in
                guard let pool, let stream else { return }
                pool.lose(stream, error: error)
            }
        ) else { return false }

        let downlink = Task<Void, Never> { [weak self, weak pool, weak stream] in
            guard let self, let pool, let stream else { return }
            do {
                while !Task.isCancelled {
                    let record = try await stream.records.receiveRecord()
                    let packet: Data
                    do {
                        packet = try stream.decoder.decrypt(record)
                    } catch {
                        if stream.isUDP { continue }
                        throw error
                    }
                    pool.markReceived()
                    if packet.isEmpty { continue }
                    try writePacket(packet)
                    recordTraffic(upload: 0, download: UInt64(packet.count))
                }
            } catch is CancellationError {
            } catch {
                pool.lose(stream, error: error)
            }
        }
        stream.retainDownlink(downlink)
        return !stream.isDead
    }

    private func startUplinkIfNeeded() {
        let task = stateLock.withLock { () -> Task<Void, Never>? in
            guard !stopped, uplinkTask == nil else { return nil }
            let task = Task<Void, Never> { [weak self] in await self?.runUplink() }
            uplinkTask = task
            return task
        }
        if stateLock.withLock({ stopped }) { task?.cancel() }
    }

    private func startStatsIfNeeded() {
        let task = stateLock.withLock { () -> Task<Void, Never>? in
            guard !stopped, statsTask == nil else { return nil }
            let task = Task<Void, Never> { [weak self] in
                while !Task.isCancelled {
                    do { try await Task.sleep(nanoseconds: 1_000_000_000) }
                    catch { return }
                    guard let self else { return }
                    self.publishStatsTick()
                }
            }
            statsTask = task
            return task
        }
        if stateLock.withLock({ stopped }) { task?.cancel() }
    }

    private func runUplink() async {
        while !Task.isCancelled, !stateLock.withLock({ stopped }) {
            let (packets, _) = await readPackets()
            guard !Task.isCancelled else { return }
            for packet in packets {
                guard !Task.isCancelled,
                      let pool = stateLock.withLock({ stopped ? nil : activePool }),
                      let stream = pool.selectStream() else { continue }
                do {
                    guard try await stream.sender.sendUserPacket(packet) else { continue }
                    pool.markUserUplink()
                    recordTraffic(upload: UInt64(packet.count), download: 0)
                } catch is CancellationError {
                    return
                } catch {
                    // UDP send failures have datagram-loss semantics. The independent
                    // receive watchdog decides whether the path actually died.
                    if !stream.isUDP { pool.lose(stream, error: error) }
                }
            }
        }
    }

    private func startMultipath(in pool: TunnelStreamPool) {
        pool.startMultipathLivenessIfNeeded()
        guard !pool.config.isUDP,
              let session = pool.multipath,
              session.maximumStreams > 1 else { return }
        sharedStore.appendLog(
            "Multipath: server allows \(session.maximumStreams) stream(s), adaptive=\(session.adaptive)"
        )
        let task = Task<Void, Never> { [weak self, pool] in
            guard let self else { return }
            if !session.adaptive {
                for index in pool.scheduler.initialSecondaryIndexes {
                    guard !Task.isCancelled else { return }
                    await joinStream(index: index, in: pool)
                }
                sharedStore.appendLog("Multipath fixed: \(pool.streamCount) stream(s) active")
                return
            }

            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: 3_000_000_000) }
                catch { return }
                let total = totalTraffic()
                let relative = total >= pool.trafficBaseline ? total - pool.trafficBaseline : total
                switch pool.scheduler.observeThroughput(totalBytes: relative) {
                case .openStream(let index, let rate):
                    sharedStore.appendLog(
                        "Multipath adaptive: opening #\(index) at \(rate / 1_000) KB/s"
                    )
                    await joinStream(index: index, in: pool)
                case .plateau(let rate):
                    sharedStore.appendLog(
                        "Multipath adaptive: plateau at \(pool.streamCount) stream(s), \(rate / 1_000) KB/s"
                    )
                    return
                case .targetReached:
                    return
                case .hold(_):
                    continue
                }
            }
        }
        pool.retainManagementTask(task)
    }

    private func joinStream(index: Int, in pool: TunnelStreamPool) async {
        do {
            let stream = try await establishBondedStream(
                config: pool.config,
                token: pool.multipath?.token ?? Data(),
                index: index
            )
            guard pool.add(stream) else { return }
            guard activate(stream, in: pool) else { return }
            sharedStore.appendLog("Bonded stream #\(index) joined (\(pool.streamCount) active)")
        } catch is CancellationError {
        } catch {
            pool.scheduler.markJoinFailed(index: index)
            sharedStore.appendLog("Bonded stream #\(index) failed: \(error.localizedDescription)")
        }
    }

    private func establishBondedStream(
        config: VPNConfig,
        token: Data,
        index: Int
    ) async throws -> TunnelStreamRuntime {
        guard !config.isUDP else {
            throw TunnelEngineError.unsupportedCombination("UDP multipath")
        }
        let raw = try NetworkTransport(config: config)
        let timeoutSeconds = config.connectionTimeoutSeconds
        do {
            return try await withThrowingTaskGroup(of: TunnelStreamRuntime.self) { group in
                group.addTask { [self] in
                    try await raw.connect()
                    if config.wireMode.caseInsensitiveCompare("plain") == .orderedSame {
                        let result = try await PlainJoinHandshake.run(
                            transport: raw,
                            config: config,
                            token: token,
                            streamIndex: index,
                            sharedStore: sharedStore
                        )
                        return TunnelStreamRuntime(
                            index: index,
                            records: PlainRecordTransport(
                                underlyingTransport: raw,
                                reader: result.reader
                            ),
                            encoder: result.encoder,
                            decoder: result.decoder,
                            config: config
                        )
                    }
                    let result = try await MaskedModeHandshake.runJoin(
                        transport: raw,
                        config: config,
                        token: token,
                        index: index,
                        sharedStore: sharedStore
                    )
                    return TunnelStreamRuntime(
                        index: index,
                        records: result.recordTransport,
                        encoder: result.encoder,
                        decoder: result.decoder,
                        config: config
                    )
                }
                group.addTask {
                    try await Task.sleep(nanoseconds: UInt64(timeoutSeconds) * 1_000_000_000)
                    raw.cancel()
                    throw TunnelEngineError.startTimedOut(timeoutSeconds)
                }
                defer { group.cancelAll() }
                guard let result = try await group.next() else {
                    throw TunnelEngineError.transportUnavailable
                }
                return result
            }
        } catch {
            raw.cancel()
            throw error
        }
    }

    private func supervise(startingWith initialPool: TunnelStreamPool) async {
        var pool = initialPool
        while !Task.isCancelled, !stateLock.withLock({ stopped }) {
            guard let failure = await pool.failure.next() else { return }
            if failure is CancellationError || Task.isCancelled { return }
            guard !stateLock.withLock({ stopped }) else { return }

            sharedStore.appendLog("Transport lost: \(failure.localizedDescription)")
            clear(pool)
            pool.cancel()
            provider.reasserting = true
            update(phase: .reconnecting, message: "Reconnecting…", error: failure.localizedDescription)

            let policy = ReconnectPolicy(config: baseConfig)
            var failureCount = 0
            var elapsed = pool.elapsedSinceAttemptStartedMilliseconds
            var lastError: Error = failure

            reconnect: while !Task.isCancelled, !stateLock.withLock({ stopped }) {
                switch policy.decision(
                    failureCount: failureCount,
                    millisecondsSinceAttemptStarted: elapsed
                ) {
                case .stop(let reason):
                    let error = TunnelEngineError.reconnectStopped(reason, lastError.localizedDescription)
                    terminalFailure(error)
                    return

                case .retry(let attempt, let delayMilliseconds):
                    if delayMilliseconds > 0 {
                        let number = max(attempt, 1)
                        update(
                            phase: .reconnecting,
                            message: "Reconnect attempt \(number) in \(Self.delayDescription(delayMilliseconds))…",
                            error: lastError.localizedDescription
                        )
                        do {
                            try await Task.sleep(
                                nanoseconds: UInt64(delayMilliseconds) * 1_000_000
                            )
                        } catch { return }
                    }

                    let attemptStartedAt = Date()
                    do {
                        let established = try await establishPrimary(using: baseConfig)
                        let replacement = try await activateEstablished(established)
                        sharedStore.appendLog("Reconnect succeeded")
                        pool = replacement
                        break reconnect
                    } catch is CancellationError {
                        return
                    } catch {
                        guard !Task.isCancelled, !stateLock.withLock({ stopped }) else { return }
                        lastError = error
                        if isFatalConnectionError(error) {
                            terminalFailure(error)
                            return
                        }
                        failureCount = policy.nextFailureCount(
                            previous: failureCount,
                            sessionWasEstablished: false
                        )
                        elapsed = max(0, Int(Date().timeIntervalSince(attemptStartedAt) * 1_000))
                        sharedStore.appendLog("Reconnect failed: \(error.localizedDescription)")
                    }
                }
            }
        }
    }

    private func terminalFailure(_ error: Error) {
        let resources = stateLock.withLock { () -> (
            pool: TunnelStreamPool?,
            uplink: Task<Void, Never>?,
            supervisor: Task<Void, Never>?,
            stats: Task<Void, Never>?,
            shouldCancel: Bool
        ) in
            guard !stopped else { return (nil, nil, nil, nil, false) }
            stopped = true
            networkSettingsGeneration &+= 1
            let value = (activePool, uplinkTask, supervisorTask, statsTask, true)
            activePool = nil
            uplinkTask = nil
            supervisorTask = nil
            statsTask = nil
            return value
        }
        guard resources.shouldCancel else { return }
        provider.reasserting = false
        resources.pool?.cancel()
        resources.uplink?.cancel()
        resources.supervisor?.cancel()
        resources.stats?.cancel()
        resetSnapshot(
            phase: .error,
            message: error.localizedDescription,
            error: error.localizedDescription
        )
        provider.cancelTunnelWithError(error)
    }

    private func isFatalConnectionError(_ error: Error) -> Bool {
        if error is VPNConfigError { return true }
        if let engine = error as? TunnelEngineError,
           case .unsupportedCombination = engine {
            return true
        }
        if let native = error as? QeliNativeError {
            switch native {
            case .unavailable, .invalidInput(_): return true
            case .operationFailed(_): return false
            }
        }
        if let plain = error as? PlainHandshakeError {
            switch plain {
            case .invalidRecordLength(_): return false
            default: return true
            }
        }
        if let masked = error as? MaskedHandshakeError {
            switch masked {
            case .handshakeTimedOut(_), .invalidServerHello, .hybridShareMissing,
                 .invalidMLKEMSharedSecret(_):
                return false
            case .unsupportedWireMode(_), .udpAdapterRequired,
                 .invalidMLKEMEncapsulationKey(_), .emptyClientHello,
                 .staticBindingNeedsPinnedKey, .serverKeyMismatch,
                 .proofOnlyNeedsPinnedKey, .serverProofTooShort(_),
                 .invalidServerProof, .authenticationFailed(_),
                 .invalidOKResponse, .invalidJoinTokenLength(_),
                 .invalidStreamIndex(_), .joinRejected:
                return true
            }
        }
        if let transport = error as? MaskedTransportError {
            switch transport {
            case .obfsTCPRequired, .realityTCPRequired, .emptyObfsKey,
                 .realityNeedsPinnedKey, .realityNeedsShortID, .invalidPinnedKey,
                 .invalidReadLength(_), .invalidRandomRange, .invalidHTTPRequest:
                return true
            case .webSocketUpgradeRejected, .invalidHTTPResponse, .httpHeadTooLarge,
                 .webSocketPayloadTooLarge(_), .junkRecordTooLarge(_), .junkAfterBufferedData,
                 .invalidTLSHeader, .invalidTLSRecordLength(_):
                return false
            }
        }
        if let datagram = error as? UDPDatagramCodecError {
            switch datagram {
            case .emptyObfsKey, .invalidObfsKeyLength(_), .invalidConnectionID:
                return true
            case .invalidQUICPacket, .emptyPayload, .truncatedRecordHeader(_),
                 .truncatedRecord(_, _), .randomFailure(_):
                return false
            }
        }
        return false
    }

    private func readPackets() async -> ([Data], [NSNumber]) {
        await withCheckedContinuation { continuation in
            provider.packetFlow.readPackets { packets, protocols in
                continuation.resume(returning: (packets, protocols))
            }
        }
    }

    private func writePacket(_ packet: Data) throws {
        let family = packet.first.map { $0 >> 4 == 6 ? AF_INET6 : AF_INET } ?? AF_INET
        let accepted = packetWriteLock.withLock {
            provider.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: family)])
        }
        guard accepted else { throw TunnelEngineError.packetInjectionFailed }
    }

    private func recordTraffic(upload: UInt64, download: UInt64) {
        stateLock.withLock {
            snapshot.bytesUploaded &+= upload
            snapshot.bytesDownloaded &+= download
        }
    }

    private func publishStatsTick() {
        let now = Date()
        stateLock.withLock {
            guard !stopped else { return }
            let elapsed = now.timeIntervalSince(lastStatsDate)
            guard elapsed > 0 else { return }
            snapshot.uploadBytesPerSecond = UInt64(
                Double(snapshot.bytesUploaded &- sampledUpload) / elapsed
            )
            snapshot.downloadBytesPerSecond = UInt64(
                Double(snapshot.bytesDownloaded &- sampledDownload) / elapsed
            )
            sampledUpload = snapshot.bytesUploaded
            sampledDownload = snapshot.bytesDownloaded
            lastStatsDate = now
            snapshot.updatedAt = now
            sharedStore.save(snapshot)
        }
    }

    private func totalTraffic() -> UInt64 {
        stateLock.withLock {
            let (value, overflow) = snapshot.bytesUploaded.addingReportingOverflow(
                snapshot.bytesDownloaded
            )
            return overflow ? UInt64.max : value
        }
    }

    private func update(phase: TunnelPhase, message: String, error: String? = nil) {
        stateLock.withLock {
            snapshot.phase = phase
            snapshot.message = message
            snapshot.error = error
            snapshot.updatedAt = Date()
            sharedStore.save(snapshot)
        }
        if !message.isEmpty { sharedStore.appendLog(message) }
    }

    private func resetSnapshot(phase: TunnelPhase, message: String, error: String?) {
        stateLock.withLock {
            activeSession = nil
            snapshot.phase = phase
            snapshot.message = message
            snapshot.error = error
            snapshot.clientAddress = nil
            snapshot.connectedAt = nil
            snapshot.bytesUploaded = 0
            snapshot.bytesDownloaded = 0
            snapshot.uploadBytesPerSecond = 0
            snapshot.downloadBytesPerSecond = 0
            sampledUpload = 0
            sampledDownload = 0
            lastStatsDate = Date()
            snapshot.updatedAt = lastStatsDate
            sharedStore.save(snapshot)
        }
        if !message.isEmpty { sharedStore.appendLog(message) }
    }

    private static func multipath(from session: TunnelSessionConfiguration) -> MultipathSession? {
        guard session.maxStreams > 1, !session.sessionToken.isEmpty else { return nil }
        return try? MultipathSession(
            sessionTokenHex: session.sessionToken,
            maximumStreams: session.maxStreams,
            adaptive: session.multipathAdaptive
        )
    }

    private static func bootstrapSession(for config: VPNConfig) -> TunnelSessionConfiguration {
        TunnelSessionConfiguration(
            clientAddress: "198.18.0.1",
            prefixLength: 32,
            pushedDNS: [],
            pushedRoutes: [],
            mtu: config.mtu > 0 ? config.mtu : 1_400
        )
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func delayDescription(_ milliseconds: Int) -> String {
        if milliseconds < 1_000 { return "\(milliseconds) ms" }
        let seconds = Double(milliseconds) / 1_000
        return seconds.rounded(.towardZero) == seconds
            ? "\(Int(seconds)) s"
            : String(format: "%.1f s", seconds)
    }

    private static func ipv4Mask(prefixLength: Int) -> String {
        let prefix = min(max(prefixLength, 0), 32)
        let bits = prefix == 0 ? UInt32(0) : UInt32.max << UInt32(32 - prefix)
        return [24, 16, 8, 0].map { String((bits >> UInt32($0)) & 0xff) }
            .joined(separator: ".")
    }

    private static func ipv4Route(_ cidr: String) -> NEIPv4Route? {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2,
              let prefix = Int(parts[1]),
              (0...32).contains(prefix) else { return nil }
        return NEIPv4Route(
            destinationAddress: String(parts[0]),
            subnetMask: ipv4Mask(prefixLength: prefix)
        )
    }

    private static func deduplicated(_ routes: [NEIPv4Route]) -> [NEIPv4Route] {
        var seen = Set<String>()
        return routes.filter {
            seen.insert("\($0.destinationAddress)/\($0.destinationSubnetMask)").inserted
        }
    }
}

enum TunnelEngineError: LocalizedError {
    case packetInjectionFailed
    case transportUnavailable
    case sessionUnavailable
    case staleNetworkSettings
    case networkPathUnavailable
    case startTimedOut(Int)
    case unsupportedCombination(String)
    case reconnectStopped(ReconnectStopReason, String)

    var errorDescription: String? {
        switch self {
        case .packetInjectionFailed:
            return "iOS rejected a packet from the Qeli tunnel."
        case .transportUnavailable:
            return "The tunnel transport is unavailable."
        case .sessionUnavailable:
            return "The tunnel has no active network session to reload."
        case .staleNetworkSettings:
            return "A newer tunnel session superseded these network settings."
        case .networkPathUnavailable:
            return "The active network path is unavailable."
        case .startTimedOut(let seconds):
            return "The Qeli handshake did not finish within \(seconds) seconds."
        case .unsupportedCombination(let value):
            return "Unsupported Qeli transport combination: \(value)."
        case .reconnectStopped(let reason, let detail):
            switch reason {
            case .disabled: return "Reconnect is disabled. Last error: \(detail)"
            case .retryLimitReached: return "Reconnect retry limit reached. Last error: \(detail)"
            }
        }
    }
}

private final class StartupDeadline: @unchecked Sendable {
    private let lock = NSLock()
    private var expired = false

    var didExpire: Bool { lock.withLock { expired } }
    func expire() { lock.withLock { expired = true } }
}

private enum UDPPathMTUProbeError: LocalizedError {
    case noResult(ceiling: Int)
    case randomFailure(OSStatus)

    var errorDescription: String? {
        switch self {
        case .noResult(let ceiling):
            return "UDP path-MTU probing produced no result below ceiling \(ceiling)."
        case .randomFailure(let status):
            return "Secure MTU probe identifier generation failed (\(status))."
        }
    }
}

/// Tracks the physical interface used by one Network.framework connection. A
/// satisfied Wi-Fi -> cellular (or reverse) transition is still a new underlying
/// path and must re-authenticate the Qeli session immediately.
private final class UnderlyingPathMonitor: @unchecked Sendable {
    private let lock = NSLock()
    private var signature: UInt8?

    init(initialPath: NWPath?) {
        signature = initialPath.map(Self.signature)
    }

    func requiresReconnect(for path: NWPath) -> Bool {
        guard path.status == .satisfied else { return true }
        let next = Self.signature(path)
        return lock.withLock {
            guard let previous = signature else {
                signature = next
                return false
            }
            guard previous != next else { return false }
            signature = next
            return true
        }
    }

    private static func signature(_ path: NWPath) -> UInt8 {
        var value: UInt8 = 0
        if path.usesInterfaceType(.wifi) { value |= 1 << 0 }
        if path.usesInterfaceType(.cellular) { value |= 1 << 1 }
        if path.usesInterfaceType(.wiredEthernet) { value |= 1 << 2 }
        if path.usesInterfaceType(.loopback) { value |= 1 << 3 }
        if path.usesInterfaceType(.other) { value |= 1 << 4 }
        return value
    }
}

private actor AsyncOperationGate {
    private var held = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !held {
            held = true
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        if waiters.isEmpty { held = false }
        else { waiters.removeFirst().resume() }
    }
}
