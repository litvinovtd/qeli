import Combine
import Foundation
import NetworkExtension

/// A tiny MainActor FIFO mutex for NetworkExtension preference mutations. MainActor alone is
/// not enough: saveToPreferences/loadFromPreferences suspend, so another Task can re-enter and
/// mutate the same NETunnelProviderManager before the first save completes.
@MainActor
final class PreferenceMutationGate {
    private var held = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func withLock<T>(_ operation: @MainActor () async throws -> T) async rethrows -> T {
        await acquire()
        defer { release() }
        return try await operation()
    }

    private func acquire() async {
        if !held {
            held = true
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    private func release() {
        if waiters.isEmpty {
            held = false
        } else {
            waiters.removeFirst().resume()
        }
    }
}

@MainActor
final class TunnelManager: NSObject, ObservableObject {
    @Published private(set) var snapshot: TunnelSnapshot
    @Published private(set) var systemStatus: NEVPNStatus = .invalid

    private let sharedStore: SharedTunnelStore
    private var manager: NETunnelProviderManager?
    private var prepareTask: Task<NETunnelProviderManager, Error>?
    private var statusObserver: NSObjectProtocol?
    private var statsTimer: Timer?
    private var operationGeneration: UInt64 = 0
    /// Revision assigned synchronously by the UI before it launches an asynchronous
    /// On-Demand preference write. This is separate from `operationGeneration`: a
    /// settings edit must not cancel a tunnel connection attempt, but an older edit
    /// that was suspended in `prepare()` must not persist after a newer edit.
    private var onDemandPreferenceRevision: UInt64 = 0
    private var connectInProgress = false
    private let preferenceMutationGate = PreferenceMutationGate()

    init(sharedStore: SharedTunnelStore = SharedTunnelStore()) {
        self.sharedStore = sharedStore
        self.snapshot = sharedStore.snapshot()
        super.init()
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let connection = notification.object as? NEVPNConnection else { return }
            Task { @MainActor [weak self] in
                guard let self,
                      let ownConnection = self.manager?.connection,
                      connection === ownConnection else { return }
                self.consume(status: connection.status)
            }
        }
    }

    deinit {
        if let statusObserver { NotificationCenter.default.removeObserver(statusObserver) }
        statsTimer?.invalidate()
    }

    func prepare() async throws {
        if let manager {
            systemStatus = manager.connection.status
            consume(status: systemStatus)
            return
        }
        let task: Task<NETunnelProviderManager, Error>
        if let existing = prepareTask {
            task = existing
        } else {
            task = Task {
                let managers = try await Self.loadManagers()
                return managers.first(where: { candidate in
                    (candidate.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                        == AppConstants.tunnelBundleIdentifier
                }) ?? NETunnelProviderManager()
            }
            prepareTask = task
        }
        do {
            let loaded = try await task.value
            if manager == nil { manager = loaded }
            prepareTask = nil
            if let manager {
                systemStatus = manager.connection.status
                consume(status: systemStatus)
            }
        } catch {
            prepareTask = nil
            throw error
        }
    }

    func connect(profile: Profile, settings: AppSettings) async throws {
        guard !connectInProgress else { throw TunnelManagerError.connectAlreadyInProgress }
        // reality-tls seals the auth token into the ClientHello, so it cannot even be built
        // without the pinned key + short id. Android refuses this up front with a readable
        // message; without the check iOS dialled out and failed deep in the handshake.
        if let config = try? VPNConfig(parsing: profile.configText),
           config.wireMode.lowercased() == "reality-tls",
           config.serverPublicKeyHex?.isEmpty != false || config.realityShortID?.isEmpty != false {
            throw TunnelManagerError.realityRequiresPinnedKey
        }
        operationGeneration &+= 1
        invalidatePendingOnDemandUpdates()
        let generation = operationGeneration
        connectInProgress = true
        var handedOffToSystem = false
        defer {
            connectInProgress = false
            let status = manager?.connection.status ?? .invalid
            if operationGeneration != generation && (status == .invalid || status == .disconnected) {
                var value = snapshot
                value.phase = .disconnected
                value.message = ""
                clearConnectionFields(&value)
                publish(value)
            } else if operationGeneration == generation && !handedOffToSystem {
                var value = snapshot
                value.phase = .error
                value.message = "Could not start the VPN tunnel"
                value.error = value.message
                clearConnectionFields(&value)
                publish(value)
            }
        }

        let config = try VPNConfig(parsing: profile.configText)
        var value = snapshot
        value.phase = .preparing
        value.profileID = profile.id
        value.message = "Installing VPN configuration…"
        value.error = nil
        clearConnectionFields(&value)
        publish(value)

        try await prepare()
        try ensureCurrent(generation)
        guard let manager else { throw TunnelManagerError.managerUnavailable }

        try await preferenceMutationGate.withLock {
            try ensureCurrent(generation)
            Self.configure(manager, profile: profile, config: config, settings: settings)
            try await Self.save(manager)
            try ensureCurrent(generation)
            try await Self.load(manager)
            try ensureCurrent(generation)
        }

        guard let session = manager.connection as? NETunnelProviderSession else {
            throw TunnelManagerError.sessionUnavailable
        }
        try ensureCurrent(generation)
        try session.startTunnel(options: ["profileID": profile.id.uuidString as NSString])
        handedOffToSystem = true
        startStatsPolling()
    }

    /// Persists the profile UUID used by future On-Demand/provider launches without
    /// starting or replacing the currently running tunnel. Managed app policy uses
    /// this so a background start cannot fall back to a previously selected profile.
    func applyProfileConfiguration(profile: Profile, settings: AppSettings) async throws {
        invalidatePendingOnDemandUpdates()
        let config = try VPNConfig(parsing: profile.configText)
        try await prepare()
        guard let manager else { throw TunnelManagerError.managerUnavailable }
        try await preferenceMutationGate.withLock {
            Self.configure(manager, profile: profile, config: config, settings: settings)
            try await Self.save(manager)
            try await Self.load(manager)
        }
        systemStatus = manager.connection.status
        consume(status: systemStatus)
    }

    /// Stops and disables a previously installed Qeli configuration when an
    /// MDM-selected profile cannot be resolved. Keeping the old provider UUID or
    /// On-Demand rules here would turn a policy error into an unmanaged fallback.
    func failClosedForManagedProfilePolicy() async throws {
        operationGeneration &+= 1
        invalidatePendingOnDemandUpdates()
        try await prepare()
        guard let manager else { throw TunnelManagerError.managerUnavailable }

        let qeliProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol
        guard qeliProtocol?.providerBundleIdentifier == AppConstants.tunnelBundleIdentifier else {
            // Even a non-Qeli manager may have been returned after Qeli was uninstalled or
            // its provider identifier changed. Preserve the original fail-closed contract:
            // stop the selected manager and remove automatic restart rules, but do not
            // disable or overwrite another provider's protocol configuration.
            await preferenceMutationGate.withLock {
                manager.connection.stopVPNTunnel()
                manager.onDemandRules = []
                manager.isOnDemandEnabled = false
            }
            var value = snapshot
            value.phase = .disconnected
            value.message = ""
            clearConnectionFields(&value)
            publish(value)
            return
        }

        try await preferenceMutationGate.withLock {
            manager.connection.stopVPNTunnel()
            manager.onDemandRules = []
            manager.isOnDemandEnabled = false
            manager.isEnabled = false
            try await Self.save(manager)
            try await Self.load(manager)
        }
        systemStatus = manager.connection.status
        consume(status: systemStatus)
    }

    /// Reserves an ordering revision before the caller creates an asynchronous Task.
    /// Calling this synchronously from the setting mutation preserves user-event order,
    /// rather than the non-deterministic order in which those Tasks reach `prepare()`.
    func reserveOnDemandUpdate() -> UInt64 {
        onDemandPreferenceRevision &+= 1
        return onDemandPreferenceRevision
    }

    func updateOnDemand(settings: AppSettings, revision: UInt64) async throws {
        try await prepare()
        try ensureCurrentOnDemandRevision(revision)
        guard let manager else { throw TunnelManagerError.managerUnavailable }
        try await preferenceMutationGate.withLock {
            try ensureCurrentOnDemandRevision(revision)
            let rules = Self.makeOnDemandRules(settings: settings)
            manager.onDemandRules = rules
            manager.isOnDemandEnabled = !rules.isEmpty
            // Persist ALWAYS. The save used to be gated on `manager.isEnabled`, so with a
            // disabled manager this mutated the in-memory object, wrote nothing to the VPN
            // preferences, and returned success. Serialize the complete mutate/save/load
            // transaction as well: MainActor may re-enter at either await, and an older
            // Trusted Wi-Fi edit must never overwrite a newer rule set.
            try await Self.save(manager)
            try await Self.load(manager)
            // The revision can change while either callback is suspended. The older write may
            // already have reached preferences, but its caller must not perform a follow-up
            // action (notably manual stop); the queued latest revision will replace it.
            try ensureCurrentOnDemandRevision(revision)
        }
        systemStatus = manager.connection.status
        consume(status: systemStatus)
    }

    func reloadProviderSettings() async throws {
        guard systemStatus == .connected,
              let session = manager?.connection as? NETunnelProviderSession else {
            throw TunnelManagerError.sessionUnavailable
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            do {
                try session.sendProviderMessage(Data("reload-settings".utf8)) { data in
                    guard let data, let response = String(data: data, encoding: .utf8) else {
                        continuation.resume(throwing: TunnelManagerError.providerMessageRejected("empty response"))
                        return
                    }
                    if response == "ok" { continuation.resume(returning: ()) }
                    else { continuation.resume(throwing: TunnelManagerError.providerMessageRejected(response)) }
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    func disconnect() {
        operationGeneration &+= 1
        let status = manager?.connection.status ?? .invalid
        var value = snapshot
        if !connectInProgress && (status == .invalid || status == .disconnected) {
            value.phase = .disconnected
            value.message = ""
            clearConnectionFields(&value)
        } else {
            value.phase = .disconnecting
            value.message = "Stopping tunnel…"
        }
        publish(value)
        // Publish the loss of the private path before asking NetworkExtension to remove it.
        // AppModel normally cancels and awaits update checks before calling this method; this
        // ordering also makes every observer see the loss before the stop completes.
        manager?.connection.stopVPNTunnel()
    }

    func refreshSnapshot() {
        snapshot = sharedStore.snapshot()
        consume(status: manager?.connection.status ?? .invalid)
    }

    private func consume(status: NEVPNStatus) {
        systemStatus = status
        var value = sharedStore.snapshot()
        switch status {
        case .invalid:
            if value.phase != .error {
                value.phase = .disconnected
                value.message = ""
            }
            clearConnectionFields(&value)
            statsTimer?.invalidate(); statsTimer = nil
        case .disconnected:
            if value.phase != .error {
                if trustedWiFiPolicyIsArmed {
                    value.phase = .waiting
                    // NetworkExtension exposes the installed rules but not which rule matched.
                    // Calling every disconnected state "trusted Wi-Fi" was observably false on
                    // cellular, no-network and transient reconnect paths. Keep the desired-state
                    // lock, but describe only what the app can prove: auto-resume policy is armed.
                    value.message = "Connect On Demand is waiting for the current network policy."
                } else {
                    value.phase = .disconnected
                    value.message = ""
                }
            }
            clearConnectionFields(&value)
            statsTimer?.invalidate(); statsTimer = nil
        case .connecting:
            value.phase = .connecting
            if value.message.isEmpty { value.message = "Starting…" }
        case .connected:
            // `startTunnel` completes after the fail-closed TUN is installed; the
            // Qeli supervisor may still be authenticating. Treat the system state
            // as "provider running" and let the provider snapshot be the sole
            // authority that promotes the UI to Connected.
            if value.phase != .connected && value.phase != .reconnecting {
                value.phase = .connecting
                if value.message.isEmpty { value.message = "Opening encrypted transport…" }
            }
            startStatsPolling()
            requestProviderSnapshot()
        case .reasserting:
            value.phase = .reconnecting
            value.message = "Reconnecting…"
        case .disconnecting:
            value.phase = .disconnecting
            value.message = "Stopping tunnel…"
        @unknown default:
            break
        }
        publish(value)
    }

    private func clearConnectionFields(_ value: inout TunnelSnapshot) {
        value.clientAddress = nil
        value.tunnelAddresses = nil
        value.tunnelGateway = nil
        value.connectedAt = nil
        value.bytesUploaded = 0
        value.bytesDownloaded = 0
        value.uploadBytesPerSecond = 0
        value.downloadBytesPerSecond = 0
        value.privateUpdatePath = nil
        value.liveConnectionProperties = nil
        value.updatedAt = Date()
    }

    private func startStatsPolling() {
        guard statsTimer == nil else { return }
        statsTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.requestProviderSnapshot() }
        }
        requestProviderSnapshot()
    }

    private func requestProviderSnapshot() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        do {
            try session.sendProviderMessage(Data("snapshot".utf8)) { [weak self] data in
                guard let data,
                      let value = try? JSONDecoder().decode(TunnelSnapshot.self, from: data) else { return }
                Task { @MainActor in self?.publish(value) }
            }
        } catch {
            // A connection can transition between the status check and this message.
        }
    }

    private func publish(_ value: TunnelSnapshot) {
        var value = value
        value.updatedAt = Date()
        snapshot = value
        sharedStore.save(value)
    }

    private func ensureCurrent(_ generation: UInt64) throws {
        guard operationGeneration == generation else { throw CancellationError() }
    }

    private func ensureCurrentOnDemandRevision(_ revision: UInt64) throws {
        guard onDemandPreferenceRevision == revision else { throw CancellationError() }
    }

    private func invalidatePendingOnDemandUpdates() {
        onDemandPreferenceRevision &+= 1
    }

    private var trustedWiFiPolicyIsArmed: Bool {
        Self.hasTrustedWiFiDisconnectRule(
            isOnDemandEnabled: manager?.isOnDemandEnabled == true,
            rules: manager?.onDemandRules ?? []
        )
    }

    nonisolated static func hasTrustedWiFiDisconnectRule(
        isOnDemandEnabled: Bool,
        rules: [NEOnDemandRule]
    ) -> Bool {
        OnDemandPolicy.hasTrustedWiFiDisconnectRule(
            isOnDemandEnabled: isOnDemandEnabled,
            rules: rules
        )
    }

    /// Ordered first-match policy: exact trusted Wi-Fi names pause the tunnel; every other
    /// known or unknown network falls through to Connect. `connectionDesired` is cleared by
    /// an explicit Disconnect, disabling the whole policy until the next explicit Connect.
    nonisolated static func makeOnDemandRules(settings: AppSettings) -> [NEOnDemandRule] {
        OnDemandPolicy.makeRules(settings: settings)
    }

    private static func configure(
        _ manager: NETunnelProviderManager,
        profile: Profile,
        config: VPNConfig,
        settings: AppSettings
    ) {
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = AppConstants.tunnelBundleIdentifier
        tunnelProtocol.serverAddress = config.serverAddress
        let strictFullTunnel = config.isFullTunnel
            && !config.allowIPv4Leak
            && !config.allowIPv6Leak
            && !config.allowLAN
            && !settings.allowLAN
            && config.excludeRoutes.isEmpty
        tunnelProtocol.includeAllNetworks = strictFullTunnel
        tunnelProtocol.enforceRoutes = config.isFullTunnel
        tunnelProtocol.excludeLocalNetworks = config.isFullTunnel
            && (config.allowLAN || settings.allowLAN)
        tunnelProtocol.excludeAPNs = false
        tunnelProtocol.excludeCellularServices = false
        // No credentials/profile text in Network Extension preferences. The provider
        // uses this UUID to read the encrypted App Group store through shared Keychain.
        tunnelProtocol.providerConfiguration = [
            "schema": 1,
            "profileID": profile.id.uuidString,
            "logLevel": settings.logLevel.rawValue
        ]
        manager.protocolConfiguration = tunnelProtocol
        manager.localizedDescription = "Qeli"
        manager.isEnabled = true
        let rules = makeOnDemandRules(settings: settings)
        manager.onDemandRules = rules
        manager.isOnDemandEnabled = !rules.isEmpty
    }

    private static func loadManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: managers ?? []) }
            }
        }
    }

    private static func save(_ manager: NETunnelProviderManager) async throws {
        // Void spelled out: the call is a bare statement, so there is no return type to infer
        // from, and both resume calls sit inside the completion closure.
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: ()) }
            }
        }
    }

    private static func load(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: ()) }
            }
        }
    }
}

enum TunnelManagerError: LocalizedError {
    case managerUnavailable
    case sessionUnavailable
    case connectAlreadyInProgress
    case providerMessageRejected(String)
    case realityRequiresPinnedKey

    var errorDescription: String? {
        switch self {
        case .managerUnavailable: return "The system VPN manager is unavailable."
        case .sessionUnavailable: return "The Qeli Packet Tunnel session is unavailable."
        case .connectAlreadyInProgress: return "A Qeli connection attempt is already in progress."
        case .realityRequiresPinnedKey:
            return "reality-tls needs both the pinned server key and reality_sid; add them to the profile."
        case .providerMessageRejected(let message): return "The Packet Tunnel rejected the settings update: \(message)"
        }
    }
}
