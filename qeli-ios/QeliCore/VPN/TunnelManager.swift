import Combine
import Foundation
import NetworkExtension

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
    private var connectInProgress = false

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
        operationGeneration &+= 1
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

        Self.configure(manager, profile: profile, config: config, settings: settings)
        try await Self.save(manager)
        try ensureCurrent(generation)
        try await Self.load(manager)
        try ensureCurrent(generation)

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
        let config = try VPNConfig(parsing: profile.configText)
        try await prepare()
        guard let manager else { throw TunnelManagerError.managerUnavailable }
        Self.configure(manager, profile: profile, config: config, settings: settings)
        try await Self.save(manager)
        try await Self.load(manager)
        systemStatus = manager.connection.status
        consume(status: systemStatus)
    }

    /// Stops and disables a previously installed Qeli configuration when an
    /// MDM-selected profile cannot be resolved. Keeping the old provider UUID or
    /// On-Demand rules here would turn a policy error into an unmanaged fallback.
    func failClosedForManagedProfilePolicy() async throws {
        operationGeneration &+= 1
        try await prepare()
        guard let manager else { throw TunnelManagerError.managerUnavailable }

        manager.connection.stopVPNTunnel()
        manager.onDemandRules = []
        manager.isOnDemandEnabled = false

        let qeliProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol
        guard qeliProtocol?.providerBundleIdentifier == AppConstants.tunnelBundleIdentifier else {
            var value = snapshot
            value.phase = .disconnected
            value.message = ""
            clearConnectionFields(&value)
            publish(value)
            return
        }

        manager.isEnabled = false
        try await Self.save(manager)
        try await Self.load(manager)
        systemStatus = manager.connection.status
        consume(status: systemStatus)
    }

    func updateOnDemand(_ enabled: Bool) async throws {
        try await prepare()
        guard let manager else { throw TunnelManagerError.managerUnavailable }
        manager.onDemandRules = enabled ? [NEOnDemandRuleConnect() as NEOnDemandRule] : []
        manager.isOnDemandEnabled = enabled
        if manager.isEnabled { try await Self.save(manager) }
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
        manager?.connection.stopVPNTunnel()
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
    }

    func refreshSnapshot() {
        snapshot = sharedStore.snapshot()
        consume(status: manager?.connection.status ?? .invalid)
    }

    private func consume(status: NEVPNStatus) {
        systemStatus = status
        var value = sharedStore.snapshot()
        switch status {
        case .invalid, .disconnected:
            if value.phase != .error { value.phase = .disconnected; value.message = "" }
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
        value.connectedAt = nil
        value.bytesUploaded = 0
        value.bytesDownloaded = 0
        value.uploadBytesPerSecond = 0
        value.downloadBytesPerSecond = 0
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
            && !config.allowIPv6Leak
            && !config.allowLAN
            && !settings.allowLAN
            && config.excludeRoutes.isEmpty
        tunnelProtocol.includeAllNetworks = strictFullTunnel
        tunnelProtocol.enforceRoutes = config.isFullTunnel
        tunnelProtocol.excludeLocalNetworks = config.allowLAN || settings.allowLAN
        tunnelProtocol.excludeAPNs = false
        tunnelProtocol.excludeCellularServices = false
        // No credentials/profile text in Network Extension preferences. The provider
        // uses this UUID to read the encrypted App Group store through shared Keychain.
        tunnelProtocol.providerConfiguration = [
            "schema": 1,
            "profileID": profile.id.uuidString
        ]
        manager.protocolConfiguration = tunnelProtocol
        manager.localizedDescription = "Qeli"
        manager.isEnabled = true
        manager.onDemandRules = settings.onDemandEnabled
            ? [NEOnDemandRuleConnect() as NEOnDemandRule]
            : []
        manager.isOnDemandEnabled = settings.onDemandEnabled
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
        try await withCheckedThrowingContinuation { continuation in
            manager.saveToPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: ()) }
            }
        }
    }

    private static func load(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { continuation in
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

    var errorDescription: String? {
        switch self {
        case .managerUnavailable: return "The system VPN manager is unavailable."
        case .sessionUnavailable: return "The Qeli Packet Tunnel session is unavailable."
        case .connectAlreadyInProgress: return "A Qeli connection attempt is already in progress."
        case .providerMessageRejected(let message): return "The Packet Tunnel rejected the settings update: \(message)"
        }
    }
}
