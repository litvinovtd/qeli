import Foundation
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let sharedStore = SharedTunnelStore()
    private let lifecycleLock = NSRecursiveLock()
    let settingsGate = ProviderOperationGate()
    let packetReadGate = ProviderOperationGate()
    private var engine: QeliNativeTunnelEngine?
    private var sessionLogStore: SharedTunnelStore?
    private var startTask: Task<Void, Never>?
    private var startCompletion: ProviderStartCompletion?
    private var lifecycleGeneration: UInt64 = 0

    override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let completion = ProviderStartCompletion(completionHandler)
        let state = lifecycleLock.withLock { () -> (
            generation: UInt64,
            previousTask: Task<Void, Never>?,
            previousCompletion: ProviderStartCompletion?,
            previousEngine: QeliNativeTunnelEngine?,
            logStore: SharedTunnelStore
        ) in
            lifecycleGeneration &+= 1
            sessionLogStore?.finishLogSession(clear: false)
            let logStore = SharedTunnelStore()
            sessionLogStore = logStore
            let value = (lifecycleGeneration, startTask, startCompletion, engine, logStore)
            startTask = nil
            startCompletion = completion
            engine = nil
            reasserting = false
            return value
        }
        state.previousTask?.cancel()
        state.previousCompletion?.finish(CancellationError())

        let task = Task { [weak self] in
            guard let self else { completion.finish(CancellationError()); return }
            if let previousEngine = state.previousEngine { await previousEngine.stop() }
            var startedEngine: QeliNativeTunnelEngine?
            do {
                try Task.checkCancellation()
                guard isCurrent(state.generation) else { throw CancellationError() }
                guard PacketTunnelSigningDiagnostics.hasRequiredEntitlements() else {
                    throw PacketTunnelProviderError.invalidSigning
                }
                // The app owns profile publication; the extension is a read-only consumer.
                let archive = try ProfileStore().load(initializeIfMissing: false)
                let profileID = TunnelProfileSelection.resolve(
                    requested: options?["profileID"],
                    configured: (protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerConfiguration?["profileID"]
                )
                let configuredLogLevel = ((protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerConfiguration?["logLevel"] as? String)
                // A one-shot app request wins; automatic launches must carry the
                // exact persisted provider UUID. Never fall back to a locally active
                // profile when managed/provider configuration is missing or stale.
                guard let profileID,
                      let profile = archive.profiles.first(where: { $0.id == profileID }) else {
                    throw PacketTunnelProviderError.profileNotFound
                }
                let config = try VPNConfig(parsing: profile.configText)
                let engine = QeliNativeTunnelEngine(
                    provider: self,
                    profile: profile,
                    config: config,
                    logLevel: configuredLogLevel ?? config.loggingLevel ?? "info",
                    sharedStore: state.logStore
                )
                startedEngine = engine
                guard install(engine: engine, generation: state.generation) else {
                    throw CancellationError()
                }
                try await engine.start()
                try Task.checkCancellation()
                guard isCurrent(state.generation) else { throw CancellationError() }
                // Do not report success if the tunnel has ALREADY failed terminally.
                //
                // `engine.start()` spawns the connection supervisor as a detached task and
                // returns as soon as the fail-closed TUN is installed. That supervisor can
                // reach `terminalFailure` — and therefore `cancelTunnelWithError` — before
                // we get here; a `proto = udp` + `mode = plain` profile does it
                // immediately, because `unsupportedCombination` is classified as fatal.
                // Finishing with `nil` then told NetworkExtension the tunnel had started
                // while it was being torn down: the UI flickered connected → failed, and
                // with On-Demand enabled iOS relaunched the provider in a loop.
                // (Audit 2026-07-27, M4.)
                let snapshot = engine.currentSnapshot()
                if snapshot.phase == .error && !engine.isFailClosedSecurityHold() {
                    let reason = snapshot.error ?? snapshot.message
                    throw PacketTunnelProviderError.startFailed(reason)
                }
                completion.finish(nil)
            } catch is CancellationError {
                if let startedEngine { await startedEngine.stop() }
                if let startedEngine { clear(engine: startedEngine, generation: state.generation) }
                completion.finish(CancellationError())
            } catch {
                if let startedEngine { await startedEngine.stop() }
                if let startedEngine { clear(engine: startedEngine, generation: state.generation) }
                recordStartFailure(error, generation: state.generation)
                completion.finish(error)
            }
            finishStart(generation: state.generation)
        }
        let retained = lifecycleLock.withLock { () -> Bool in
            guard lifecycleGeneration == state.generation, startCompletion === completion else { return false }
            startTask = task
            return true
        }
        if !retained { task.cancel() }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        let state = lifecycleLock.withLock { () -> (
            generation: UInt64,
            task: Task<Void, Never>?,
            completion: ProviderStartCompletion?,
            engine: QeliNativeTunnelEngine?,
            logStore: SharedTunnelStore?
        ) in
            lifecycleGeneration &+= 1
            let value = (lifecycleGeneration, startTask, startCompletion, engine, sessionLogStore)
            startTask = nil
            startCompletion = nil
            engine = nil
            reasserting = false
            return value
        }
        state.task?.cancel()
        state.completion?.finish(CancellationError())
        Task {
            await state.engine?.stop()
            var finalSnapshot = state.engine?.currentSnapshot() ?? sharedStore.snapshot()
            if state.engine == nil && finalSnapshot.phase != .error {
                finalSnapshot = TunnelSnapshot()
            }
            lifecycleLock.withLock {
                if lifecycleGeneration == state.generation, engine == nil {
                    let settings = SettingsStore().load()
                    // Network changes/sleep are resumable interruptions. NE does not
                    // identify the matching On Demand rule; retain diagnostics for its
                    // unspecified stops while the desired connection remains armed.
                    let resuming: Bool
                    switch reason {
                    case .noNetworkAvailable, .unrecoverableNetworkChange, .sleep, .appUpdate:
                        resuming = true
                    case .none:
                        resuming = settings.onDemandEnabled && settings.connectionDesired
                    default:
                        resuming = false
                    }
                    let retainForResume = resuming && finalSnapshot.phase != .error
                    state.logStore?.finishLogSession(
                        clear: settings.clearLogOnDisconnect && !retainForResume,
                        terminalError: finalSnapshot.phase == .error
                    )
                    sessionLogStore = nil
                    sharedStore.save(finalSnapshot)
                }
            }
            completionHandler()
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        let activeEngine = lifecycleLock.withLock { engine }
        if String(data: messageData, encoding: .utf8) == "reload-settings" {
            guard let activeEngine else {
                completionHandler?(Data("error:no active tunnel".utf8))
                return
            }
            Task {
                do {
                    try await activeEngine.reloadNetworkSettings()
                    completionHandler?(Data("ok".utf8))
                } catch {
                    lifecycleLock.withLock {
                        if engine === activeEngine {
                            sessionLogStore?.appendLog("ERROR reloading settings: \(error.localizedDescription)")
                        }
                    }
                    completionHandler?(Data("error:\(error.localizedDescription)".utf8))
                }
            }
            return
        }
        let snapshot = activeEngine?.currentSnapshot() ?? sharedStore.snapshot()
        completionHandler?(try? JSONEncoder().encode(snapshot))
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        lifecycleLock.withLock { sessionLogStore?.appendLog("Device sleeping") }
        completionHandler()
    }

    override func wake() { lifecycleLock.withLock { engine }?.wake() }

    private func isCurrent(_ generation: UInt64) -> Bool {
        lifecycleLock.withLock { lifecycleGeneration == generation }
    }

    private func install(engine newEngine: QeliNativeTunnelEngine, generation: UInt64) -> Bool {
        let initial = newEngine.currentSnapshot() // never take the engine lock while holding lifecycleLock
        return lifecycleLock.withLock {
            guard lifecycleGeneration == generation else { return false }
            engine = newEngine
            sharedStore.save(initial)
            return true
        }
    }

    private func clear(engine value: QeliNativeTunnelEngine, generation: UInt64) {
        lifecycleLock.withLock {
            guard lifecycleGeneration == generation, engine === value else { return }
            engine = nil
        }
    }

    private func finishStart(generation: UInt64) {
        lifecycleLock.withLock {
            guard lifecycleGeneration == generation else { return }
            startTask = nil
            startCompletion = nil
        }
    }

    private func recordStartFailure(_ error: Error, generation: UInt64) {
        lifecycleLock.withLock {
            guard lifecycleGeneration == generation else { return }
            var snapshot = sharedStore.snapshot()
            snapshot.phase = .error
            snapshot.error = error.localizedDescription
            snapshot.message = error.localizedDescription
            snapshot.privateUpdatePath = nil
            snapshot.liveConnectionProperties = nil
            snapshot.updatedAt = Date()
            sharedStore.save(snapshot)
            sessionLogStore?.appendLog("ERROR: \(error.localizedDescription)")
            sessionLogStore?.finishLogSession(
                clear: SettingsStore().load().clearLogOnDisconnect, terminalError: true
            )
            sessionLogStore = nil
        }
    }

    func ownsEngine(_ owner: QeliNativeTunnelEngine) -> Bool {
        lifecycleLock.withLock { engine === owner }
    }

    func publishEngineSnapshot(_ snapshot: TunnelSnapshot, owner: QeliNativeTunnelEngine) {
        lifecycleLock.withLock {
            guard engine === owner else { return }
            sharedStore.save(snapshot)
        }
    }

    func setEngineReasserting(_ value: Bool, owner: QeliNativeTunnelEngine) {
        lifecycleLock.withLock {
            guard engine === owner else { return }
            reasserting = value
        }
    }

    func cancelEngineTunnel(_ error: Error, owner: QeliNativeTunnelEngine) {
        lifecycleLock.withLock {
            guard engine === owner else { return }
            // Cover provider-initiated terminal cancellation too; cleanup must not
            // depend on a later system stop callback. Security holds do not call here.
            sessionLogStore?.finishLogSession(
                clear: SettingsStore().load().clearLogOnDisconnect, terminalError: true
            )
            sessionLogStore = nil
            cancelTunnelWithError(error)
        }
    }

    func applyEngineSettings(
        _ settings: NEPacketTunnelNetworkSettings, owner: QeliNativeTunnelEngine,
        completion: @escaping (Error?) -> Void
    ) -> Bool {
        lifecycleLock.withLock {
            guard engine === owner else { return false }
            setTunnelNetworkSettings(settings, completionHandler: completion)
            return true
        }
    }

    func readEnginePackets(
        owner: QeliNativeTunnelEngine, completion: @escaping ([Data], [NSNumber]) -> Void
    ) -> Bool {
        lifecycleLock.withLock {
            guard engine === owner else { return false }
            packetFlow.readPackets(completionHandler: completion)
            return true
        }
    }

    func writeEnginePackets(
        _ packets: [Data], protocols: [NSNumber], owner: QeliNativeTunnelEngine
    ) -> Bool {
        lifecycleLock.withLock {
            guard engine === owner else { return false }
            return packetFlow.writePackets(packets, withProtocols: protocols)
        }
    }

}

private final class ProviderStartCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var handler: ((Error?) -> Void)?

    init(_ handler: @escaping (Error?) -> Void) { self.handler = handler }

    func finish(_ error: Error?) {
        let callback = lock.withLock { () -> ((Error?) -> Void)? in
            defer { handler = nil }
            return handler
        }
        callback?(error)
    }
}

private enum PacketTunnelSigningDiagnostics {
    static func hasRequiredEntitlements() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        guard let expectedAppGroup = Bundle.main.object(
                  forInfoDictionaryKey: "QeliAppGroup"
              ) as? String,
              !expectedAppGroup.isEmpty,
              !expectedAppGroup.contains("$("),
              let expectedKeychainGroup = Bundle.main.object(
                  forInfoDictionaryKey: "QeliKeychainAccessGroup"
              ) as? String,
              !expectedKeychainGroup.isEmpty,
              !expectedKeychainGroup.contains("$(") else { return false }
        // Reaching this process proves that iOS accepted the packet-tunnel entitlement.
        // Probe the remaining shared capabilities through public APIs so re-signed builds
        // fail with a useful diagnostic instead of using the private SecTask API.
        return FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: expectedAppGroup
        ) != nil && KeychainStore.canAccess(group: expectedKeychainGroup)
        #endif
    }
}

enum PacketTunnelProviderError: LocalizedError {
    case profileNotFound
    case invalidSigning
    /// The engine reached a terminal failure before `startTunnel` could report success.
    case startFailed(String)

    var errorDescription: String? {
        switch self {
        case .profileNotFound:
            return "The active encrypted Qeli profile was not found."
        case .invalidSigning:
            return "The Qeli Packet Tunnel extension is missing its VPN, App Group, or Keychain entitlement. Install a correctly signed build."
        case .startFailed(let reason):
            return reason.isEmpty ? "The Qeli tunnel failed to start." : reason
        }
    }
}
