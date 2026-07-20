import Foundation
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let sharedStore = SharedTunnelStore()
    private let lifecycleLock = NSLock()
    private var engine: QeliTunnelEngine?
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
            previousEngine: QeliTunnelEngine?
        ) in
            lifecycleGeneration &+= 1
            let value = (lifecycleGeneration, startTask, startCompletion, engine)
            startTask = nil
            startCompletion = completion
            engine = nil
            return value
        }
        state.previousTask?.cancel()
        state.previousCompletion?.finish(CancellationError())

        let task = Task { [weak self] in
            guard let self else { completion.finish(CancellationError()); return }
            if let previousEngine = state.previousEngine { await previousEngine.stop() }
            var startedEngine: QeliTunnelEngine?
            do {
                try Task.checkCancellation()
                guard isCurrent(state.generation) else { throw CancellationError() }
                let archive = try ProfileStore().load()
                let optionID = (options?["profileID"] as? NSString)
                    .map { $0 as String }
                    .flatMap(UUID.init(uuidString:))
                let configuredID = ((protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerConfiguration?["profileID"] as? String)
                    .flatMap(UUID.init(uuidString:))
                // A one-shot app request wins; automatic launches must carry the
                // exact persisted provider UUID. Never fall back to a locally active
                // profile when managed/provider configuration is missing or stale.
                let candidates = [optionID, configuredID].compactMap { $0 }
                guard let profile = candidates.compactMap({ id in
                    archive.profiles.first(where: { $0.id == id })
                }).first else {
                    throw PacketTunnelProviderError.profileNotFound
                }
                let config = try VPNConfig(parsing: profile.configText)
                let engine = QeliTunnelEngine(
                    provider: self,
                    profile: profile,
                    config: config,
                    sharedStore: sharedStore
                )
                startedEngine = engine
                guard install(engine: engine, generation: state.generation) else {
                    throw CancellationError()
                }
                try await engine.start()
                try Task.checkCancellation()
                guard isCurrent(state.generation) else { throw CancellationError() }
                completion.finish(nil)
            } catch is CancellationError {
                if isCurrent(state.generation), let startedEngine {
                    await startedEngine.stop()
                    clear(engine: startedEngine, generation: state.generation)
                }
                completion.finish(CancellationError())
            } catch {
                if isCurrent(state.generation) {
                    if let startedEngine { await startedEngine.stop() }
                    if isCurrent(state.generation) {
                        if let startedEngine { clear(engine: startedEngine, generation: state.generation) }
                        recordStartFailure(error)
                    }
                }
                completion.finish(error)
            }
            finishStart(generation: state.generation)
        }
        let retained = lifecycleLock.withLock { () -> Bool in
            guard lifecycleGeneration == state.generation else { return false }
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
            task: Task<Void, Never>?,
            completion: ProviderStartCompletion?,
            engine: QeliTunnelEngine?
        ) in
            lifecycleGeneration &+= 1
            let value = (startTask, startCompletion, engine)
            startTask = nil
            startCompletion = nil
            engine = nil
            return value
        }
        state.task?.cancel()
        state.completion?.finish(CancellationError())
        Task {
            await state.engine?.stop()
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
                    sharedStore.appendLog("ERROR reloading settings: \(error.localizedDescription)")
                    completionHandler?(Data("error:\(error.localizedDescription)".utf8))
                }
            }
            return
        }
        let snapshot = activeEngine?.currentSnapshot() ?? sharedStore.snapshot()
        completionHandler?(try? JSONEncoder().encode(snapshot))
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        sharedStore.appendLog("Device sleeping")
        completionHandler()
    }

    override func wake() { lifecycleLock.withLock { engine }?.wake() }

    private func isCurrent(_ generation: UInt64) -> Bool {
        lifecycleLock.withLock { lifecycleGeneration == generation }
    }

    private func install(engine newEngine: QeliTunnelEngine, generation: UInt64) -> Bool {
        lifecycleLock.withLock {
            guard lifecycleGeneration == generation else { return false }
            engine = newEngine
            return true
        }
    }

    private func clear(engine value: QeliTunnelEngine, generation: UInt64) {
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

    private func recordStartFailure(_ error: Error) {
        var snapshot = sharedStore.snapshot()
        snapshot.phase = .error
        snapshot.error = error.localizedDescription
        snapshot.message = error.localizedDescription
        snapshot.updatedAt = Date()
        sharedStore.save(snapshot)
        sharedStore.appendLog("ERROR: \(error.localizedDescription)")
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

enum PacketTunnelProviderError: LocalizedError {
    case profileNotFound

    var errorDescription: String? { "The active encrypted Qeli profile was not found." }
}
