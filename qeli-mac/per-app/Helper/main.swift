import Darwin
import Foundation
import NetworkExtension
import SystemExtensions

private let extensionIdentifier = "ru.qeli.app.perapp"

struct QeliPerAppCtl {
    static func main() {
        do {
            let arguments = CommandLine.arguments
            guard arguments.count >= 2 else { throw HelperError.usage }
            switch arguments[1] {
            case "prepare":
                try activateSystemExtension()
            case "start":
                guard arguments.count == 3 else { throw HelperError.usage }
                try installState(URL(fileURLWithPath: arguments[2]))
                try activateSystemExtension()
                do {
                    try configureDNS(enabled: true)
                    try configureAndStartTransparent()
                } catch {
                    try? mutateState { $0.tunnelUp = false }
                    try? stopAll()
                    throw error
                }
            case "update":
                guard arguments.count == 3 else { throw HelperError.usage }
                try installState(URL(fileURLWithPath: arguments[2]))
                do { try notifyTransparentProvider() }
                catch {
                    try? mutateState { $0.tunnelUp = false }
                    try? notifyTransparentProvider()
                    throw error
                }
            case "down":
                try mutateState { $0.tunnelUp = false }
                try notifyTransparentProvider()
            case "stop":
                try mutateState { $0.tunnelUp = false }
                try stopAll()
            case "guard":
                guard arguments.count == 5, let ownerPID = Int32(arguments[2]) else {
                    throw HelperError.usage
                }
                // Install before the potentially long system-extension approval flow. The
                // guardian can then renew a short lease throughout that wait; a power loss
                // never leaves a multi-minute stale allowance behind.
                try installState(URL(fileURLWithPath: arguments[4]))
                try guardOwner(ownerPID, executablePath: arguments[3])
            default: throw HelperError.usage
            }
            print("ok")
        } catch {
            FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }

    private static func installState(_ source: URL) throws {
        let state = try JSONDecoder().decode(RoutingState.self, from: Data(contentsOf: source))
        try RoutingStateStore.save(state)
    }

    private static func mutateState(_ body: (inout RoutingState) -> Void) throws {
        var state = try RoutingStateStore.load(); body(&state); try RoutingStateStore.save(state)
    }

    /// The preferences installed by NetworkExtension survive process death, reboot and app
    /// deletion. Keep a short lease alive while the owning qeli process and its executable
    /// still exist. If either disappears, expire the state and disable both managers. The
    /// already-running helper remains mapped even when Qeli.app is removed from Applications.
    private static func guardOwner(_ ownerPID: Int32, executablePath: String) throws {
        while processExists(ownerPID)
                && FileManager.default.fileExists(atPath: executablePath) {
            do {
                try mutateState {
                    $0.leaseExpiresAtUnixMs = unixMilliseconds() + 5_000
                }
            } catch {
                // Atomic state replacement by start/update may briefly race this heartbeat.
                // Keep trying: the current lease naturally expires (safe fail-open) until a
                // successful renewal rather than losing the only removal watchdog.
                FileHandle.standardError.write(Data(
                    "Qeli per-app lease renewal failed: \(error.localizedDescription)\n".utf8))
            }
            Thread.sleep(forTimeInterval: 1)
        }
        try? mutateState {
            $0.tunnelUp = false
            $0.leaseExpiresAtUnixMs = 0
        }
        try stopAll()
    }

    private static func processExists(_ pid: Int32) -> Bool {
        if kill(pid, 0) == 0 { return true }
        return errno == EPERM
    }

    private static func unixMilliseconds() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }

    private static func activateSystemExtension() throws {
        let waiter = ExtensionActivationWaiter()
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: DispatchQueue(label: "ru.qeli.perapp.activation"))
        request.delegate = waiter
        OSSystemExtensionManager.shared.submitRequest(request)
        try waiter.wait()
    }

    private static func configureAndStartTransparent() throws {
        let managers = try loadTransparentManagers()
        let manager = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                == extensionIdentifier
        }) ?? NETransparentProxyManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = extensionIdentifier
        proto.serverAddress = "Qeli per-app transport"
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Qeli per-app routing"
        manager.isEnabled = true
        try save(manager)
        // NetworkExtension requires a reload after the first save before startVPNTunnel.
        let loaded = try loadTransparentManagers().first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                == extensionIdentifier
        }) ?? manager
        if loaded.connection.status != .connected && loaded.connection.status != .connecting {
            try loaded.connection.startVPNTunnel()
        }
        try waitUntilConnected(loaded)
        try sendReload(loaded)
    }

    private static func notifyTransparentProvider() throws {
        guard let manager = try loadTransparentManagers().first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                == extensionIdentifier
        }) else { throw HelperError.transparentConfigurationMissing }
        if manager.connection.status != .connected && manager.connection.status != .connecting {
            guard manager.isEnabled else { throw HelperError.transparentConfigurationDisabled }
            try manager.connection.startVPNTunnel()
        }
        try waitUntilConnected(manager)
        try sendReload(manager)
    }

    private static func waitUntilConnected(_ manager: NETransparentProxyManager) throws {
        let deadline = Date().addingTimeInterval(30)
        while Date() < deadline {
            switch manager.connection.status {
            case .connected: return
            case .invalid:
                throw HelperError.transparentProviderUnavailable
            default:
                Thread.sleep(forTimeInterval: 0.2)
            }
        }
        throw HelperError.transparentProviderUnavailable
    }

    private static func sendReload(_ manager: NETransparentProxyManager) throws {
        guard let session = manager.connection as? NETunnelProviderSession else {
            throw HelperError.transparentSessionMissing
        }
        let semaphore = DispatchSemaphore(value: 0)
        var callbackError: Error?
        do {
            try session.sendProviderMessage(Data("reload".utf8)) { reply in
                if let reply, let text = String(data: reply, encoding: .utf8), text.hasPrefix("error:") {
                    callbackError = HelperError.providerRejected(text)
                }
                semaphore.signal()
            }
        } catch { throw error }
        guard semaphore.wait(timeout: .now() + 10) == .success else { throw HelperError.timeout }
        if let callbackError { throw callbackError }
    }

    private static func stopTransparent() throws {
        guard let manager = try loadTransparentManagers().first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                == extensionIdentifier
        }) else { return }
        manager.connection.stopVPNTunnel()
        manager.isEnabled = false
        try save(manager)
    }

    /// Always attempts both halves. Leaving the DNS proxy enabled because transparent
    /// teardown failed (or vice versa) is worse than returning the first error afterwards.
    private static func stopAll() throws {
        var firstError: Error?
        do { try stopTransparent() } catch { firstError = error }
        do { try configureDNS(enabled: false) } catch { if firstError == nil { firstError = error } }
        if let firstError { throw firstError }
    }

    private static func configureDNS(enabled: Bool) throws {
        let manager = NEDNSProxyManager.shared()
        try wait { done in manager.loadFromPreferences(completionHandler: done) }
        if enabled {
            let proto = NEDNSProxyProviderProtocol()
            proto.providerBundleIdentifier = extensionIdentifier
            manager.providerProtocol = proto
            manager.localizedDescription = "Qeli per-app DNS"
        }
        manager.isEnabled = enabled
        try wait { done in manager.saveToPreferences(completionHandler: done) }
    }

    private static func loadTransparentManagers() throws -> [NETransparentProxyManager] {
        let semaphore = DispatchSemaphore(value: 0)
        var result: [NETransparentProxyManager] = []
        var resultError: Error?
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            result = managers ?? []; resultError = error; semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + 15) == .success else { throw HelperError.timeout }
        if let resultError { throw resultError }
        return result
    }

    private static func save(_ manager: NETransparentProxyManager) throws {
        try wait { done in manager.saveToPreferences(completionHandler: done) }
    }

    private static func wait(_ operation: (@escaping (Error?) -> Void) -> Void) throws {
        let semaphore = DispatchSemaphore(value: 0)
        var resultError: Error?
        operation { error in resultError = error; semaphore.signal() }
        guard semaphore.wait(timeout: .now() + 30) == .success else { throw HelperError.timeout }
        if let resultError { throw resultError }
    }
}

private final class ExtensionActivationWaiter: NSObject, OSSystemExtensionRequestDelegate {
    private let semaphore = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var result: Result<Void, Error>?

    func wait() throws {
        guard semaphore.wait(timeout: .now() + 180) == .success else { throw HelperError.timeout }
        lock.lock(); let completed = result; lock.unlock()
        try completed?.get()
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        finish(result == .completed ? .success(()) : .failure(HelperError.rebootRequired))
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        finish(.failure(error))
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        FileHandle.standardError.write(Data(
            "Approve the Qeli network extension in System Settings > Privacy & Security.\n".utf8))
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties)
        -> OSSystemExtensionRequest.ReplacementAction { .replace }

    private func finish(_ value: Result<Void, Error>) {
        lock.lock()
        guard result == nil else { lock.unlock(); return }
        result = value; lock.unlock(); semaphore.signal()
    }
}

private enum HelperError: LocalizedError {
    case usage, timeout, rebootRequired, transparentConfigurationMissing
    case transparentConfigurationDisabled, transparentProviderUnavailable
    case transparentSessionMissing, providerRejected(String)

    var errorDescription: String? {
        switch self {
        case .usage: return "usage: QeliPerAppCtl prepare | start|update <state.json> | down | stop | guard <pid> <executable> <state.json>"
        case .timeout: return "macOS Network Extension operation timed out"
        case .rebootRequired: return "macOS must be restarted to activate the updated Qeli extension"
        case .transparentConfigurationMissing: return "Qeli transparent-proxy configuration is missing"
        case .transparentConfigurationDisabled: return "Qeli transparent-proxy configuration is disabled"
        case .transparentProviderUnavailable: return "Qeli transparent-proxy provider did not become connected"
        case .transparentSessionMissing: return "Qeli transparent-proxy session is unavailable"
        case .providerRejected(let text): return text
        }
    }
}

QeliPerAppCtl.main()
