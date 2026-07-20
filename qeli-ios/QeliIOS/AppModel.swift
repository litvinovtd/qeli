import Combine
import Foundation
import Network
import NetworkExtension
import SwiftUI
import WidgetKit

enum ReachabilityState: Equatable {
    case idle
    case checking
    case reachable(milliseconds: Int)
    case unavailable(String)
}

struct AppAlert: Identifiable {
    let id = UUID()
    var title: String
    var message: String
}

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var profiles: [Profile] = []
    @Published private(set) var activeProfileID: UUID?
    @Published var settings: AppSettings
    @Published private(set) var tunnelSnapshot: TunnelSnapshot
    @Published private(set) var reachability: [UUID: ReachabilityState] = [:]
    @Published private(set) var logLines: [TunnelLogLine] = []
    @Published private(set) var updateCheckState: UpdateCheckState = .idle
    @Published private(set) var managedConfiguration: QeliManagedConfiguration
    @Published var alert: AppAlert?
    @Published var pendingDeepLink: URL?

    let tunnelManager: TunnelManager
    private let profileStore: ProfileStore
    private let settingsStore: SettingsStore
    private let sharedTunnelStore: SharedTunnelStore
    private var archive: ProfileArchive
    private var cancellables = Set<AnyCancellable>()
    private var automaticUpdateChecked = false
    private var updateTask: Task<Void, Never>?

    init(
        profileStore: ProfileStore = ProfileStore(),
        settingsStore: SettingsStore = SettingsStore(),
        sharedTunnelStore: SharedTunnelStore = SharedTunnelStore()
    ) {
        let managedConfiguration = ManagedConfigurationReader().load()
        self.profileStore = profileStore
        self.settingsStore = settingsStore
        self.sharedTunnelStore = sharedTunnelStore
        self.settings = settingsStore.load()
        self.managedConfiguration = managedConfiguration
        self.tunnelManager = TunnelManager(sharedStore: sharedTunnelStore)
        self.tunnelSnapshot = sharedTunnelStore.snapshot()
        self.logLines = sharedTunnelStore.logLines()
        do {
            self.archive = try profileStore.load()
        } catch {
            self.archive = .initial
            self.alert = AppAlert(title: "Profile store error", message: error.localizedDescription)
        }
        profiles = archive.profiles
        if managedConfiguration.hasActiveProfilePolicy {
            activeProfileID = managedConfiguration.activeProfileID.flatMap { managedID in
                archive.profiles.contains(where: { $0.id == managedID }) ? managedID : nil
            }
        } else {
            activeProfileID = archive.activeProfileID
        }
        WidgetControlBridge.setWidgetControlsEnabled(
            managedConfiguration.widgetControlsEnabled ?? true
        )

        tunnelManager.$snapshot
            .receive(on: RunLoop.main)
            .sink { [weak self] value in
                let previousPhase = self?.tunnelSnapshot.phase
                self?.tunnelSnapshot = value
                self?.logLines = sharedTunnelStore.logLines()
                if previousPhase != value.phase {
                    WidgetCenter.shared.reloadTimelines(ofKind: AppConstants.statusWidgetKind)
                    if #available(iOS 18.0, *) {
                        ControlCenter.shared.reloadControls(ofKind: AppConstants.connectionControlKind)
                    }
                }
                if self?.hasPrivateUpdatePath != true {
                    self?.updateTask?.cancel()
                    self?.updateTask = nil
                }
                self?.maybeCheckForUpdates()
            }
            .store(in: &cancellables)

        NotificationCenter.default.publisher(for: .qeliWidgetControlRequestAvailable)
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in
                Task { @MainActor [weak self] in
                    await self?.consumePendingWidgetControlRequest()
                }
            }
            .store(in: &cancellables)

        Task { [weak self] in
            guard let self else { return }
            do {
                try await tunnelManager.prepare()
                tunnelSnapshot = tunnelManager.snapshot
                await refreshManagedConfiguration(forceVPNPolicy: true)
                let handledWidgetRequest = await consumePendingWidgetControlRequest()
                if !handledWidgetRequest,
                   settings.autoConnectOnLaunch,
                   !tunnelSnapshot.phase.isActive,
                   let profile = activeProfile {
                    try await tunnelManager.connect(profile: profile, settings: effectiveSettings)
                }
            } catch is CancellationError {
                return
            } catch {
                present(error, title: "VPN configuration")
            }
        }
    }

    var activeProfile: Profile? {
        profiles.first(where: { $0.id == activeProfileID })
    }

    var isTunnelBusy: Bool { tunnelSnapshot.phase.isActive }
    var canSwitchProfile: Bool {
        !isTunnelBusy && !managedConfiguration.hasActiveProfilePolicy
    }
    var effectiveOnDemandEnabled: Bool {
        managedConfiguration.onDemandEnabled ?? settings.onDemandEnabled
    }

    private var effectiveSettings: AppSettings {
        var value = settings
        value.onDemandEnabled = effectiveOnDemandEnabled
        return value
    }

    func toggleConnection() async {
        if isTunnelBusy {
            tunnelManager.disconnect()
            return
        }
        guard let activeProfile else {
            alert = AppAlert(title: "No profile", message: "Create or import a profile first.")
            return
        }
        do {
            let config = try VPNConfig(parsing: activeProfile.configText)
            guard config.serverAddress != "SERVER_IP_OR_HOST" else {
                alert = AppAlert(
                    title: "Set up the profile",
                    message: "Replace SERVER_IP_OR_HOST and the placeholder credentials with your Qeli server settings."
                )
                return
            }
            try await tunnelManager.connect(profile: activeProfile, settings: effectiveSettings)
        } catch is CancellationError {
            return
        } catch {
            present(error, title: "Could not connect")
        }
    }

    @discardableResult
    func consumePendingWidgetControlRequest() async -> Bool {
        guard managedConfiguration.widgetControlsEnabled != false else { return false }
        guard let request = WidgetControlBridge.consumePendingIntent() else { return false }
        await applyWidgetCommand(request.command)
        return true
    }

    @discardableResult
    func handleWidgetControlURL(_ url: URL) async -> Bool {
        guard WidgetControlBridge.isControlURL(url) else { return false }
        if WidgetControlBridge.isStatusURL(url) { return true }
        if let request = WidgetControlBridge.consume(url: url) {
            await applyWidgetCommand(request.command)
        }
        return true
    }

    func selectProfile(_ id: UUID) {
        guard canSwitchProfile else {
            if managedConfiguration.hasActiveProfilePolicy {
                alert = AppAlert(
                    title: "Managed profile",
                    message: "Your organization controls the active VPN profile."
                )
            } else {
                alert = AppAlert(title: "Tunnel active", message: "Disconnect before switching profile.")
            }
            return
        }
        archive.activeProfileID = id
        persistArchive()
    }

    func saveProfile(id: UUID?, name: String, configText: String) throws {
        let previous = archive
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else { throw VPNConfigError.invalid("profile name is empty") }
        let config = try VPNConfig(parsing: configText)
        let normalized = try config.toINI(label: trimmedName)
        if let id, let index = archive.profiles.firstIndex(where: { $0.id == id }) {
            archive.profiles[index].name = trimmedName
            archive.profiles[index].configText = normalized
            archive.profiles[index].modifiedAt = Date()
        } else {
            let profile = Profile(name: trimmedName, configText: normalized)
            archive.profiles.append(profile)
            if canSwitchProfile { archive.activeProfileID = profile.id }
        }
        do { try commitArchive() }
        catch { archive = previous; throw error }
    }

    @discardableResult
    func importProfile(_ rawText: String, suggestedName: String? = nil) throws -> Profile {
        let previous = archive
        let trimmed = rawText.trimmingCharacters(in: .whitespacesAndNewlines)
        let config = try VPNConfig(parsing: trimmed)
        let name = suggestedName?.nonEmpty
            ?? (trimmed.hasPrefix("qeli://") ? VPNConfig.label(fromQeliURI: trimmed) : nil)
            ?? Self.commentLabel(trimmed)
            ?? "profile"
        let profile = Profile(name: name, configText: try config.toINI(label: name))
        archive.profiles.append(profile)
        if canSwitchProfile { archive.activeProfileID = profile.id }
        do { try commitArchive() }
        catch { archive = previous; throw error }
        return profile
    }

    func importDeepLink() {
        guard let url = pendingDeepLink else { return }
        pendingDeepLink = nil
        do { _ = try importProfile(url.absoluteString) }
        catch { present(error, title: "Invalid qeli:// link") }
    }

    func duplicate(_ id: UUID) {
        guard let index = archive.profiles.firstIndex(where: { $0.id == id }) else { return }
        let source = archive.profiles[index]
        let copy = Profile(name: "\(source.name) (copy)", configText: source.configText)
        archive.profiles.insert(copy, at: index + 1)
        persistArchive()
    }

    func delete(_ id: UUID) {
        guard let index = archive.profiles.firstIndex(where: { $0.id == id }) else { return }
        if id == managedConfiguration.activeProfileID {
            alert = AppAlert(
                title: "Managed profile",
                message: "Remove the managed profile policy before deleting this profile."
            )
            return
        }
        if isTunnelBusy && id == activeProfileID {
            alert = AppAlert(title: "Tunnel active", message: "Disconnect before deleting the active profile.")
            return
        }
        archive.profiles.remove(at: index)
        archive.normalize()
        persistArchive()
    }

    func move(fromOffsets: IndexSet, toOffset: Int) {
        archive.profiles.move(fromOffsets: fromOffsets, toOffset: toOffset)
        persistArchive()
    }

    func updateSettings(_ update: (inout AppSettings) -> Void) {
        let previousEffectiveOnDemand = effectiveOnDemandEnabled
        let previous = settings
        update(&settings)
        settingsStore.save(settings)
        let current = settings
        let currentEffectiveOnDemand = effectiveOnDemandEnabled
        if current.checkForUpdates { maybeCheckForUpdates() }
        Task {
            do {
                if previousEffectiveOnDemand != currentEffectiveOnDemand {
                    try await tunnelManager.updateOnDemand(currentEffectiveOnDemand)
                }
                if previous.allowLAN != current.allowLAN,
                   tunnelManager.systemStatus == .connected {
                    try await tunnelManager.reloadProviderSettings()
                }
            } catch {
                present(error, title: "VPN settings")
            }
        }
    }

    func ping(_ profile: Profile) {
        reachability[profile.id] = .checking
        Task {
            do {
                let config = try VPNConfig(parsing: profile.configText)
                guard !config.isUDP else {
                    reachability[profile.id] = .unavailable("protocol probe pending")
                    return
                }
                let milliseconds = try await ReachabilityProbe.tcp(
                    host: config.serverAddress,
                    port: config.port,
                    timeout: 4
                )
                reachability[profile.id] = .reachable(milliseconds: milliseconds)
            } catch {
                reachability[profile.id] = .unavailable(error.localizedDescription)
            }
        }
    }

    func pingAll() { profiles.forEach(ping) }

    func clearLog() {
        sharedTunnelStore.clearLog()
        logLines = []
    }

    func refreshLog() { logLines = sharedTunnelStore.logLines() }

    func checkForUpdates() {
        guard hasPrivateUpdatePath else {
            alert = AppAlert(
                title: "Private tunnel required",
                message: "Update checks require a connected full-tunnel profile with IPv6 leak protection and no custom excluded routes."
            )
            return
        }
        runUpdateCheck(notifyWhenAvailable: false)
    }

    func makeBackup(passphrase: String) async throws -> Data {
        let json = try profileStore.exportJSON(archive)
        guard !passphrase.isEmpty else { return json }
        return try await Task.detached(priority: .userInitiated) {
            try BackupCrypto.encrypt(json, passphrase: passphrase)
        }.value
    }

    func decodeBackup(_ data: Data, passphrase: String) async throws -> ProfileArchive {
        let plaintext: Data
        if BackupCrypto.isEncrypted(data) {
            plaintext = try await Task.detached(priority: .userInitiated) {
                try BackupCrypto.decrypt(data, passphrase: passphrase)
            }.value
        } else {
            plaintext = data
        }
        return try profileStore.importJSON(plaintext)
    }

    func replaceProfiles(with archive: ProfileArchive) {
        guard !isTunnelBusy else {
            alert = AppAlert(title: "Tunnel active", message: "Disconnect before restoring profiles.")
            return
        }
        self.archive = archive
        persistArchive()
        reachability.removeAll()
    }

    func present(_ error: Error, title: String) {
        alert = AppAlert(title: title, message: error.localizedDescription)
    }

    private func commitArchive() throws {
        try profileStore.save(archive)
        profiles = archive.profiles
        synchronizeActiveProfile()
        if managedConfiguration.hasActiveProfilePolicy {
            Task { [weak self] in
                await self?.refreshManagedConfiguration(forceVPNPolicy: true)
            }
        }
    }

    private func applyWidgetCommand(_ command: QeliConnectionCommand) async {
        guard managedConfiguration.widgetControlsEnabled != false else { return }
        do {
            // Reconcile the persisted snapshot with the system VPN status before
            // applying a desired state. This also makes a cold-launch disconnect
            // operate on the loaded NETunnelProviderManager instead of a nil one.
            try await tunnelManager.prepare()
        } catch is CancellationError {
            return
        } catch {
            present(error, title: "VPN configuration")
            return
        }
        tunnelSnapshot = tunnelManager.snapshot

        let systemIsActive: Bool
        switch tunnelManager.systemStatus {
        case .invalid, .disconnected:
            systemIsActive = false
        case .connecting, .connected, .reasserting, .disconnecting:
            systemIsActive = true
        @unknown default:
            systemIsActive = tunnelManager.snapshot.phase.isActive
        }

        switch command {
        case .connect:
            guard !systemIsActive else { return }
            await toggleConnection()
        case .disconnect:
            guard systemIsActive else { return }
            tunnelManager.disconnect()
        }
    }

    func refreshManagedConfiguration(forceVPNPolicy: Bool = false) async {
        let previous = managedConfiguration
        let previousEffectiveOnDemand = effectiveOnDemandEnabled
        let current = ManagedConfigurationReader().load()
        managedConfiguration = current
        synchronizeActiveProfile()
        WidgetControlBridge.setWidgetControlsEnabled(
            current.widgetControlsEnabled ?? true
        )

        let currentEffectiveOnDemand = effectiveOnDemandEnabled
        let managedProfileChanged = previous.hasActiveProfilePolicy != current.hasActiveProfilePolicy
            || previous.activeProfileID != current.activeProfileID
        let shouldApplyProfile = forceVPNPolicy
            ? current.hasActiveProfilePolicy
            : managedProfileChanged
        let shouldApplyOnDemand = forceVPNPolicy
            ? current.onDemandEnabled != nil
            : previousEffectiveOnDemand != currentEffectiveOnDemand
                && (previous.onDemandEnabled != nil || current.onDemandEnabled != nil)
        guard shouldApplyProfile || shouldApplyOnDemand else { return }
        do {
            try await tunnelManager.prepare()
            if shouldApplyProfile {
                let profile: Profile?
                if current.hasActiveProfilePolicy {
                    guard let managedID = current.activeProfileID else {
                        try await tunnelManager.failClosedForManagedProfilePolicy()
                        throw ManagedConfigurationError.profileNotFound(nil)
                    }
                    profile = profiles.first(where: { $0.id == managedID })
                } else {
                    profile = activeProfile
                }
                guard let profile else {
                    if current.hasActiveProfilePolicy {
                        try await tunnelManager.failClosedForManagedProfilePolicy()
                    }
                    throw ManagedConfigurationError.profileNotFound(
                        current.activeProfileID ?? previous.activeProfileID
                    )
                }
                try await tunnelManager.applyProfileConfiguration(
                    profile: profile,
                    settings: effectiveSettings
                )
            } else {
                try await tunnelManager.updateOnDemand(currentEffectiveOnDemand)
            }
        } catch is CancellationError {
        } catch {
            present(error, title: "Managed VPN policy")
        }
    }

    private func synchronizeActiveProfile() {
        if managedConfiguration.hasActiveProfilePolicy {
            activeProfileID = managedConfiguration.activeProfileID.flatMap { managedID in
                archive.profiles.contains(where: { $0.id == managedID }) ? managedID : nil
            }
        } else {
            activeProfileID = archive.activeProfileID
        }
    }

    private func persistArchive() {
        do {
            try commitArchive()
        } catch {
            if let stored = try? profileStore.load() { archive = stored }
            present(error, title: "Could not save profiles")
        }
    }

    private func maybeCheckForUpdates() {
        guard settings.checkForUpdates,
              !automaticUpdateChecked,
              hasPrivateUpdatePath else { return }
        automaticUpdateChecked = true
        runUpdateCheck(notifyWhenAvailable: true)
    }

    private func runUpdateCheck(notifyWhenAvailable: Bool) {
        guard updateCheckState != .checking else { return }
        updateCheckState = .checking
        updateTask?.cancel()
        updateTask = Task { [weak self] in
            guard let self else { return }
            do {
                let info = try await UpdateChecker.check(currentVersion: AppConstants.version)
                if info.isNewer {
                    updateCheckState = .available(info)
                    sharedTunnelStore.appendLog("Update available: \(info.latest)")
                    logLines = sharedTunnelStore.logLines()
                    if notifyWhenAvailable {
                        alert = AppAlert(
                            title: "Update available",
                            message: "Qeli \(info.latest) is available. Open Settings to view the release."
                        )
                    }
                } else {
                    updateCheckState = .current
                }
            } catch is CancellationError {
                updateCheckState = .idle
            } catch {
                updateCheckState = .failed(error.localizedDescription)
            }
            updateTask = nil
        }
    }

    private var hasPrivateUpdatePath: Bool {
        guard tunnelManager.systemStatus == .connected,
              let config = activeProfile?.parsedConfig else { return false }
        return config.isFullTunnel && !config.allowIPv6Leak && config.excludeRoutes.isEmpty
    }

    private static func commentLabel(_ text: String) -> String? {
        guard let line = text.components(separatedBy: .newlines)
            .first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("#") }) else { return nil }
        return String(line.trimmingCharacters(in: .whitespaces).dropFirst())
            .trimmingCharacters(in: .whitespaces)
            .nonEmpty
    }
}

private enum ReachabilityProbe {
    static func tcp(host: String, port: Int, timeout: TimeInterval) async throws -> Int {
        guard let rawPort = UInt16(exactly: port), let networkPort = NWEndpoint.Port(rawValue: rawPort) else {
            throw URLError(.badURL)
        }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: networkPort, using: .tcp)
        let start = DispatchTime.now().uptimeNanoseconds
        return try await withCheckedThrowingContinuation { continuation in
            let gate = ProbeGate()
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    let elapsed = DispatchTime.now().uptimeNanoseconds - start
                    gate.resume {
                        connection.cancel()
                        continuation.resume(returning: Int(elapsed / 1_000_000))
                    }
                case .failed(let error):
                    gate.resume { connection.cancel(); continuation.resume(throwing: error) }
                default:
                    break
                }
            }
            connection.start(queue: DispatchQueue.global(qos: .utility))
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout) {
                gate.resume {
                    connection.cancel()
                    continuation.resume(throwing: URLError(.timedOut))
                }
            }
        }
    }
}

private final class ProbeGate: @unchecked Sendable {
    private let lock = NSLock()
    private var didResume = false

    func resume(_ body: () -> Void) {
        lock.lock()
        guard !didResume else { lock.unlock(); return }
        didResume = true
        lock.unlock()
        body()
    }
}

private enum ManagedConfigurationError: LocalizedError {
    case profileNotFound(UUID?)

    var errorDescription: String? {
        switch self {
        case .profileNotFound(let id):
            let suffix = id.map { " (\($0.uuidString))" } ?? ""
            return "The managed Qeli profile is not present on this device\(suffix)."
        }
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
