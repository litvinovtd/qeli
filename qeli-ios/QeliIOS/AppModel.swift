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
    /// English localization key; the view resolves it via `LocalizedStringKey`.
    var title: String
    var message: String
    /// Set when `message` is already-interpolated display text (a version number, a server
    /// error) rather than a key, so the view shows it as-is instead of looking it up.
    var isLiteralMessage = false
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
    private var updateTaskIsAutomatic = false
    private var updateCheckGeneration: UInt64 = 0
    private var updateChecksSuspendedForTunnelTeardown = false
    private var queuedProbes: [Profile] = []
    private var queuedOrActiveProbeIDs = Set<UUID>()
    private var startupSigningInvalid = false
    private var profileStoreLoadRejected = false
    private var activeProbeCount = 0
    private let managedPolicyGate = PreferenceMutationGate()
    private static let maximumConcurrentProbes = 4

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
        let missingSigningRequirements = IOSSigningDiagnostics.missingRequirements()
        if !missingSigningRequirements.isEmpty {
            self.archive = .initial
            self.startupSigningInvalid = true
            self.profileStoreLoadRejected = true
            self.alert = Self.invalidSigningAlert
        } else {
            do {
                self.archive = try profileStore.load(initializeIfMissing: true)
            } catch {
                self.archive = .initial
                self.profileStoreLoadRejected = true
                if (error as? KeychainError)?.isMissingEntitlement == true {
                    self.startupSigningInvalid = true
                    self.alert = Self.invalidSigningAlert
                } else {
                    self.alert = AppAlert(title: "Profile store error", message: error.localizedDescription,
                                          isLiteralMessage: true)
                }
            }
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
                guard let self else { return }
                let previousPhase = tunnelSnapshot.phase
                tunnelSnapshot = value
                logLines = sharedTunnelStore.logLines()
                if previousPhase != value.phase {
                    WidgetCenter.shared.reloadTimelines(ofKind: AppConstants.statusWidgetKind)
                    if #available(iOS 18.0, *) {
                        ControlCenter.shared.reloadControls(ofKind: AppConstants.connectionControlKind)
                    }
                }
                if !hasPrivateUpdatePath,
                   (updateTask != nil || updateCheckState == .checking) {
                    // Unexpected provider loss cannot be awaited here, but cancellation is
                    // still delivered immediately. Code-driven stops use the awaited barrier
                    // in cancelUpdateCheckBeforeTunnelTeardown() below.
                    _ = cancelUpdateCheck(resetAutomatic: true)
                }
                maybeCheckForUpdates()
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
            guard !startupSigningInvalid else { return }
            do {
                try await tunnelManager.prepare()
                tunnelSnapshot = tunnelManager.snapshot
                await refreshManagedConfiguration(forceVPNPolicy: true)
                let handledWidgetRequest = await consumePendingWidgetControlRequest()
                if !handledWidgetRequest,
                   settings.autoConnectOnLaunch,
                   !tunnelSnapshot.phase.isActive,
                   let profile = activeProfile {
                    setConnectionDesired(true)
                    try await tunnelManager.connect(profile: profile, settings: effectiveSettings)
                }
            } catch is CancellationError {
                return
            } catch {
                present(error, title: "VPN configuration")
            }
        }
    }

    private static var invalidSigningAlert: AppAlert {
        AppAlert(
            title: "Invalid iOS signing",
            message: "This copy of Qeli is missing the Apple VPN, App Group or Keychain entitlements. Install a correctly signed build from TestFlight, the App Store, or an authorized Apple Developer team."
        )
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
        // An explicit managed "On Demand = enabled" remains authoritative. Outside MDM,
        // manual Disconnect clears the device-local desired bit and cancels auto-resume.
        if managedConfiguration.onDemandEnabled == true { value.connectionDesired = true }
        return value
    }

    func toggleConnection() async {
        if isTunnelBusy {
            await disconnectManually()
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
            setConnectionDesired(true)
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
        let previous = archive
        archive.activeProfileID = id
        persistArchive(rollbackTo: previous)
    }

    /// Returns whether a running tunnel still uses the previous active configuration.
    @discardableResult
    func saveProfile(original: Profile?, name: String, configText: String) throws -> Bool {
        let previous = archive
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else { throw VPNConfigError.invalid("profile name is empty") }
        let config = try VPNConfig(parsing: configText)
        let normalized = try config.toINI(label: trimmedName)
        var reconnectRequired = false
        if let original {
            guard let index = archive.profiles.firstIndex(where: { $0.id == original.id }),
                  archive.profiles[index] == original else {
                throw ProfileStoreError.staleProfile
            }
            reconnectRequired = (
                isTunnelBusy && original.id == activeProfileID &&
                archive.profiles[index].configText != normalized
            )
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
        return reconnectRequired
    }

    @discardableResult
    func importProfile(_ rawText: String, suggestedName: String? = nil) throws -> Profile {
        let previous = archive
        let trimmed = rawText.trimmingCharacters(in: .whitespacesAndNewlines)
        let config = try VPNConfig(parsing: rawText)
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
        let previous = archive
        let source = archive.profiles[index]
        let copy = Profile(name: "\(source.name) (copy)", configText: source.configText)
        archive.profiles.insert(copy, at: index + 1)
        do { try commitArchive() }
        catch {
            archive = previous
            present(error, title: "Could not duplicate profile")
        }
    }

    func delete(_ original: Profile) {
        guard let index = archive.profiles.firstIndex(where: { $0.id == original.id }),
              archive.profiles[index] == original else {
            alert = AppAlert(
                title: "Profile changed",
                message: "Profile changed while the dialog was open. Reopen it before deleting."
            )
            return
        }
        if original.id == managedConfiguration.activeProfileID {
            alert = AppAlert(
                title: "Managed profile",
                message: "Remove the managed profile policy before deleting this profile."
            )
            return
        }
        if isTunnelBusy && original.id == activeProfileID {
            alert = AppAlert(title: "Tunnel active", message: "Disconnect before deleting the active profile.")
            return
        }
        let previous = archive
        archive.profiles.remove(at: index)
        archive.normalize()
        persistArchive(rollbackTo: previous)
    }

    func move(fromOffsets: IndexSet, toOffset: Int) {
        let previous = archive
        archive.profiles.move(fromOffsets: fromOffsets, toOffset: toOffset)
        persistArchive(rollbackTo: previous)
    }

    func move(_ id: UUID, by offset: Int) {
        guard abs(offset) == 1,
              let source = archive.profiles.firstIndex(where: { $0.id == id }) else { return }
        let destination = source + offset
        guard archive.profiles.indices.contains(destination) else { return }
        let previous = archive
        archive.profiles.swapAt(source, destination)
        persistArchive(rollbackTo: previous)
    }

    func updateSettings(_ update: (inout AppSettings) -> Void) {
        let previousEffectiveSettings = effectiveSettings
        let previous = settings
        update(&settings)
        settings.trustedWiFiSSIDs = TrustedWiFiPolicy.normalized(settings.trustedWiFiSSIDs)
        settingsStore.save(settings)
        let current = settings
        let currentEffectiveSettings = effectiveSettings
        let onDemandPolicyChanged = Self.onDemandPolicyChanged(
            previousEffectiveSettings,
            currentEffectiveSettings
        )
        // Reserve while still in the synchronous UI mutation. Two rapidly-created Tasks
        // are not guaranteed to begin in creation order; the revision makes the latest
        // settings event authoritative even if an older Task reaches NetworkExtension last.
        let onDemandRevision = onDemandPolicyChanged
            ? tunnelManager.reserveOnDemandUpdate()
            : nil
        if current.checkForUpdates {
            maybeCheckForUpdates()
        } else {
            // Turning the opt-in off revokes an in-flight automatic or manual request too.
            _ = cancelUpdateCheck(resetAutomatic: true)
        }
        Task {
            if let onDemandRevision {
                do {
                    try await tunnelManager.updateOnDemand(
                        settings: currentEffectiveSettings,
                        revision: onDemandRevision
                    )
                } catch is CancellationError {
                    // A newer UI edit reserved the authoritative revision.
                } catch {
                    present(error, title: "VPN settings")
                }
            }
            do {
                if previous.allowLAN != current.allowLAN,
                   tunnelManager.systemStatus == .connected {
                    try await tunnelManager.reloadProviderSettings()
                }
            } catch is CancellationError {
            } catch {
                present(error, title: "VPN settings")
            }
        }
    }

    private static func onDemandPolicyChanged(_ previous: AppSettings, _ current: AppSettings) -> Bool {
        previous.onDemandEnabled != current.onDemandEnabled
            || previous.connectionDesired != current.connectionDesired
            || previous.trustedWiFiEnabled != current.trustedWiFiEnabled
            || previous.trustedWiFiSSIDs != current.trustedWiFiSSIDs
    }

    private func setConnectionDesired(_ desired: Bool) {
        guard settings.connectionDesired != desired else { return }
        settings.connectionDesired = desired
        settingsStore.save(settings)
    }

    /// Disable On Demand before stopping the live tunnel. Reversing this order allows iOS to
    /// reconnect between the stop and the preference write, which defeats a manual Disconnect.
    private func disconnectManually() async {
        let previousDesired = settings.connectionDesired
        setConnectionDesired(false)
        while !effectiveSettings.connectionDesired {
            let onDemandRevision = tunnelManager.reserveOnDemandUpdate()
            do {
                try await tunnelManager.updateOnDemand(
                    settings: effectiveSettings,
                    revision: onDemandRevision
                )
                guard !effectiveSettings.connectionDesired else { return }
                // URLSession is not bindable to a specific iOS packet-tunnel interface.
                // Wait until its cancellation has completed before removing that interface,
                // so DNS/connect cannot be retried on the physical default route.
                await cancelUpdateCheckBeforeTunnelTeardown()
                tunnelManager.disconnect()
                return
            } catch is CancellationError {
                if Task.isCancelled { return }
                // A concurrent settings edit also captured connectionDesired=false. Retry
                // its latest policy instead of restoring true and diverging from the rules
                // that newer task is about to persist. An explicit Connect flips the bit and
                // exits the loop without stopping its new generation.
                continue
            } catch {
                // The system preference still contains the previous rules, so keep our persisted
                // intent consistent and leave the live tunnel up instead of pretending it stopped.
                setConnectionDesired(previousDesired)
                present(error, title: "VPN settings")
                return
            }
        }
    }

    func ping(_ profile: Profile) {
        guard profiles.contains(where: { $0.id == profile.id && $0.configText == profile.configText }),
              queuedOrActiveProbeIDs.insert(profile.id).inserted else { return }
        reachability[profile.id] = .checking
        queuedProbes.append(profile)
        startQueuedProbes()
    }

    private func startQueuedProbes() {
        while activeProbeCount < Self.maximumConcurrentProbes, !queuedProbes.isEmpty {
            let profile = queuedProbes.removeFirst()
            activeProbeCount += 1
            Task { [weak self] in
                guard let self else { return }
                await runProbe(profile)
                activeProbeCount -= 1
                queuedOrActiveProbeIDs.remove(profile.id)
                startQueuedProbes()
            }
        }
    }

    private func runProbe(_ profile: Profile) async {
        let result: ReachabilityState
        do {
            let config = try VPNConfig(parsing: profile.configText)
            // While THIS profile's tunnel is up, dialing the public endpoint measures a
            // looped-back path (or is carried by the tunnel it is probing) and reports a
            // meaningless RTT. Probe the tunnel gateway instead, like Android does.
            let viaTunnel = tunnelSnapshot.phase.isActive && profile.id == activeProfileID
            let host = viaTunnel
                ? (tunnelSnapshot.tunnelGateway ?? config.serverAddress)
                : config.serverAddress
            let milliseconds: Int
            if config.isUDP {
                // The native probe parses its target from the profile. When this is the
                // active tunnel, replace only that target with the in-tunnel gateway;
                // probing the public UDP endpoint through itself is meaningless, while
                // falling through to a TCP connect marks every UDP-only listener down.
                let profileText: String
                if viaTunnel {
                    // Keep identity/SNI/REALITY credentials unchanged and replace only the
                    // validated network endpoint used by the handle-free UDP probe.
                    var probeConfig = config
                    probeConfig.serverAddress = host
                    profileText = try probeConfig.toTransportCoreINI()
                } else {
                    profileText = profile.configText
                }
                milliseconds = try await Task.detached(priority: .utility) {
                    Int(try QeliNativeCore.udpProbe(
                        config: profileText,
                        timeoutMilliseconds: 2_000
                    ))
                }.value
            } else {
                milliseconds = try await ReachabilityProbe.tcp(
                    host: host,
                    port: config.port,
                    timeout: 4
                )
            }
            result = .reachable(milliseconds: milliseconds)
        } catch {
            result = .unavailable(error.localizedDescription)
        }
        guard !Task.isCancelled,
              profiles.contains(where: { $0.id == profile.id && $0.configText == profile.configText }) else { return }
        reachability[profile.id] = result
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
                message: "Update checks require a connected full-tunnel profile with IPv4/IPv6 leak protection, no LAN bypass and no custom excluded routes."
            )
            return
        }
        runUpdateCheck(notifyWhenAvailable: false, automatic: false)
    }

    func makeBackup(passphrase: String) async throws -> Data {
        guard !profileStoreLoadRejected else {
            throw ProfileStoreError.unavailableAfterLoadFailure
        }
        let archiveSnapshot = archive
        let store = profileStore
        let json = try await Task.detached(priority: .userInitiated) {
            try store.exportJSON(archiveSnapshot)
        }.value
        guard !passphrase.isEmpty else { return json }
        let encrypted = try await Task.detached(priority: .userInitiated) {
            try BackupCrypto.encrypt(json, passphrase: passphrase)
        }.value
        guard encrypted.count <= ProfileStore.maximumBackupFileBytes else {
            throw ProfileStoreError.archiveTooLarge
        }
        return encrypted
    }

    func decodeBackup(_ data: Data, passphrase: String) async throws -> ProfileArchive {
        guard data.count <= ProfileStore.maximumBackupFileBytes else {
            throw ProfileStoreError.archiveTooLarge
        }
        let plaintext: Data
        if BackupCrypto.isEncrypted(data) {
            plaintext = try await Task.detached(priority: .userInitiated) {
                try BackupCrypto.decrypt(data, passphrase: passphrase)
            }.value
        } else {
            plaintext = data
        }
        let store = profileStore
        return try await Task.detached(priority: .userInitiated) {
            try store.importJSON(plaintext)
        }.value
    }

    func replaceProfiles(with archive: ProfileArchive) {
        guard !isTunnelBusy else {
            alert = AppAlert(title: "Tunnel active", message: "Disconnect before restoring profiles.")
            return
        }
        let previous = self.archive
        self.archive = archive
        if persistArchive(rollbackTo: previous, replacingUnreadableStore: true) {
            reachability.removeAll()
        }
    }

    /// Resolve a localization key in the *selected* UI language.
    ///
    /// Views get this for free from `\.locale`, but that environment value doesn't reach
    /// model code, so anything built here (alerts, formatted messages) has to look the
    /// string up in the right `.lproj` explicitly.
    func localized(_ key: String) -> String {
        guard let path = Bundle.main.path(forResource: settings.language.rawValue, ofType: "lproj"),
              let bundle = Bundle(path: path) else {
            return NSLocalizedString(key, comment: "")
        }
        return NSLocalizedString(key, bundle: bundle, comment: "")
    }

    func present(_ error: Error, title: String) {
        // localizedDescription is system/server text, not one of our keys.
        alert = AppAlert(title: title, message: error.localizedDescription, isLiteralMessage: true)
    }

    private func commitArchive(replacingUnreadableStore: Bool = false) throws {
        guard !profileStoreLoadRejected || replacingUnreadableStore else {
            throw ProfileStoreError.unavailableAfterLoadFailure
        }
        try profileStore.save(archive)
        profileStoreLoadRejected = false
        let previousConfigs = Dictionary(uniqueKeysWithValues: profiles.map { ($0.id, $0.configText) })
        profiles = archive.profiles
        let currentConfigs = Dictionary(uniqueKeysWithValues: profiles.map { ($0.id, $0.configText) })
        for id in Array(reachability.keys) where currentConfigs[id] == nil || currentConfigs[id] != previousConfigs[id] {
            reachability.removeValue(forKey: id)
        }
        // Remove only queued IDs; an active native probe keeps its slot until its bounded
        // call returns, so a replacement cannot exceed the four-worker limit.
        let obsolete = queuedProbes.filter { currentConfigs[$0.id] != $0.configText }
        queuedProbes.removeAll { currentConfigs[$0.id] != $0.configText }
        for profile in obsolete { queuedOrActiveProbeIDs.remove(profile.id) }
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
            systemIsActive = tunnelManager.snapshot.phase.isActive
        case .connecting, .connected, .reasserting, .disconnecting:
            systemIsActive = true
        @unknown default:
            systemIsActive = tunnelManager.snapshot.phase.isActive
        }

        switch command {
        case .toggle:
            // Resolve a toggle only after prepare() refreshed the real NEVPNStatus.
            // App Group snapshots are display caches and may survive a provider crash.
            if systemIsActive {
                await disconnectManually()
            } else {
                await toggleConnection()
            }
        case .connect:
            if !systemIsActive {
                await toggleConnection()
                return
            }
            // The Widget request is a desired-state command, not merely a request to flip
            // the current NEVPNStatus. Reconcile the durable bit and On-Demand rules even
            // when an older widget build already started the session directly.
            let previousDesired = settings.connectionDesired
            setConnectionDesired(true)
            let onDemandRevision = tunnelManager.reserveOnDemandUpdate()
            do {
                try await tunnelManager.updateOnDemand(
                    settings: effectiveSettings,
                    revision: onDemandRevision
                )
            } catch is CancellationError {
                return
            } catch {
                setConnectionDesired(previousDesired)
                present(error, title: "VPN settings")
            }
        case .disconnect:
            // Always persist connectionDesired=false and disable On Demand before stop.
            // Skipping an already-disconnected session left the automatic policy armed.
            await disconnectManually()
        }
    }

    func refreshManagedConfiguration(forceVPNPolicy: Bool = false) async {
        do {
            try await managedPolicyGate.withLock {
                // Load MDM inside the serialized transaction. Loading before the wait
                // would allow an older captured policy to overwrite a newer refresh.
                await reconcileManagedConfiguration(forceVPNPolicy: forceVPNPolicy)
            }
        } catch is CancellationError {
        } catch {
            present(error, title: "Managed VPN policy")
        }
    }

    private func reconcileManagedConfiguration(forceVPNPolicy: Bool) async {
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
                        try await failClosedForManagedProfilePolicy()
                        throw ManagedConfigurationError.profileNotFound(nil)
                    }
                    profile = profiles.first(where: { $0.id == managedID })
                } else {
                    profile = activeProfile
                }
                guard let profile else {
                    if current.hasActiveProfilePolicy {
                        try await failClosedForManagedProfilePolicy()
                    }
                    throw ManagedConfigurationError.profileNotFound(
                        current.activeProfileID ?? previous.activeProfileID
                    )
                }
                try await tunnelManager.applyProfileConfiguration(
                    profile: profile,
                    settings: { self.effectiveSettings }
                )
            } else {
                let onDemandRevision = tunnelManager.reserveOnDemandUpdate()
                try await tunnelManager.updateOnDemand(
                    settings: effectiveSettings,
                    revision: onDemandRevision
                )
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

    @discardableResult
    private func persistArchive(
        rollbackTo previous: ProfileArchive,
        replacingUnreadableStore: Bool = false
    ) -> Bool {
        do {
            try commitArchive(replacingUnreadableStore: replacingUnreadableStore)
            return true
        } catch {
            // Roll back from the in-memory snapshot first. Reloading the store can fail for the
            // same reason as the save; relying on that second I/O operation left `archive`
            // mutated while the published profile list still described the old state.
            archive = (try? profileStore.load()) ?? previous
            profiles = archive.profiles
            synchronizeActiveProfile()
            present(error, title: "Could not save profiles")
            return false
        }
    }

    private func maybeCheckForUpdates() {
        guard settings.checkForUpdates,
              !automaticUpdateChecked,
              updateCheckState != .checking,
              hasPrivateUpdatePath else { return }
        automaticUpdateChecked = true
        runUpdateCheck(notifyWhenAvailable: true, automatic: true)
    }

    /// Invalidate the current request synchronously and return its Task so callers that are
    /// about to remove the packet tunnel can wait for URLSession cancellation to finish.
    @discardableResult
    private func cancelUpdateCheck(resetAutomatic: Bool) -> Task<Void, Never>? {
        if resetAutomatic { automaticUpdateChecked = false }
        guard updateTask != nil || updateCheckState == .checking else { return nil }
        let task = updateTask
        updateCheckGeneration &+= 1
        task?.cancel()
        updateTask = nil
        updateTaskIsAutomatic = false
        updateCheckState = .idle
        return task
    }

    private func cancelUpdateCheckBeforeTunnelTeardown() async {
        let task = cancelUpdateCheck(resetAutomatic: true)
        await task?.value
    }

    /// Keep update checks suppressed across every suspension point in the managed
    /// fail-closed transaction. `prepare()`/preference reloads may publish an intermediate
    /// connected snapshot; without this guard that publication could start a fresh automatic
    /// request after the cancellation barrier but before NetworkExtension removes the tunnel.
    private func failClosedForManagedProfilePolicy() async throws {
        updateChecksSuspendedForTunnelTeardown = true
        defer { updateChecksSuspendedForTunnelTeardown = false }
        await cancelUpdateCheckBeforeTunnelTeardown()
        try await tunnelManager.failClosedForManagedProfilePolicy()
    }

    private func runUpdateCheck(notifyWhenAvailable: Bool, automatic: Bool) {
        guard updateCheckState != .checking else { return }
        updateCheckState = .checking
        updateTask?.cancel()
        updateCheckGeneration &+= 1
        let generation = updateCheckGeneration
        updateTaskIsAutomatic = automatic
        updateTask = Task { [weak self] in
            guard let self else { return }
            defer {
                // An invalidated request must never clear or relabel a newer generation.
                if updateCheckGeneration == generation {
                    updateTask = nil
                    updateTaskIsAutomatic = false
                }
            }
            do {
                let info = try await UpdateChecker.check(currentVersion: AppConstants.version)
                guard updateCheckGeneration == generation else { return }
                if !automatic && settings.checkForUpdates {
                    // A completed manual check already satisfies the opt-in once-per-launch
                    // policy; do not immediately repeat the same request automatically.
                    automaticUpdateChecked = true
                }
                if info.isNewer {
                    updateCheckState = .available(info)
                    sharedTunnelStore.appendLog("Update available: \(info.latest)")
                    logLines = sharedTunnelStore.logLines()
                    if notifyWhenAvailable {
                        alert = AppAlert(
                            title: "Update available",
                            message: String(
                                format: localized("Qeli %@ is available. Open Settings to view the release."),
                                info.latest
                            ),
                            isLiteralMessage: true
                        )
                    }
                } else {
                    updateCheckState = .current
                }
            } catch is CancellationError {
                if updateCheckGeneration == generation {
                    updateCheckState = .idle
                    if automatic { automaticUpdateChecked = false }
                }
            } catch {
                if updateCheckGeneration == generation {
                    if !automatic && settings.checkForUpdates {
                        automaticUpdateChecked = true
                    }
                    updateCheckState = .failed(error.localizedDescription)
                }
            }
        }
    }

    private var hasPrivateUpdatePath: Bool {
        guard !updateChecksSuspendedForTunnelTeardown,
              tunnelManager.systemStatus == .connected,
              tunnelSnapshot.phase == .connected else { return false }
        // Profiles can be edited while their previous config is still active. The provider
        // publishes this from the immutable config it actually loaded, so never re-derive the
        // decision from the current contents of the profile editor.
        return tunnelSnapshot.privateUpdatePath == true
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
        let completion = CancellableProbeCompletion<Int> {
            connection.stateUpdateHandler = nil
            connection.cancel()
        }
        let outcome = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                completion.park(continuation)
                completion.start {
                    connection.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            let elapsed = DispatchTime.now().uptimeNanoseconds - start
                            completion.finish(.success(Int(elapsed / 1_000_000)))
                        case .failed(let error):
                            completion.finish(.failure(error))
                        case .cancelled:
                            completion.finish(.failure(CancellationError()))
                        default:
                            break
                        }
                    }
                    connection.start(queue: DispatchQueue.global(qos: .utility))
                    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout) {
                        completion.finish(.failure(URLError(.timedOut)))
                    }
                }
            }
        } onCancel: {
            completion.finish(.failure(CancellationError()))
        }
        try Task.checkCancellation()
        return try outcome.get()
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
