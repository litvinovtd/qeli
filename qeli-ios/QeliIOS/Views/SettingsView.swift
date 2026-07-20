import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var passphrase = ""
    @State private var backupDocument: BackupDocument?
    @State private var showingExporter = false
    @State private var showingImporter = false
    @State private var pendingRestore: ProfileArchive?
    @State private var preparingBackup = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Connection") {
                    Toggle("Auto-connect on app launch", isOn: setting(\.autoConnectOnLaunch))
                    Toggle(
                        "Connect On Demand",
                        isOn: Binding(
                            get: { model.effectiveOnDemandEnabled },
                            set: { enabled in
                                model.updateSettings { $0.onDemandEnabled = enabled }
                            }
                        )
                    )
                    .disabled(model.managedConfiguration.onDemandEnabled != nil)
                    Toggle("Allow local network access (LAN)", isOn: setting(\.allowLAN))
                    Text("Connect On Demand is the iOS equivalent of boot auto-connect. True Always-On VPN requires a supervised MDM device.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Managed deployment") {
                    LabeledContent("Managed app configuration", value: managedConfiguration.isManaged ? "Detected" : "Not installed")
                    if let profileID = managedConfiguration.activeProfileID {
                        LabeledContent("Managed profile", value: profileID.uuidString)
                            .font(.caption)
                    } else if managedConfiguration.hasActiveProfilePolicy {
                        LabeledContent("Managed profile", value: "Invalid policy")
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                    if let enabled = managedConfiguration.onDemandEnabled {
                        LabeledContent("Managed On Demand", value: enabled ? "Enabled" : "Disabled")
                    }
                    if let enabled = managedConfiguration.widgetControlsEnabled {
                        LabeledContent("Managed widget controls", value: enabled ? "Enabled" : "Disabled")
                    }
                    Text("Per-App VPN is assigned by MDM to managed apps. Apple's strict Always-On enforcement is supervised-device IKEv2 and cannot run the Qeli custom packet protocol.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Section("Appearance") {
                    Picker("Theme", selection: setting(\.appearance)) {
                        ForEach(AppAppearance.allCases) { appearance in Text(appearance.title).tag(appearance) }
                    }
                    Picker("Log timestamp", selection: setting(\.logTimeFormat)) {
                        ForEach(LogTimeFormat.allCases) { format in Text(format.title).tag(format) }
                    }
                }
                Section("Backup and restore") {
                    SecureField("Passphrase (optional for export)", text: $passphrase)
                    Button {
                        preparingBackup = true
                        Task {
                            defer { preparingBackup = false }
                            do {
                                backupDocument = BackupDocument(data: try await model.makeBackup(passphrase: passphrase))
                                showingExporter = true
                            } catch { model.present(error, title: "Backup failed") }
                        }
                    } label: {
                        Label(preparingBackup ? "Preparing…" : "Back up profiles…", systemImage: "square.and.arrow.up")
                    }
                    .disabled(preparingBackup)
                    Button { showingImporter = true } label: {
                        Label("Restore profiles…", systemImage: "square.and.arrow.down")
                    }
                    Text("An empty export passphrase creates Android-compatible plaintext JSON. A passphrase uses QELI-ENC-1 encryption compatible with Android.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("About") {
                    LabeledContent("Version", value: "\(AppConstants.version) (\(AppConstants.build))")
                    Toggle("Check for updates automatically", isOn: setting(\.checkForUpdates))
                    Button("Check now") { model.checkForUpdates() }
                        .disabled(model.updateCheckState == .checking)
                    updateStatus
                    Link("Project releases", destination: URL(string: "https://github.com/litvinovtd/qeli/releases")!)
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
        .fileExporter(
            isPresented: $showingExporter,
            document: backupDocument,
            contentType: .data,
            defaultFilename: passphrase.isEmpty ? "qeli-profiles.json" : "qeli-profiles.qeli-backup"
        ) { result in
            if case .failure(let error) = result { model.present(error, title: "Backup failed") }
            backupDocument = nil
        }
        .fileImporter(
            isPresented: $showingImporter,
            allowedContentTypes: [.json, .plainText, .data],
            allowsMultipleSelection: false
        ) { result in
            Task {
                do {
                    guard let url = try result.get().first else { return }
                    let access = url.startAccessingSecurityScopedResource()
                    defer { if access { url.stopAccessingSecurityScopedResource() } }
                    let data = try Data(contentsOf: url)
                    pendingRestore = try await model.decodeBackup(data, passphrase: passphrase)
                } catch { model.present(error, title: "Restore failed") }
            }
        }
        .confirmationDialog(
            "Replace all current profiles?",
            isPresented: Binding(get: { pendingRestore != nil }, set: { if !$0 { pendingRestore = nil } }),
            titleVisibility: .visible
        ) {
            Button("Restore \(pendingRestore?.profiles.count ?? 0) profiles", role: .destructive) {
                if let pendingRestore { model.replaceProfiles(with: pendingRestore) }
                pendingRestore = nil
            }
            Button("Cancel", role: .cancel) { pendingRestore = nil }
        } message: {
            Text("This replaces the current encrypted profile set.")
        }
    }

    private func setting<Value>(_ keyPath: WritableKeyPath<AppSettings, Value>) -> Binding<Value> {
        Binding(
            get: { model.settings[keyPath: keyPath] },
            set: { value in model.updateSettings { $0[keyPath: keyPath] = value } }
        )
    }

    private var managedConfiguration: QeliManagedConfiguration {
        model.managedConfiguration
    }

    @ViewBuilder
    private var updateStatus: some View {
        switch model.updateCheckState {
        case .idle:
            EmptyView()
        case .checking:
            Label("Checking…", systemImage: "arrow.triangle.2.circlepath")
                .foregroundStyle(.secondary)
        case .current:
            Label("You have the latest version", systemImage: "checkmark.circle.fill")
                .foregroundStyle(QeliTheme.connected)
        case .available(let info):
            Link(destination: info.url) {
                Label("Qeli \(info.latest) is available", systemImage: "arrow.down.circle.fill")
            }
        case .failed(let message):
            Label(message, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(QeliTheme.error)
        }
    }
}

struct BackupDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data, .json, .plainText] }
    var data: Data

    init(data: Data) { self.data = data }

    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}
