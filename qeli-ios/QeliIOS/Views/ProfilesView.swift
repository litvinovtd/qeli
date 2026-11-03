import SwiftUI
import UniformTypeIdentifiers

struct ProfilesView: View {
    @EnvironmentObject private var model: AppModel
    @State private var editingProfile: Profile?
    @State private var creatingProfile = false
    @State private var sharingProfile: Profile?
    @State private var deletingProfile: Profile?
    @State private var showingImportChoices = false
    @State private var showingFileImporter = false
    @State private var showingPaste = false
    @State private var showingScanner = false
    @State private var pastedLink = ""

    var body: some View {
        VStack(spacing: 10) {
            profileActions

            ScrollView {
                LazyVStack(spacing: 8) {
                    ForEach(model.profiles) { profile in
                        profileRow(profile)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 16)
            }
            .overlay {
                if model.profiles.isEmpty {
                    ContentUnavailableView(
                        "No profiles",
                        systemImage: "network.slash",
                        description: Text("Import or create a profile.")
                    )
                }
            }
        }
        .confirmationDialog("Add profile", isPresented: $showingImportChoices, titleVisibility: .visible) {
            Button("Scan QR code") { showingScanner = true }
            Button("Paste qeli:// link") { showingPaste = true }
            Button("Import config file") { showingFileImporter = true }
            Button("Cancel", role: .cancel) {}
        }
        .alert("Paste qeli:// link", isPresented: $showingPaste) {
            TextField("qeli://…", text: $pastedLink)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Import") {
                do { _ = try model.importProfile(pastedLink); pastedLink = "" }
                catch { model.present(error, title: "Invalid link") }
            }
            Button("Cancel", role: .cancel) { pastedLink = "" }
        }
        .confirmationDialog(
            "Delete \(deletingProfile?.name ?? "profile")?",
            isPresented: Binding(get: { deletingProfile != nil }, set: { if !$0 { deletingProfile = nil } }),
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                if let deletingProfile { model.delete(deletingProfile) }
                deletingProfile = nil
            }
            Button("Cancel", role: .cancel) { deletingProfile = nil }
        }
        .sheet(isPresented: $creatingProfile) { ProfileEditorView(profile: nil) }
        .sheet(item: $editingProfile) { profile in ProfileEditorView(profile: profile) }
        .sheet(item: $sharingProfile) { profile in ShareProfileView(profile: profile) }
        .sheet(isPresented: $showingScanner) {
            QRScannerSheet { code in
                showingScanner = false
                do { _ = try model.importProfile(code) }
                catch { model.present(error, title: "Invalid QR code") }
            }
        }
        .fileImporter(
            isPresented: $showingFileImporter,
            allowedContentTypes: [.plainText, .data],
            allowsMultipleSelection: false
        ) { result in
            Task { @MainActor in
                do {
                    guard let url = try result.get().first else { return }
                    let access = url.startAccessingSecurityScopedResource()
                    defer { if access { url.stopAccessingSecurityScopedResource() } }
                    let data = try await Task.detached(priority: .userInitiated) {
                        try ProfileStore.readBounded(
                            from: url,
                            maximumBytes: ProfileStore.maximumConfigBytes
                        )
                    }.value
                    guard let text = String(data: data, encoding: .utf8) else {
                        throw CocoaError(.fileReadInapplicableStringEncoding)
                    }
                    _ = try model.importProfile(
                        text,
                        suggestedName: url.deletingPathExtension().lastPathComponent
                    )
                } catch { model.present(error, title: "Could not import profile") }
            }
        }
    }

    private var profileActions: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 6) {
                importButton
                newProfileButton
                pingAllButton
            }
            VStack(spacing: 6) {
                HStack(spacing: 6) {
                    importButton
                    newProfileButton
                }
                HStack {
                    Spacer()
                    pingAllButton
                }
            }
            VStack(spacing: 6) {
                importButton
                newProfileButton
                pingAllButton.frame(maxWidth: .infinity, alignment: .trailing)
            }
        }
        .padding(.horizontal, 16)
    }

    private var importButton: some View {
        Button("Import") { showingImportChoices = true }
            .buttonStyle(QeliOutlinedActionButtonStyle())
    }

    private var newProfileButton: some View {
        Button("New") { creatingProfile = true }
            .buttonStyle(QeliOutlinedActionButtonStyle())
    }

    private var pingAllButton: some View {
        Button("Ping all") { model.pingAll() }
            .buttonStyle(QeliTextActionButtonStyle())
    }

    private func profileRow(_ profile: Profile) -> some View {
        HStack(spacing: 12) {
            Button { model.selectProfile(profile.id) } label: {
                HStack(spacing: 8) {
                    VStack(spacing: 3) {
                        Circle().fill(reachabilityColor(profile)).frame(width: 10, height: 10)
                        Text(reachabilityCompactText(profile))
                            .font(.system(size: 9))
                            .foregroundStyle(QeliTheme.textSecondary)
                            .lineLimit(1)
                    }
                    .frame(width: 42)
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(profile.name).font(.headline).foregroundStyle(QeliTheme.textPrimary).lineLimit(1)
                            if profile.id == model.activeProfileID {
                                Text("ACTIVE").font(.system(size: 9, weight: .bold)).foregroundStyle(QeliTheme.primary)
                            }
                        }
                        Text(profile.parsedConfig.map { "\($0.serverAddress):\($0.port) · \($0.protocolName.uppercased()) / \($0.wireMode)" } ?? "⚠ invalid config")
                            .font(.caption).foregroundStyle(QeliTheme.textSecondary).lineLimit(1)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            // Switching is refused while the tunnel is up (AppModel.canSwitchProfile). Dim
            // the rows that can't be picked so that reads as unavailable BEFORE the tap,
            // instead of only surfacing as an alert afterwards — same affordance as the
            // Android and desktop clients. Only the selectable area is dimmed: the row's
            // menu (Share / Edit / Duplicate / Delete) stays fully usable while locked.
            .opacity(isSwitchLocked(profile) ? 0.45 : 1)
            Spacer(minLength: 4)
            Menu {
                Button { sharingProfile = profile } label: { Label("Share", systemImage: "square.and.arrow.up") }
                Button { editingProfile = profile } label: { Label("Edit", systemImage: "pencil") }
                Button { model.duplicate(profile.id) } label: { Label("Duplicate", systemImage: "plus.square.on.square") }
                Button { model.ping(profile) } label: { Label("Ping", systemImage: "wave.3.right") }
                Button {} label: { Label("Apps through VPN (MDM only)", systemImage: "building.2") }.disabled(true)
                Button { model.move(profile.id, by: -1) } label: {
                    Label("Move up", systemImage: "arrow.up")
                }
                .disabled(model.profiles.first?.id == profile.id)
                Button { model.move(profile.id, by: 1) } label: {
                    Label("Move down", systemImage: "arrow.down")
                }
                .disabled(model.profiles.last?.id == profile.id)
                Divider()
                Button(role: .destructive) { deletingProfile = profile } label: { Label("Delete", systemImage: "trash") }
            } label: {
                Image(systemName: "ellipsis")
                    .font(.title3.weight(.semibold))
                    .rotationEffect(.degrees(90))
                    .frame(width: 44, height: 44)
            }
            .foregroundStyle(QeliTheme.textSecondary)
            .accessibilityLabel("Profile actions")
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(profile.id == model.activeProfileID ? QeliTheme.primaryContainer : QeliTheme.surface)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(profile.id == model.activeProfileID ? QeliTheme.primary : QeliTheme.outline)
        }
    }

    /// True when this row can't be made active right now — the tunnel is up (or an MDM
    /// policy owns the choice) and the row isn't the one already running.
    private func isSwitchLocked(_ profile: Profile) -> Bool {
        !model.canSwitchProfile && profile.id != model.activeProfileID
    }

    private func reachabilityCompactText(_ profile: Profile) -> String {
        switch model.reachability[profile.id] ?? .idle {
        case .checking: return "…"
        case .reachable(let milliseconds): return "\(milliseconds) ms"
        case .idle, .unavailable: return ""
        }
    }

    private func reachabilityColor(_ profile: Profile) -> Color {
        switch model.reachability[profile.id] ?? .idle {
        case .reachable: return QeliTheme.connected
        case .checking: return QeliTheme.connecting
        case .unavailable: return QeliTheme.error
        case .idle: return .secondary.opacity(0.5)
        }
    }
}
