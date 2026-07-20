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
            HStack {
                Button { showingImportChoices = true } label: { Label("Import", systemImage: "square.and.arrow.down") }
                    .buttonStyle(.bordered)
                Button { creatingProfile = true } label: { Label("New", systemImage: "plus") }
                    .buttonStyle(.borderedProminent).tint(QeliTheme.primary)
                Spacer()
                Button { model.pingAll() } label: { Label("Ping all", systemImage: "wave.3.right") }
                    .buttonStyle(.bordered)
                EditButton()
            }
            .padding(.horizontal, 16)

            List {
                ForEach(model.profiles) { profile in
                    profileRow(profile)
                        .listRowBackground(QeliTheme.surface)
                        .listRowSeparator(.hidden)
                        .listRowInsets(EdgeInsets(top: 5, leading: 16, bottom: 5, trailing: 16))
                }
                .onMove(perform: model.move)
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .overlay {
                if model.profiles.isEmpty {
                    ContentUnavailableView("No profiles", systemImage: "network.slash", description: Text("Import or create a profile."))
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
                if let deletingProfile { model.delete(deletingProfile.id) }
                deletingProfile = nil
            }
            Button("Cancel", role: .cancel) { deletingProfile = nil }
        }
        .sheet(isPresented: $creatingProfile) { ProfileEditorView(profile: nil) }
        .sheet(item: $editingProfile) { profile in ProfileEditorView(profile: profile) }
        .sheet(item: $sharingProfile) { profile in ShareProfileView(profile: profile) }
        .sheet(isPresented: $showingScanner) {
            NavigationStack {
                QRScannerView { code in
                    showingScanner = false
                    do { _ = try model.importProfile(code) }
                    catch { model.present(error, title: "Invalid QR code") }
                }
                .navigationTitle("Scan profile")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { showingScanner = false } } }
            }
        }
        .fileImporter(
            isPresented: $showingFileImporter,
            allowedContentTypes: [.plainText, .json, .data],
            allowsMultipleSelection: false
        ) { result in
            do {
                guard let url = try result.get().first else { return }
                let access = url.startAccessingSecurityScopedResource()
                defer { if access { url.stopAccessingSecurityScopedResource() } }
                let data = try Data(contentsOf: url)
                guard let text = String(data: data, encoding: .utf8) else { throw CocoaError(.fileReadInapplicableStringEncoding) }
                _ = try model.importProfile(text, suggestedName: url.deletingPathExtension().lastPathComponent)
            } catch { model.present(error, title: "Could not import profile") }
        }
    }

    private func profileRow(_ profile: Profile) -> some View {
        HStack(spacing: 12) {
            Button { model.selectProfile(profile.id) } label: {
                HStack(spacing: 12) {
                    Circle().fill(reachabilityColor(profile)).frame(width: 10, height: 10)
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(profile.name).font(.headline).foregroundStyle(.primary).lineLimit(1)
                            if profile.id == model.activeProfileID {
                                Text("ACTIVE").font(.system(size: 9, weight: .bold)).foregroundStyle(QeliTheme.primary)
                            }
                        }
                        Text(profile.parsedConfig.map { "\($0.serverAddress):\($0.port) · \($0.protocolName.uppercased()) / \($0.wireMode)" } ?? "⚠ invalid config")
                            .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        Text(reachabilityText(profile)).font(.caption2).foregroundStyle(.secondary)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            Spacer(minLength: 4)
            Menu {
                Button { sharingProfile = profile } label: { Label("Share", systemImage: "square.and.arrow.up") }
                Button { editingProfile = profile } label: { Label("Edit", systemImage: "pencil") }
                Button { model.duplicate(profile.id) } label: { Label("Duplicate", systemImage: "plus.square.on.square") }
                Button { model.ping(profile) } label: { Label("Ping", systemImage: "wave.3.right") }
                Button {} label: { Label("Apps through VPN (MDM only)", systemImage: "building.2") }.disabled(true)
                Divider()
                Button(role: .destructive) { deletingProfile = profile } label: { Label("Delete", systemImage: "trash") }
            } label: {
                Image(systemName: "ellipsis.circle").font(.title3).frame(width: 34, height: 34)
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 17, style: .continuous)
                .fill(profile.id == model.activeProfileID ? QeliTheme.primary.opacity(0.10) : QeliTheme.surface)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 17, style: .continuous)
                .stroke(profile.id == model.activeProfileID ? QeliTheme.primary.opacity(0.45) : Color.primary.opacity(0.08))
        }
    }

    private func reachabilityText(_ profile: Profile) -> String {
        switch model.reachability[profile.id] ?? .idle {
        case .idle: return "not checked"
        case .checking: return "checking…"
        case .reachable(let milliseconds): return "\(milliseconds) ms"
        case .unavailable(let message): return message
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
