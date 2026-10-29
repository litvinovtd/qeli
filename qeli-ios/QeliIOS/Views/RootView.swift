import SwiftUI

private enum RootTab: String, CaseIterable, Identifiable {
    case connection = "Connection"
    case profiles = "Profiles"
    case log = "Log"
    var id: String { rawValue }
    var title: LocalizedStringKey { LocalizedStringKey(rawValue) }
}

struct RootView: View {
    @EnvironmentObject private var model: AppModel
    @State private var tab: RootTab = .connection
    @State private var showingSettings = false

    var body: some View {
        VStack(spacing: 10) {
            header
            tabControl

            Group {
                switch tab {
                case .connection: ConnectionView()
                case .profiles: ProfilesView()
                case .log: LogsView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(QeliTheme.background.ignoresSafeArea())
        .sheet(isPresented: $showingSettings) { SettingsView() }
        .alert(item: $model.alert) { alert in
            // LocalizedStringKey, not the bare String: AppModel builds these as English
            // keys, and Text(String) would render them verbatim regardless of language.
            // Already-interpolated messages carry `isLiteral` so they bypass the lookup.
            Alert(
                title: Text(LocalizedStringKey(alert.title)),
                message: alert.isLiteralMessage
                    ? Text(alert.message)
                    : Text(LocalizedStringKey(alert.message)),
                dismissButton: .default(Text("OK"))
            )
        }
        .confirmationDialog(
            "Import profile?",
            isPresented: Binding(
                get: { model.pendingDeepLink != nil },
                set: { isPresented in
                    if !isPresented { model.pendingDeepLink = nil }
                }
            ),
            titleVisibility: .visible
        ) {
            Button("Import") { model.importDeepLink(); tab = .profiles }
            Button("Cancel", role: .cancel) { model.pendingDeepLink = nil }
        } message: {
            Text(pendingDeepLinkSummary)
        }
        .onOpenURL { url in
            if WidgetControlBridge.isControlURL(url) {
                tab = .connection
                Task { await model.handleWidgetControlURL(url) }
                return
            }
            guard url.scheme?.lowercased() == "qeli" else { return }
            model.pendingDeepLink = url
        }
    }

    private var tabControl: some View {
        HStack(spacing: 0) {
            ForEach(RootTab.allCases) { item in
                Button {
                    withAnimation(.easeInOut(duration: 0.18)) { tab = item }
                } label: {
                    Text(item.title)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(item == tab ? Color.white : QeliTheme.textSecondary)
                        .frame(maxWidth: .infinity, minHeight: 40)
                        .background {
                            if item == tab {
                                RoundedRectangle(cornerRadius: 12, style: .continuous)
                                    .fill(QeliTheme.primary)
                            }
                        }
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(item == tab ? .isSelected : [])
            }
        }
        .padding(4)
        .frame(height: 48)
        .background(
            QeliTheme.surfaceVariant,
            in: RoundedRectangle(cornerRadius: 16, style: .continuous)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(QeliTheme.outline, lineWidth: 1)
        }
        .padding(.horizontal, 16)
    }

    private var pendingDeepLinkSummary: String {
        guard let url = model.pendingDeepLink,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return model.localized("Qeli profile")
        }
        let host = components.host ?? model.localized("Qeli server")
        let endpoint = components.port.map { "\(host):\($0)" } ?? host
        let rawMode = components.queryItems?
            .first(where: { $0.name == "mode" })?.value?.lowercased()
        let mode = rawMode.flatMap {
            ["plain", "fake-tls", "obfs", "reality-tls"].contains($0) ? $0 : nil
        }
        return mode.map { String(format: model.localized("Server: %@ • Mode: %@"), endpoint, $0) }
            ?? String(format: model.localized("Server: %@"), endpoint)
    }

    private var header: some View {
        HStack(spacing: 12) {
            QeliLogo()
            VStack(alignment: .leading, spacing: 1) {
                Text("Qeli").font(.title2.bold()).foregroundStyle(QeliTheme.textPrimary)
                Text("Quick Easy Link IP")
                    .font(.caption)
                    .foregroundStyle(QeliTheme.primary)
            }
            Spacer()
            Button { showingSettings = true } label: {
                Image(systemName: "gearshape.fill").frame(width: 44, height: 44)
            }
            .buttonStyle(.plain)
            .foregroundStyle(QeliTheme.textSecondary)
            .accessibilityLabel("Settings")
            Button {
                model.updateSettings { settings in
                    settings.appearance = settings.appearance == .dark ? .light : .dark
                }
            } label: {
                Image(systemName: model.settings.appearance == .dark ? "sun.max.fill" : "moon.fill")
                    .frame(width: 44, height: 44)
            }
            .buttonStyle(.plain)
            .foregroundStyle(QeliTheme.textSecondary)
            .accessibilityLabel("Toggle theme")
        }
        .padding(.horizontal, 20)
        .padding(.top, 18)
    }
}
