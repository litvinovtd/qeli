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
        VStack(spacing: 12) {
            header
            Picker("Section", selection: $tab) {
                ForEach(RootTab.allCases) { item in Text(item.title).tag(item) }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal)

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
            Alert(title: Text(alert.title), message: Text(alert.message), dismissButton: .default(Text("OK")))
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

    private var pendingDeepLinkSummary: String {
        guard let url = model.pendingDeepLink,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return "Qeli profile"
        }
        let host = components.host ?? "Qeli server"
        let endpoint = components.port.map { "\(host):\($0)" } ?? host
        let rawMode = components.queryItems?
            .first(where: { $0.name == "mode" })?.value?.lowercased()
        let mode = rawMode.flatMap {
            ["plain", "fake-tls", "obfs", "reality-tls"].contains($0) ? $0 : nil
        }
        return mode.map { "Server: \(endpoint) • Mode: \($0)" } ?? "Server: \(endpoint)"
    }

    private var header: some View {
        HStack(spacing: 12) {
            QeliLogo()
            VStack(alignment: .leading, spacing: 1) {
                Text("Qeli").font(.title2.bold())
                Text("Quick Easy Link IP")
                    .font(.caption)
                    .foregroundStyle(QeliTheme.primary)
            }
            Spacer()
            Button { showingSettings = true } label: {
                Image(systemName: "gearshape.fill").frame(width: 34, height: 34)
            }
            .accessibilityLabel("Settings")
            Button {
                model.updateSettings { settings in
                    settings.appearance = settings.appearance == .dark ? .light : .dark
                }
            } label: {
                Image(systemName: model.settings.appearance == .dark ? "sun.max.fill" : "moon.fill")
                    .frame(width: 34, height: 34)
            }
            .accessibilityLabel("Toggle theme")
        }
        .padding(.horizontal, 20)
        .padding(.top, 8)
    }
}
