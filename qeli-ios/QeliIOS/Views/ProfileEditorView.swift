import SwiftUI

struct ProfileEditorView: View {
    private static let roamingPolicies = ["auto", "required", "off"]
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let profile: Profile?
    @State private var name: String
    @State private var configText: String
    @State private var roamingPolicy: String
    @State private var validationError: String?
    @State private var showingReconnectNotice = false

    init(profile: Profile?) {
        self.profile = profile
        let initialText = profile?.configText ?? Profile.template.configText
        let initialRoaming = (try? VPNConfig(parsing: initialText))?.roamingPolicy ?? "auto"
        _name = State(initialValue: profile?.name ?? "My server")
        _configText = State(initialValue: initialText)
        _roamingPolicy = State(initialValue: initialRoaming)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Profile name") { TextField("Profile name", text: $name) }
                Section {
                    Picker("Session roaming", selection: $roamingPolicy) {
                        ForEach(Self.roamingPolicies, id: \.self) { policy in
                            Text(LocalizedStringKey(
                                policy == "auto" ? "Automatic (when supported)"
                                : policy == "required" ? "Required" : "Disabled"
                            )).tag(policy)
                        }
                    }
                } footer: {
                    Text("Auto keeps the authenticated session across network changes when supported, otherwise reconnects. Required refuses unsupported servers or platforms.")
                }
                Section("Config (INI)") {
                    TextEditor(text: $configText)
                        .font(.system(.body, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .frame(minHeight: 320)
                }
                if let validationError {
                    Section { Label(validationError, systemImage: "exclamationmark.triangle.fill").foregroundStyle(QeliTheme.error) }
                }
            }
            .navigationTitle(profile == nil ? LocalizedStringKey("New profile") : LocalizedStringKey("Edit profile"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        do {
                            var editedConfig = try VPNConfig(parsing: configText)
                            editedConfig.roamingPolicy = roamingPolicy
                            let normalized = try editedConfig.toINI()
                            let reconnectRequired = try model.saveProfile(
                                original: profile, name: name, configText: normalized
                            )
                            if reconnectRequired { showingReconnectNotice = true }
                            else { dismiss() }
                        } catch { validationError = error.localizedDescription }
                    }
                }
            }
        }
        .alert("Reconnect required", isPresented: $showingReconnectNotice) {
            Button("OK") { dismiss() }
        } message: {
            Text("The active profile was saved. Disconnect and connect again to apply it to the running tunnel.")
        }
    }
}
