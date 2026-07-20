import SwiftUI

struct ProfileEditorView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let profile: Profile?
    @State private var name: String
    @State private var configText: String
    @State private var validationError: String?

    init(profile: Profile?) {
        self.profile = profile
        _name = State(initialValue: profile?.name ?? "My server")
        _configText = State(initialValue: profile?.configText ?? Profile.template.configText)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Profile name") { TextField("Profile name", text: $name) }
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
                            try model.saveProfile(id: profile?.id, name: name, configText: configText)
                            dismiss()
                        } catch { validationError = error.localizedDescription }
                    }
                }
            }
        }
    }
}
