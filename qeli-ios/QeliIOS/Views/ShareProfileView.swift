import SwiftUI

struct ShareProfileView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false
    let profile: Profile
    private let link: String?
    private let shareError: String?

    init(profile: Profile) {
        self.profile = profile
        do {
            link = try VPNConfig(parsing: profile.configText).toQeliURI(label: profile.name)
            shareError = nil
        } catch {
            link = nil
            shareError = error.localizedDescription
        }
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if let link {
                    if let image = QRCodeGenerator.image(for: link) {
                        Image(uiImage: image)
                            .interpolation(.none)
                            .resizable()
                            .scaledToFit()
                            .frame(maxWidth: 270)
                            .padding(14)
                            .background(.white, in: RoundedRectangle(cornerRadius: 18))
                    }
                    Text(link)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .lineLimit(7)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .qeliCard()
                    HStack(spacing: 12) {
                        Button {
                            UIPasteboard.general.string = link
                            copied = true
                        } label: {
                            Label(copied ? "Link copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        ShareLink(item: link) {
                            Label("Share profile", systemImage: "square.and.arrow.up")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(QeliTheme.primary)
                    }
                    Text("The share link contains the profile credentials.")
                        .font(.footnote).foregroundStyle(.secondary)
                } else {
                    ContentUnavailableView(
                        "Cannot share profile",
                        systemImage: "exclamationmark.triangle",
                        description: Text(shareError ?? "Unknown error")
                    )
                }
            }
            .padding()
            .navigationTitle("Share “\(profile.name)”")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}
