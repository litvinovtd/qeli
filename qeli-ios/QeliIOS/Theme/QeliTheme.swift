import SwiftUI

enum QeliTheme {
    static let primary = Color(red: 0.22, green: 0.55, blue: 0.98)
    static let secondary = Color(red: 0.47, green: 0.32, blue: 0.95)
    static let connected = Color(red: 0.14, green: 0.72, blue: 0.43)
    static let connecting = Color(red: 0.96, green: 0.67, blue: 0.20)
    static let disconnected = Color.secondary.opacity(0.55)
    static let error = Color(red: 0.92, green: 0.27, blue: 0.30)
    static let background = Color(uiColor: .systemGroupedBackground)
    static let surface = Color(uiColor: .secondarySystemGroupedBackground)
}

struct QeliCard: ViewModifier {
    var padding: CGFloat = 16

    func body(content: Content) -> some View {
        content
            .padding(padding)
            .background(QeliTheme.surface, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .stroke(Color.primary.opacity(0.09), lineWidth: 1)
            }
    }
}

extension View {
    func qeliCard(padding: CGFloat = 16) -> some View { modifier(QeliCard(padding: padding)) }
}

struct QeliLogo: View {
    var size: CGFloat = 44

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                .fill(LinearGradient(colors: [QeliTheme.primary, QeliTheme.secondary], startPoint: .topLeading, endPoint: .bottomTrailing))
            Text("Q")
                .font(.system(size: size * 0.56, weight: .black, design: .rounded))
                .foregroundStyle(.white)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

