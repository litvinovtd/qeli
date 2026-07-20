import SwiftUI

@main
struct QeliIOSApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .preferredColorScheme(colorScheme)
        }
        .onChange(of: scenePhase) { phase in
            guard phase == .active else { return }
            Task {
                await model.refreshManagedConfiguration()
                await model.consumePendingWidgetControlRequest()
            }
        }
    }

    private var colorScheme: ColorScheme? {
        switch model.settings.appearance {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }
}
