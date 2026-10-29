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
                // Drive the UI language from the setting instead of the device locale, so
                // the app opens in English by default on any phone (matching Android) and
                // switches live when the user picks a language — SwiftUI resolves every
                // LocalizedStringKey against this locale.
                .environment(\.locale, model.settings.language.locale)
        }
        .onChange(of: scenePhase, initial: true) { _, phase in
            model.setSceneActive(phase == .active)
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
