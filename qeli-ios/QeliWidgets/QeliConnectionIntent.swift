import AppIntents
import Foundation
import WidgetKit

enum QeliWidgetIntentError: LocalizedError {
    case appGroupUnavailable
    case controlsDisabled

    var errorDescription: String? {
        switch self {
        case .appGroupUnavailable:
            return "Qeli could not write the control request to its shared App Group."
        case .controlsDisabled:
            return "Your organization disabled Qeli widget controls."
        }
    }
}

struct QeliToggleConnectionIntent: AppIntent {
    static var title: LocalizedStringResource = "Toggle Qeli VPN"
    static var description = IntentDescription("Connect or disconnect the active Qeli profile.")
    static var openAppWhenRun = true
    static var isDiscoverable = false
    static var authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication

    func perform() async throws -> some IntentResult {
        let current = SharedTunnelStore().snapshot()
        let command: QeliConnectionCommand = current.phase.isActive ? .disconnect : .connect
        try issue(command)
        return .result()
    }
}

@available(iOS 18.0, *)
struct QeliSetConnectionIntent: SetValueIntent {
    static var title: LocalizedStringResource = "Set Qeli VPN Connection"
    static var description = IntentDescription("Connect or disconnect the active Qeli profile.")
    static var openAppWhenRun = true
    static var isDiscoverable = false
    static var authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication

    @Parameter(title: "Connected")
    var value: Bool

    func perform() async throws -> some IntentResult {
        try issue(value ? .connect : .disconnect)
        return .result()
    }
}

private func issue(_ command: QeliConnectionCommand) throws {
    guard WidgetControlBridge.widgetControlsEnabled else {
        throw QeliWidgetIntentError.controlsDisabled
    }
    guard WidgetControlBridge.issue(command) != nil else {
        throw QeliWidgetIntentError.appGroupUnavailable
    }
    NotificationCenter.default.post(name: .qeliWidgetControlRequestAvailable, object: nil)
    WidgetCenter.shared.reloadTimelines(ofKind: AppConstants.statusWidgetKind)
}
