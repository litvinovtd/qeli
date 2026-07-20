import AppIntents
import SwiftUI
import WidgetKit

@available(iOS 18.0, *)
struct QeliConnectionControl: ControlWidget {
    static let kind = AppConstants.connectionControlKind

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(
            kind: Self.kind,
            provider: Provider()
        ) { isConnected in
            ControlWidgetToggle(
                "Qeli VPN",
                isOn: isConnected,
                action: QeliSetConnectionIntent(),
                valueLabel: { value in
                    Label(
                        value ? "Connected" : "Disconnected",
                        systemImage: value ? "shield.fill" : "shield"
                    )
                }
            )
            .privacySensitive()
        }
        .displayName("Qeli VPN")
        .description("Connect or disconnect the active Qeli profile.")
    }

    private struct Provider: ControlValueProvider {
        var previewValue: Bool { false }

        func currentValue() async throws -> Bool {
            SharedTunnelStore().snapshot().phase.isActive
        }
    }
}
