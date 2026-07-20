import SwiftUI
import WidgetKit

struct QeliStatusEntry: TimelineEntry {
    let date: Date
    let snapshot: TunnelSnapshot
}

struct QeliStatusProvider: TimelineProvider {
    func placeholder(in context: Context) -> QeliStatusEntry {
        QeliStatusEntry(
            date: Date(),
            snapshot: TunnelSnapshot(phase: .connected, message: "Tunnel active", connectedAt: Date())
        )
    }

    func getSnapshot(in context: Context, completion: @escaping (QeliStatusEntry) -> Void) {
        completion(QeliStatusEntry(date: Date(), snapshot: SharedTunnelStore().snapshot()))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<QeliStatusEntry>) -> Void) {
        let now = Date()
        let snapshot = SharedTunnelStore().snapshot()
        let refreshInterval: TimeInterval = snapshot.phase.isActive ? 60 : 15 * 60
        completion(Timeline(
            entries: [QeliStatusEntry(date: now, snapshot: snapshot)],
            policy: .after(now.addingTimeInterval(refreshInterval))
        ))
    }
}

struct QeliStatusWidgetView: View {
    let entry: QeliStatusEntry
    @Environment(\.widgetFamily) private var family

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: entry.snapshot.phase.isActive ? "shield.fill" : "shield")
                    .foregroundStyle(entry.snapshot.phase.isActive ? Color.green : Color.secondary)
                Text("Qeli")
                    .font(.headline)
                Spacer()
                Circle()
                    .fill(entry.snapshot.phase.isActive ? Color.green : Color.secondary.opacity(0.5))
                    .frame(width: 8, height: 8)
            }

            Text(statusTitle)
                .font(family == .systemSmall ? .title3.bold() : .title2.bold())
                .lineLimit(1)

            if family == .systemMedium {
                Text(statusDetail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            Spacer(minLength: 0)

            Button(intent: QeliToggleConnectionIntent()) {
                Label(actionTitle, systemImage: entry.snapshot.phase.isActive ? "stop.fill" : "play.fill")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(entry.snapshot.phase.isActive ? .red : .green)
        }
        .containerBackground(for: .widget) {
            LinearGradient(
                colors: [Color.black, Color(red: 0.05, green: 0.12, blue: 0.11)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        }
        .widgetURL(WidgetControlBridge.statusURL)
    }

    private var actionTitle: String {
        entry.snapshot.phase.isActive ? "Disconnect" : "Connect"
    }

    private var statusTitle: String {
        switch entry.snapshot.phase {
        case .disconnected: return "Disconnected"
        case .preparing: return "Preparing"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .reconnecting: return "Reconnecting"
        case .disconnecting: return "Disconnecting"
        case .error: return "Needs attention"
        }
    }

    private var statusDetail: String {
        if let error = entry.snapshot.error, !error.isEmpty { return error }
        if let address = entry.snapshot.clientAddress { return "Client address: \(address)" }
        return entry.snapshot.message.isEmpty ? "Open Qeli to choose an active profile." : entry.snapshot.message
    }
}

struct QeliStatusWidget: Widget {
    let kind = AppConstants.statusWidgetKind

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: QeliStatusProvider()) { entry in
            QeliStatusWidgetView(entry: entry)
        }
        .configurationDisplayName("Qeli VPN Status")
        .description("View VPN status and connect or disconnect the active profile.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}
