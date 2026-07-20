import Foundation
import SwiftUI

struct ConnectionView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                connectionCard
                activeProfileCard
                if model.tunnelSnapshot.phase == .connected { statisticsCard }
                if let error = model.tunnelSnapshot.error, !error.isEmpty {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(QeliTheme.error)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .qeliCard()
                }
            }
            .padding(16)
        }
        .refreshable {
            model.tunnelManager.refreshSnapshot()
            model.refreshLog()
        }
    }

    private var connectionCard: some View {
        VStack(spacing: 14) {
            Button { Task { await model.toggleConnection() } } label: {
                ZStack {
                    Circle()
                        .stroke(Color.primary.opacity(0.08), lineWidth: 14)
                    Circle()
                        .trim(from: 0.03, to: model.isTunnelBusy ? 0.76 : 0.97)
                        .stroke(
                            AngularGradient(colors: [QeliTheme.primary, QeliTheme.secondary, QeliTheme.primary], center: .center),
                            style: StrokeStyle(lineWidth: 14, lineCap: .round)
                        )
                        .rotationEffect(.degrees(model.isTunnelBusy ? 160 : -90))
                        .animation(.easeInOut(duration: 0.7), value: model.tunnelSnapshot.phase)
                    VStack(spacing: 8) {
                        Image(systemName: "power")
                            .font(.system(size: 42, weight: .semibold))
                        Text(ringHint)
                            .font(.caption2.weight(.semibold))
                            .tracking(1.1)
                    }
                    .foregroundStyle(.primary)
                }
                .frame(width: 190, height: 190)
                .contentShape(Circle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(ringHint)

            HStack(spacing: 9) {
                Circle().fill(statusColor).frame(width: 11, height: 11)
                Text(statusTitle).font(.title3.bold())
                if let address = model.tunnelSnapshot.clientAddress {
                    Text("IP \(address)").font(.caption).foregroundStyle(QeliTheme.primary)
                }
            }
            if !model.tunnelSnapshot.message.isEmpty {
                Text(model.tunnelSnapshot.message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .multilineTextAlignment(.center)
            }
            if model.tunnelSnapshot.phase == .connected {
                Text("↓ \(formatRate(model.tunnelSnapshot.downloadBytesPerSecond))   ↑ \(formatRate(model.tunnelSnapshot.uploadBytesPerSecond))")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
        .qeliCard(padding: 20)
    }

    private var activeProfileCard: some View {
        HStack(spacing: 12) {
            Circle().fill(reachabilityColor).frame(width: 10, height: 10)
            VStack(alignment: .leading, spacing: 2) {
                Text("ACTIVE PROFILE").font(.caption2).foregroundStyle(.secondary)
                Text(model.activeProfile?.name ?? "—").font(.headline).lineLimit(1)
                Text(reachabilityText).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Ping") {
                if let profile = model.activeProfile { model.ping(profile) }
            }
            .buttonStyle(.bordered)
            .tint(QeliTheme.primary)
        }
        .qeliCard()
    }

    private var statisticsCard: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            HStack(spacing: 0) {
                statistic("UPTIME", formatDuration(model.tunnelSnapshot.uptime), color: .primary)
                Divider().frame(height: 42)
                statistic("↓ DOWNLOAD", formatBytes(model.tunnelSnapshot.bytesDownloaded), color: QeliTheme.connected)
                Divider().frame(height: 42)
                statistic("↑ UPLOAD", formatBytes(model.tunnelSnapshot.bytesUploaded), color: QeliTheme.primary)
            }
            .qeliCard()
        }
    }

    private func statistic(_ title: LocalizedStringKey, _ value: String, color: Color) -> some View {
        VStack(spacing: 3) {
            Text(title).font(.system(size: 9, weight: .medium)).foregroundStyle(.secondary)
            Text(value).font(.subheadline.bold().monospaced()).foregroundStyle(color).lineLimit(1).minimumScaleFactor(0.65)
        }
        .frame(maxWidth: .infinity)
    }

    private var statusTitle: LocalizedStringKey {
        switch model.tunnelSnapshot.phase {
        case .disconnected: return "Disconnected"
        case .preparing, .connecting: return "Connecting…"
        case .connected: return "Connected"
        case .reconnecting: return "Reconnecting…"
        case .disconnecting: return "Disconnecting…"
        case .error: return "Error"
        }
    }

    private var ringHint: LocalizedStringKey {
        switch model.tunnelSnapshot.phase {
        case .disconnected: return "TAP TO CONNECT"
        case .error: return "TAP TO RETRY"
        case .connected: return "TAP TO DISCONNECT"
        default: return "TAP TO CANCEL"
        }
    }

    private var statusColor: Color {
        switch model.tunnelSnapshot.phase {
        case .connected: return QeliTheme.connected
        case .preparing, .connecting, .reconnecting, .disconnecting: return QeliTheme.connecting
        case .error: return QeliTheme.error
        case .disconnected: return QeliTheme.disconnected
        }
    }

    private var reachabilityText: String {
        guard let id = model.activeProfile?.id else { return "No profile" }
        switch model.reachability[id] ?? .idle {
        case .idle: return "tap Ping to check"
        case .checking: return "checking…"
        case .reachable(let milliseconds): return "reachable · \(milliseconds) ms"
        case .unavailable(let reason): return reason
        }
    }

    private var reachabilityColor: Color {
        guard let id = model.activeProfile?.id else { return .secondary }
        switch model.reachability[id] ?? .idle {
        case .reachable: return QeliTheme.connected
        case .unavailable: return QeliTheme.error
        case .checking: return QeliTheme.connecting
        case .idle: return .secondary
        }
    }

    private func formatRate(_ bytes: UInt64) -> String { "\(formatBytes(bytes))/s" }
    private func formatBytes(_ bytes: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(bytes); var unit = 0
        while value >= 1_024, unit < units.count - 1 { value /= 1_024; unit += 1 }
        return unit == 0 ? "\(Int(value)) \(units[unit])" : String(format: "%.1f %@", value, units[unit])
    }
    private func formatDuration(_ interval: TimeInterval) -> String {
        let seconds = Int(interval)
        return String(format: "%02d:%02d:%02d", seconds / 3_600, (seconds / 60) % 60, seconds % 60)
    }
}
