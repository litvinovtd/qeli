import Foundation
import SwiftUI

struct ConnectionView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showingProtectionDetails = false

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                connectionCard
                activeProfileCard
                if model.tunnelSnapshot.phase == .connected { statisticsCard }
                protectionCard
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
                Text(LocalizedStringKey(model.tunnelSnapshot.message))
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

    /// What the active profile actually protects.
    ///
    /// One line, deliberately without a verdict. This began as a card led by a bold
    /// "All traffic is protected"; that is the strongest claim in the app, the easiest to get
    /// subtly wrong, and it cost enough height to push the tab into a scroll. The facts were
    /// the useful part, so the strip STATES them and the detail sheet carries the rest.
    /// Mirrors the Android strip decision for decision — both read `ProtectionSummary`.
    @ViewBuilder
    private var protectionCard: some View {
        // Properties OF A CONNECTION — nothing to state until there is one, and the idle
        // screen gets the whole card's height back. The selected profile remains editable;
        // describe only the immutable config snapshot owned by PacketTunnel.
        if model.tunnelSnapshot.phase == .connected,
           let properties = model.tunnelSnapshot.liveConnectionProperties {
            // This summary already includes the app-wide LAN switch as it stood when the
            // extension applied this generation's network settings.
            let summary = ProtectionSummary(live: properties)
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("CONNECTION PROPERTIES")
                        .font(.system(size: 11, weight: .semibold))
                        .kerning(0.8)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.secondary)
                }
                if let warning = summary.warnings.first {
                    // A carve-out is what the user needs to see first, and there is only one
                    // line to say it in — so it replaces the facts and colours them.
                    Text(warningString(warning, count: summary.excludedRouteCount))
                        .font(.caption)
                        .foregroundStyle(QeliTheme.connecting)
                } else {
                    Text("\(properties.wireMode) · \(properties.protocolName.uppercased())\(properties.quicEnabled ? " / QUIC" : "") · \(Text(summary.postQuantum ? "PQ" : "X25519")) · \(Text(summary.keyPinned ? "server key pinned" : "server key on trust (TOFU)"))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .lineLimit(2)
            .frame(maxWidth: .infinity, alignment: .leading)
            .qeliCard(padding: 13)
            .contentShape(Rectangle())
            .onTapGesture { showingProtectionDetails = true }
            .sheet(isPresented: $showingProtectionDetails) { protectionDetails(properties) }
        }
    }

    /// The full picture behind the card. Negotiated rows (DNS, MTU, streams, pushed routes)
    /// come from the tunnel snapshot and are simply omitted while disconnected — never
    /// guessed from the profile.
    private func protectionDetails(_ properties: LiveConnectionProperties) -> some View {
        let summary = ProtectionSummary(live: properties)
        let snapshot = model.tunnelSnapshot
        let live = snapshot.phase == .connected
        return NavigationStack {
            List {
                detailRow("Server", properties.displayEndpoint)
                detailRow(
                    "Transport",
                    "\(properties.wireMode) / \(properties.protocolName.uppercased())\(properties.quicEnabled ? " + QUIC" : "")"
                )
                detailRow("Encryption", summary.postQuantum
                    ? String(localized: "Hybrid post-quantum") : String(localized: "X25519 (no post-quantum)"))
                detailRow("Server key", summary.keyPinned
                    ? String(localized: "server key pinned") : String(localized: "server key on trust (TOFU)"))
                // The compact card shows one highest-priority warning. The sheet is the full
                // explanation, so preserve every independent bypass/security warning here.
                ForEach(Array(summary.warnings.enumerated()), id: \.offset) { item in
                    detailRow(
                        "Warning",
                        warningString(item.element, count: summary.excludedRouteCount)
                    )
                }
                if live {
                    if let addresses = snapshot.tunnelAddresses, !addresses.isEmpty {
                        detailRow("Tunnel addresses", addresses.joined(separator: ", "))
                    } else if let address = snapshot.clientAddress {
                        detailRow("Tunnel IP", address)
                    }
                    // `pushedDNS` is the resolver the tunnel ACTUALLY programmed, and `nil` is
                    // a real answer: none was installed and the device keeps its own.
                    //
                    // Falling back to the profile's list here undid the fix that produced that
                    // value. The nil case is precisely `dns = off` / `dns = system`, where the
                    // profile's resolvers are deliberately NOT applied — so the row named
                    // servers the tunnel had ignored, which is the claim this card exists not
                    // to make. The profile is not a fallback for a live fact.
                    // (Audit 2026-08-02, follow-up.)
                    detailRow("DNS", snapshot.pushedDNS ?? String(localized: "system DNS"))
                    if let mtu = snapshot.appliedMTU {
                        detailRow("MTU", properties.configuredMTU > 0 ? "\(mtu)" : "\(mtu) (auto)")
                    }
                    if snapshot.maxStreams > 1 {
                        let streams = String(
                            format: String(localized: "up to %lld streams"), snapshot.maxStreams)
                        detailRow("Multipath", snapshot.pushed?.multipathAdaptive == true
                            ? streams + ", " + String(localized: "adaptive") : streams)
                    }
                    // OMITTED, not defaulted, when the snapshot predates these fields.
                    //
                    // A running tunnel extension from an older build publishes a snapshot with
                    // no `pushed`, and substituting `PushedFacts()` reported every flag as
                    // false — the sheet then said Padding/Heartbeat/Shaping were OFF when their
                    // real state was simply unknown, which for the DPI-resistance knobs is the
                    // most misleading thing it could say. Showing nothing is honest; the rows
                    // reappear on the next connection. (Audit 2026-08-02, follow-up.)
                    if let pushed = snapshot.pushed {
                        // Only a sample is ever held or shown: a server may advertise a very
                        // long list. The count is the honest part; the sample makes it concrete.
                        if pushed.routeCount > 0 {
                            let shown = pushed.routes.joined(separator: ", ")
                            let extra = pushed.routeCount - pushed.routes.count
                            detailRow("Pushed routes", extra > 0
                                ? String(format: String(localized: "%1$@ and %2$lld more"), shown, extra)
                                : "\(shown) (\(pushed.routeCount))")
                        }
                        // The DPI-resistance knobs actually in force, which the server owns.
                        detailRow("Padding", pushed.paddingEnabled
                            ? "\(pushed.paddingMin)–\(pushed.paddingMax) B" : String(localized: "Off"))
                        detailRow("Heartbeat", pushed.heartbeatEnabled
                            ? "\(pushed.heartbeatIntervalMilliseconds / 1000) s" : String(localized: "Off"))
                        detailRow("Traffic shaping", pushed.shapingEnabled
                            ? String(localized: "On") : String(localized: "Off"))
                    }
                }
                detailRow("Routing", routingText(summary))
                detailRow("Auto-reconnect", properties.reconnectEnabled
                    ? String(localized: "On") : String(localized: "Off"))
            }
            .navigationTitle("CONNECTION PROPERTIES")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Close") { showingProtectionDetails = false }
                }
            }
        }
    }

    private func detailRow(_ label: LocalizedStringKey, _ value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).multilineTextAlignment(.trailing)
        }
        .font(.callout)
    }

    private func routingText(_ summary: ProtectionSummary) -> String {
        switch summary.scope {
        case .all: return String(localized: "All apps (default)")
        case .onlySelected: return String(localized: "Only selected apps are protected")
        case .allExcept: return String(localized: "All apps except the selected ones are protected")
        case .splitRoutes: return String(localized: "Split tunnel — only selected routes")
        }
    }

    // `headline(_:live:)` lived here and rendered the verdict the strip no longer makes.
    // Its wording survives in `routingText`, which the detail sheet still uses to describe
    // the scope — as one row among many rather than as the headline.

    private func warningString(_ warning: ProtectionWarning, count: Int) -> String {
        switch warning {
        case .lanOutside: return String(localized: "Local network stays outside the tunnel")
        case .ipv4Outside: return String(localized: "IPv4 bypasses the tunnel")
        case .ipv6Outside: return String(localized: "IPv6 bypasses the tunnel")
        case .excludedRoutes:
            return String(
                format: String(localized: "%lld route(s) excluded from the tunnel"),
                Int64(count)
            )
        case .noPinnedKey:
            return String(localized: "Without a pinned key the first connection is trusted blindly")
        // Says which way it is wrong: the selection is IGNORED and everything is tunnelled,
        // not "some apps are unprotected". (Audit 2026-08-02, §7.)
        case .perAppNotApplied:
            return String(localized: "Per-app selection needs MDM on iOS — every app is tunnelled")
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
        case .waiting: return "Waiting for network policy"
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
        case .waiting: return "TAP TO CANCEL RESUME"
        default: return "TAP TO CANCEL"
        }
    }

    private var statusColor: Color {
        switch model.tunnelSnapshot.phase {
        case .connected: return QeliTheme.connected
        case .waiting: return QeliTheme.connecting
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
