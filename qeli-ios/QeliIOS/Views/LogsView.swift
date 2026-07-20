import SwiftUI
import UIKit

struct LogsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var autoScroll = true

    var body: some View {
        VStack(spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Connection log").font(.headline)
                    Text("Live diagnostics of the current session").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(.horizontal, 16)
            HStack {
                Button(autoScroll ? "Scroll ✓" : "Scroll") { autoScroll.toggle() }.buttonStyle(.bordered)
                Button("Copy") {
                    UIPasteboard.general.string = model.logLines.map(formatted).joined(separator: "\n")
                }
                .buttonStyle(.bordered)
                Button("Clear", role: .destructive) { model.clearLog() }.buttonStyle(.bordered)
            }
            .padding(.horizontal, 16)

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 5) {
                        ForEach(model.logLines) { line in
                            Text(formatted(line))
                                .font(.system(size: 11, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(line.id)
                        }
                    }
                    .padding(12)
                }
                .background(QeliTheme.surface, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                .overlay { RoundedRectangle(cornerRadius: 16).stroke(Color.primary.opacity(0.08)) }
                .padding(.horizontal, 16)
                .onChange(of: model.logLines.count) { _, _ in
                    if autoScroll, let id = model.logLines.last?.id { withAnimation { proxy.scrollTo(id, anchor: .bottom) } }
                }
            }
            Text("qeli \(AppConstants.version)").font(.caption2).foregroundStyle(.secondary)
        }
        .padding(.bottom, 8)
        .onAppear { model.refreshLog() }
    }

    private func formatted(_ line: TunnelLogLine) -> String {
        let prefix: String
        switch model.settings.logTimeFormat {
        case .time:
            prefix = line.date.formatted(.dateTime.hour().minute().second().secondFraction(.fractional(3)))
        case .datetime:
            prefix = line.date.formatted(.dateTime.year().month().day().hour().minute().second().secondFraction(.fractional(3)))
        case .rfc3339:
            prefix = line.date.ISO8601Format(.iso8601(timeZone: .gmt).time(includingFractionalSeconds: true))
        case .epoch:
            prefix = String(format: "%.3f", line.date.timeIntervalSince1970)
        case .none:
            prefix = ""
        }
        return prefix.isEmpty ? line.message : "[\(prefix)] \(line.message)"
    }
}
