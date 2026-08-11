import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit
import VisionKit

enum QRCodeGenerator {
    private static let context = CIContext()

    static func image(for text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)),
              let cgImage = context.createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}

struct QRScannerView: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

    func makeUIViewController(context: Context) -> UIViewController {
        guard DataScannerViewController.isSupported, DataScannerViewController.isAvailable else {
            return UIHostingController(rootView: ContentUnavailableView(
                "Scanner unavailable",
                systemImage: "qrcode.viewfinder",
                description: Text("Paste the qeli:// link or import a file instead.")
            ))
        }
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: true,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        do {
            try scanner.startScanning()
            return scanner
        } catch {
            return UIHostingController(rootView: ContentUnavailableView(
                "Could not start scanner",
                systemImage: "exclamationmark.triangle",
                description: Text(error.localizedDescription)
            ))
        }
    }

    func updateUIViewController(_ uiViewController: UIViewController, context: Context) {}

    static func dismantleUIViewController(_ uiViewController: UIViewController, coordinator: Coordinator) {
        (uiViewController as? DataScannerViewController)?.stopScanning()
    }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onCode: (String) -> Void
        private var consumed = false

        init(onCode: @escaping (String) -> Void) { self.onCode = onCode }

        func dataScanner(
            _ dataScanner: DataScannerViewController,
            didAdd addedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            guard !consumed else { return }
            for item in addedItems {
                if case .barcode(let barcode) = item,
                   let value = barcode.payloadStringValue,
                   value.hasPrefix("qeli://") {
                    consumed = true
                    onCode(value)
                    return
                }
            }
        }
    }
}

/// A bounded scanner surface shared by compact and regular-width iOS layouts.
/// `DataScannerViewController` otherwise expands to the entire sheet, which turns the camera
/// into a tall full-screen page even though a QR targeting viewport is naturally square.
struct QRScannerSheet: View {
    @Environment(\.dismiss) private var dismiss
    let onCode: (String) -> Void

    var body: some View {
        NavigationStack {
            GeometryReader { proxy in
                let availableWidth = max(proxy.size.width - 32, 0)
                let availableHeight = max(proxy.size.height - 76, 0)
                let side = max(120, min(520, min(availableWidth, availableHeight)))

                VStack(spacing: 12) {
                    Spacer(minLength: 8)
                    QRScannerView(onCode: onCode)
                        .frame(width: side, height: side)
                        .background(.black)
                        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: 20, style: .continuous)
                                .stroke(.secondary.opacity(0.35), lineWidth: 1)
                        }
                        .accessibilityLabel("QR code camera preview")
                    Text("Point the camera at the qeli:// QR code.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 16)
                    Spacer(minLength: 8)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .navigationTitle("Scan profile")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
        .presentationDetents([.fraction(0.72), .large])
        .presentationDragIndicator(.visible)
        .presentationCornerRadius(28)
    }
}
