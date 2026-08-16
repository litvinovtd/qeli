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
enum QRScannerLayout {
    static let horizontalInset: CGFloat = 16
    static let promptReserve: CGFloat = 112
    static let maximumSide: CGFloat = 520

    static func previewSide(in size: CGSize) -> CGFloat {
        let width = max(size.width - horizontalInset * 2, 0)
        let height = max(size.height - promptReserve, 0)
        return max(120, min(maximumSide, min(width, height)))
    }

    static func previewCenter(in size: CGSize) -> CGPoint {
        CGPoint(x: size.width / 2, y: size.height / 2)
    }
}

struct QRScannerSheet: View {
    @Environment(\.dismiss) private var dismiss
    let onCode: (String) -> Void

    var body: some View {
        NavigationStack {
            GeometryReader { proxy in
                let side = QRScannerLayout.previewSide(in: proxy.size)
                let center = QRScannerLayout.previewCenter(in: proxy.size)
                let promptY = min(proxy.size.height - 18, center.y + side / 2 + 28)

                ZStack {
                    QRScannerView(onCode: onCode)
                        .frame(width: side, height: side)
                        .background(.black)
                        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: 20, style: .continuous)
                                .stroke(.secondary.opacity(0.35), lineWidth: 1)
                        }
                        .accessibilityLabel("QR code camera preview")
                        .position(center)
                    Text("Point the camera at the qeli:// QR code.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(width: min(side, max(proxy.size.width - 32, 0)))
                        .position(x: center.x, y: promptY)
                }
                .frame(width: proxy.size.width, height: proxy.size.height)
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
