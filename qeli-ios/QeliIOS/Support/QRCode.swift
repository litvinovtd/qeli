import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit
import AVFoundation

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

/// AVFoundation supports QR capture on every camera-equipped iOS 17 device; VisionKit's
/// DataScanner has an additional A12 hardware floor that excludes supported older iPads.
struct QRScannerView: UIViewControllerRepresentable {
    @Environment(\.locale) private var locale
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> QRCameraViewController {
        QRCameraViewController(locale: locale, onCode: onCode)
    }

    func updateUIViewController(_ uiViewController: QRCameraViewController, context: Context) {}

    static func dismantleUIViewController(_ uiViewController: QRCameraViewController, coordinator: ()) {
        uiViewController.shutdown()
    }
}

@MainActor
final class QRCameraViewController: UIViewController {
    private let locale: Locale
    private let onCode: (String) -> Void
    private var gate = QRScannerDeliveryGate()
    private var authorizationTask: Task<Void, Never>?
    private var capture: QRScannerCaptureSession?
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var rotationCoordinator: AVCaptureDevice.RotationCoordinator?
    private var rotationObservation: NSKeyValueObservation?
    private var unavailableMessage: UIViewController?
    private let activity = UIActivityIndicatorView(style: .large)

    init(locale: Locale, onCode: @escaping (String) -> Void) {
        self.locale = locale
        self.onCode = onCode
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    deinit {
        authorizationTask?.cancel()
        capture?.stop()
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        guard gate.acceptsCallbacks else { return }
        activity.color = .white
        activity.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(activity)
        NSLayoutConstraint.activate([
            activity.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            activity.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
        activity.startAnimating()
        authorizationTask = Task { [weak self] in
            let authorized: Bool
            switch AVCaptureDevice.authorizationStatus(for: .video) {
            case .authorized:
                authorized = true
            case .notDetermined:
                authorized = await AVCaptureDevice.requestAccess(for: .video)
            default:
                authorized = false
            }
            guard !Task.isCancelled, let self, self.gate.acceptsCallbacks else { return }
            if authorized { self.startCamera() }
            else { self.cameraBecameUnavailable(cameraAccessDenied: true) }
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    func shutdown() {
        gate.stop()
        authorizationTask?.cancel()
        authorizationTask = nil
        rotationObservation?.invalidate()
        rotationObservation = nil
        rotationCoordinator = nil
        capture?.stop()
        capture = nil
        activity.stopAnimating()
    }

    private func startCamera() {
        guard gate.acceptsCallbacks, capture == nil else { return }
        let capture = QRScannerCaptureSession(
            onReady: { [weak self] camera in self?.cameraReady(camera) },
            onCode: { [weak self] value in self?.received(value) },
            onUnavailable: { [weak self] in self?.cameraBecameUnavailable() })
        self.capture = capture
        let preview = AVCaptureVideoPreviewLayer(session: capture.session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.insertSublayer(preview, at: 0)
        previewLayer = preview
        capture.start()
    }

    private func cameraReady(_ camera: AVCaptureDevice) {
        guard gate.acceptsCallbacks, let previewLayer else { return }
        activity.stopAnimating()
        // The coordinator handles iPhone/iPad rotation without guessing sensor angles.
        let coordinator = AVCaptureDevice.RotationCoordinator(
            device: camera, previewLayer: previewLayer)
        rotationCoordinator = coordinator
        rotationObservation = coordinator.observe(
            \.videoRotationAngleForHorizonLevelPreview, options: [.initial, .new]
        ) { [weak self] coordinator, _ in
            let angle = coordinator.videoRotationAngleForHorizonLevelPreview
            DispatchQueue.main.async { [weak self] in
                guard let self, self.gate.acceptsCallbacks,
                      let connection = self.previewLayer?.connection,
                      connection.isVideoRotationAngleSupported(angle) else { return }
                connection.videoRotationAngle = angle
            }
        }
    }

    private func received(_ value: String) {
        guard let code = gate.consume(value) else { return }
        shutdown()
        onCode(code)
    }

    func cameraBecameUnavailable(cameraAccessDenied: Bool = false) {
        guard gate.acceptsCallbacks, unavailableMessage == nil else { return }
        shutdown()
        let title = cameraAccessDenied ? "Camera access unavailable" : "Scanner unavailable"
        let detail = cameraAccessDenied
            ? "Allow camera access in Settings, or paste the qeli:// link or import a file."
            : "Paste the qeli:// link or import a file instead."
        let message = UIHostingController(rootView: ContentUnavailableView(
            LocalizedStringKey(title), systemImage: "qrcode.viewfinder",
            description: Text(LocalizedStringKey(detail))
        ).environment(\.locale, locale))
        addChild(message)
        message.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(message.view)
        NSLayoutConstraint.activate([
            message.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            message.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            message.view.topAnchor.constraint(equalTo: view.topAnchor),
            message.view.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        message.didMove(toParent: self)
        unavailableMessage = message
    }
}

/// All mutable capture state and blocking AVFoundation operations belong to this queue.
/// Only the preview layer and the explicitly MainActor callbacks touch the main thread.
private final class QRScannerCaptureSession: NSObject, AVCaptureMetadataOutputObjectsDelegate,
    @unchecked Sendable {
    let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "ru.qeli.ios.qr-camera", qos: .userInitiated)
    private let onReady: @MainActor (AVCaptureDevice) -> Void
    private let onCode: @MainActor (String) -> Void
    private let onUnavailable: @MainActor () -> Void
    private var gate = QRScannerDeliveryGate()
    private var started = false
    private let stopLock = NSLock()
    private var stopRequested = false
    private var output: AVCaptureMetadataOutput?
    private var observers: [NSObjectProtocol] = []

    init(
        onReady: @escaping @MainActor (AVCaptureDevice) -> Void,
        onCode: @escaping @MainActor (String) -> Void,
        onUnavailable: @escaping @MainActor () -> Void
    ) {
        self.onReady = onReady
        self.onCode = onCode
        self.onUnavailable = onUnavailable
        super.init()
    }

    func start() {
        queue.async { [self] in
            guard gate.acceptsCallbacks, !started,
                  !stopLock.withLock({ stopRequested }) else { return }
            started = true
            do {
                let camera = try configure()
                guard !stopLock.withLock({ stopRequested }) else {
                    stopCapture()
                    return
                }
                observeFailures()
                session.startRunning()
                guard session.isRunning, !session.isInterrupted else {
                    fail()
                    return
                }
                DispatchQueue.main.async { [self] in onReady(camera) }
            } catch {
                fail()
            }
        }
    }

    func stop() {
        // Revoke admission immediately even if the start/configuration is still queued.
        stopLock.withLock { stopRequested = true }
        // Retain the driver until a stop queued behind configuration/startRunning drains.
        // A dismissed controller's main-actor gate already suppresses all late callbacks.
        queue.async { [self] in stopCapture() }
    }

    private func configure() throws -> AVCaptureDevice {
        guard AVCaptureDevice.authorizationStatus(for: .video) == .authorized,
              let camera = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back)
                ?? AVCaptureDevice.default(for: .video) else { throw CameraError.unavailable }
        let input = try AVCaptureDeviceInput(device: camera)
        let metadata = AVCaptureMetadataOutput()
        session.beginConfiguration()
        defer { session.commitConfiguration() }
        if session.canSetSessionPreset(.hd1280x720) { session.sessionPreset = .hd1280x720 }
        guard session.canAddInput(input) else { throw CameraError.unavailable }
        session.addInput(input)
        guard session.canAddOutput(metadata) else { throw CameraError.unavailable }
        session.addOutput(metadata)
        guard metadata.availableMetadataObjectTypes.contains(.qr) else { throw CameraError.unavailable }
        metadata.metadataObjectTypes = [.qr]
        metadata.setMetadataObjectsDelegate(self, queue: queue)
        output = metadata
        return camera
    }

    private func observeFailures() {
        for name in [AVCaptureSession.runtimeErrorNotification, AVCaptureSession.wasInterruptedNotification] {
            observers.append(NotificationCenter.default.addObserver(
                forName: name, object: session, queue: nil
            ) { [weak self] _ in
                guard let self else { return }
                self.queue.async { [weak self] in self?.fail() }
            })
        }
    }

    private func fail() {
        guard gate.acceptsCallbacks else { return }
        stopCapture()
        DispatchQueue.main.async { [self] in onUnavailable() }
    }

    private func stopCapture() {
        stopLock.withLock { stopRequested = true }
        gate.stop()
        output?.setMetadataObjectsDelegate(nil, queue: nil)
        observers.forEach(NotificationCenter.default.removeObserver)
        observers.removeAll()
        if session.isRunning { session.stopRunning() }
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard gate.acceptsCallbacks else { return }
        // Metadata callbacks have no retained video frame queue. Inspect only a small,
        // fixed batch and stop capture before publishing the first supported payload.
        for object in metadataObjects.prefix(8) {
            guard let code = object as? AVMetadataMachineReadableCodeObject,
                  code.type == .qr, let value = code.stringValue,
                  let payload = gate.consume(value) else { continue }
            stopCapture()
            DispatchQueue.main.async { [self] in onCode(payload) }
            return
        }
    }

    private enum CameraError: Error { case unavailable }
}

/// A bounded scanner surface shared by compact and regular-width iOS layouts.
/// An unconstrained camera controller expands to the entire sheet, which turns the camera
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
