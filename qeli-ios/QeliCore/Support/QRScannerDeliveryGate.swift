/// Single-owner state for a scanner callback stream. Use one instance on the capture
/// queue and another on the main actor so teardown revokes already-enqueued UI callbacks.
struct QRScannerDeliveryGate {
    static let maximumPayloadBytes = 8 * 1_024
    private var stopped = false
    private var consumed = false

    var acceptsCallbacks: Bool { !stopped && !consumed }

    mutating func consume(_ value: String) -> String? {
        guard acceptsCallbacks, value.hasPrefix("qeli://"),
              value.utf8.count <= Self.maximumPayloadBytes else { return nil }
        consumed = true
        return value
    }

    mutating func stop() { stopped = true }
}
