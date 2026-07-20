import Foundation

/// Record-oriented adapter over Network.framework's connected UDP transport.
/// It intentionally exposes the same three core operations as the TCP record
/// transports (`sendRecord`, `receiveRecord`, `cancel`) so the handshake and data
/// plane can be transport-agnostic.
final class UDPRecordTransport: QeliHandshakeRetransmittingRecordTransport, @unchecked Sendable {
    let underlying: QeliTransport
    let datagramCodec: UDPDatagramCodec

    var underlyingTransport: QeliTransport { underlying }

    private let sender: UDPDatagramSender
    private let queueLock = NSLock()
    private var queuedRecords: [Data] = []

    init(underlying: QeliTransport, config: VPNConfig) throws {
        self.underlying = underlying
        datagramCodec = try UDPDatagramCodec(config: config)
        sender = UDPDatagramSender(underlying: underlying)
    }

    init(underlying: QeliTransport, datagramCodec: UDPDatagramCodec) {
        self.underlying = underlying
        self.datagramCodec = datagramCodec
        sender = UDPDatagramSender(underlying: underlying)
    }

    func connect() async throws { try await underlying.connect() }

    func sendRecord(_ record: Data, longHeader: Bool = false) async throws {
        try await sender.send(datagramCodec.encode(record: record, longHeader: longHeader))
    }

    /// Receives one complete TLS-shaped record. UDP corruption, unknown control
    /// datagrams and incomplete fragments are dropped without killing the tunnel.
    /// There must be only one concurrent consumer, matching the tunnel downlink task.
    func receiveRecord() async throws -> Data {
        while true {
            if let record = popQueuedRecord() { return record }
            try Task.checkCancellation()
            let datagram = try await underlying.receive(maximumLength: 65_535)
            guard !datagram.isEmpty else { continue }
            let event: UDPDatagramEvent
            do {
                event = try datagramCodec.ingest(datagram: datagram)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                // Datagram transports are message-oriented: one malformed/corrupt
                // message cannot desynchronise the following message.
                continue
            }
            switch event {
            case .records(let records):
                guard let first = records.first else { continue }
                if records.count > 1 {
                    queueLock.withLock { queuedRecords.append(contentsOf: records.dropFirst()) }
                }
                return first
            case .fragmentPending, .junk, .mtuProbe, .mtuProbeAck:
                continue
            }
        }
    }

    /// Waits for a handshake response while retransmitting the exact same encrypted
    /// Qeli record at jittered ~1 second intervals. Re-encrypting would advance the
    /// packet counter and make a late copy of the original look like a replay.
    /// At the final deadline the UDP connection is cancelled to unblock `receive`.
    func receiveHandshakeRecord(
        resending record: Data,
        longHeader: Bool,
        deadline: ContinuousClock.Instant,
        expected: String
    ) async throws -> Data {
        let clock = ContinuousClock()
        let retransmitFailure = UDPFailureBox()
        let timeout = Task<Void, Never> { [weak self] in
            try? await clock.sleep(until: deadline)
            guard !Task.isCancelled else { return }
            self?.cancel()
        }
        let retransmitter = Task<Void, Never> { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                let jitter = Int.random(in: 0..<250)
                let wait = 1_000 + jitter
                try? await Task.sleep(nanoseconds: UInt64(wait) * 1_000_000)
                guard !Task.isCancelled, clock.now < deadline else { return }
                do {
                    try await self.sendRecord(record, longHeader: longHeader)
                } catch {
                    retransmitFailure.store(error)
                    self.cancel()
                    return
                }
            }
        }
        defer { timeout.cancel(); retransmitter.cancel() }
        do {
            return try await receiveRecord()
        } catch {
            if let error = retransmitFailure.value { throw error }
            if clock.now >= deadline { throw UDPRecordTransportError.handshakeTimedOut(expected) }
            throw error
        }
    }

    func sendAWGJunkPreamble(count: Int, minimumSize: Int, maximumSize: Int) async throws {
        let datagrams = try datagramCodec.encodeAWGJunkPreamble(
            count: count,
            minimumSize: minimumSize,
            maximumSize: maximumSize
        )
        try await sender.send(datagrams)
    }

    /// Sends a Qeli path-MTU control message through the same short QUIC/obfs
    /// layers as normal data. The caller owns DF socket policy and the probe ladder.
    func sendMTUProbe(id: Int, outerSize: Int) async throws {
        guard let probe = try UDPFragmentation.mtuProbeDatagram(id: id, outerSize: outerSize) else {
            throw UDPRecordTransportError.invalidProbeSize(outerSize)
        }
        let datagram = try datagramCodec.encodePayload(probe, longHeader: false)
        if let maximum = underlying.maximumDatagramSize,
           maximum > 0,
           datagram.count > maximum {
            throw UDPRecordTransportError.datagramExceedsTransportLimit(
                actual: datagram.count,
                maximum: maximum
            )
        }
        try await sender.send([datagram])
    }

    /// Reads one unframed control payload. Call only during path-MTU discovery,
    /// before starting the normal downlink consumer.
    func receiveControlEvent() async throws -> UDPDatagramEvent {
        while true {
            let datagram = try await underlying.receive(maximumLength: 65_535)
            guard !datagram.isEmpty else { continue }
            do {
                let event = try datagramCodec.ingest(datagram: datagram)
                if case .records(let records) = event {
                    queueLock.withLock { queuedRecords.append(contentsOf: records) }
                    continue
                }
                return event
            } catch is CancellationError {
                throw CancellationError()
            } catch { continue }
        }
    }

    /// Timed variant used by path-MTU discovery. The Network transport keeps one
    /// message receive armed across timeout ticks, so a timeout doesn't cancel the
    /// authenticated UDP session or lose a late ACK.
    func receiveControlEvent(timeoutMilliseconds: Int) async throws -> UDPDatagramEvent? {
        let deadline = Date().addingTimeInterval(Double(max(0, timeoutMilliseconds)) / 1_000)
        while true {
            let remaining = max(0, Int(deadline.timeIntervalSinceNow * 1_000))
            guard remaining > 0 else { return nil }
            guard let datagram = try await underlying.receiveDatagram(
                maximumLength: 65_535,
                timeoutMilliseconds: remaining
            ) else { return nil }
            guard !datagram.isEmpty else { continue }
            do {
                let event = try datagramCodec.ingest(datagram: datagram)
                if case .records(let records) = event {
                    queueLock.withLock { queuedRecords.append(contentsOf: records) }
                    continue
                }
                return event
            } catch is CancellationError {
                throw CancellationError()
            } catch { continue }
        }
    }

    func cancel() { underlying.cancel() }

    private func popQueuedRecord() -> Data? {
        queueLock.withLock {
            guard !queuedRecords.isEmpty else { return nil }
            return queuedRecords.removeFirst()
        }
    }

}

private actor UDPDatagramSender {
    private let underlying: QeliTransport

    init(underlying: QeliTransport) { self.underlying = underlying }

    func send(_ datagrams: [Data]) async throws {
        for datagram in datagrams {
            try Task.checkCancellation()
            try await underlying.send(datagram)
        }
    }
}

private final class UDPFailureBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Error?

    var value: Error? { lock.withLock { stored } }
    func store(_ error: Error) { lock.withLock { if stored == nil { stored = error } } }
}

enum UDPRecordTransportError: LocalizedError {
    case handshakeTimedOut(String)
    case invalidProbeSize(Int)
    case datagramExceedsTransportLimit(actual: Int, maximum: Int)

    var errorDescription: String? {
        switch self {
        case .handshakeTimedOut(let expected): return "UDP handshake timed out waiting for \(expected)."
        case .invalidProbeSize(let size): return "Invalid UDP path-MTU probe size \(size)."
        case .datagramExceedsTransportLimit(let actual, let maximum):
            return "UDP probe is \(actual) bytes; transport limit is \(maximum)."
        }
    }
}
