import Foundation
import Network

protocol QeliTransport: AnyObject {
    var currentPath: NWPath? { get }
    var maximumDatagramSize: Int? { get }
    func connect() async throws
    func send(_ data: Data) async throws
    func receive(maximumLength: Int) async throws -> Data
    func receiveDatagram(maximumLength: Int, timeoutMilliseconds: Int) async throws -> Data?
    func setPathUpdateHandler(_ handler: (@Sendable (NWPath) -> Void)?)
    func cancel()
}

final class NetworkTransport: QeliTransport, @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "ru.autocash.qeli.transport", qos: .userInitiated)
    private let connectionTimeoutSeconds: Int
    private let isDatagram: Bool
    private let datagramInbox: DatagramInbox?

    var currentPath: NWPath? { connection.currentPath }
    var maximumDatagramSize: Int? { isDatagram ? connection.maximumDatagramSize : nil }

    init(config: VPNConfig) throws {
        guard let rawPort = UInt16(exactly: config.port),
              let port = NWEndpoint.Port(rawValue: rawPort) else {
            throw NetworkTransportError.invalidPort(config.port)
        }
        let parameters: NWParameters
        if config.isUDP {
            parameters = .udp
            if config.mtu == 0 && config.mtuProbe {
                let ip = NWProtocolIP.Options()
                ip.disableFragmentation = true
                parameters.defaultProtocolStack.internetProtocol = ip
            }
        } else {
            let tcp = NWProtocolTCP.Options()
            tcp.enableKeepalive = true
            tcp.keepaliveIdle = 15
            tcp.keepaliveInterval = 5
            tcp.keepaliveCount = 3
            parameters = NWParameters(tls: nil, tcp: tcp)
        }
        parameters.serviceClass = .interactive
        let connection = NWConnection(
            host: NWEndpoint.Host(config.serverAddress),
            port: port,
            using: parameters
        )
        self.connection = connection
        isDatagram = config.isUDP
        datagramInbox = config.isUDP ? DatagramInbox(connection: connection) : nil
        connectionTimeoutSeconds = max(1, config.connectionTimeoutSeconds)
    }

    func connect() async throws {
        try Task.checkCancellation()
        let gate = ContinuationGate()
        let timeoutSeconds = connectionTimeoutSeconds
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        gate.resume { continuation.resume(returning: ()) }
                    case .failed(let error):
                        gate.resume { continuation.resume(throwing: error) }
                    case .cancelled:
                        gate.resume { continuation.resume(throwing: CancellationError()) }
                    default:
                        break
                    }
                }
                connection.start(queue: queue)
                queue.asyncAfter(deadline: .now() + .seconds(timeoutSeconds)) { [connection] in
                    gate.resume {
                        connection.cancel()
                        continuation.resume(throwing: NetworkTransportError.timedOut(timeoutSeconds))
                    }
                }
            }
        } onCancel: { [connection] in
            connection.cancel()
        }
    }

    func send(_ data: Data) async throws {
        try Task.checkCancellation()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                connection.send(content: data, completion: .contentProcessed { error in
                    if let error { continuation.resume(throwing: error) }
                    else { continuation.resume(returning: ()) }
                })
            }
        } onCancel: { [connection] in
            connection.cancel()
        }
    }

    func receive(maximumLength: Int = 65_535) async throws -> Data {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            if let datagramInbox {
                return try await datagramInbox.receive(
                    maximumLength: maximumLength,
                    timeoutMilliseconds: nil
                ) ?? Data()
            }
            return try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: 1, maximumLength: maximumLength) {
                    data, _, complete, error in
                    if let error { continuation.resume(throwing: error) }
                    else if let data, !data.isEmpty { continuation.resume(returning: data) }
                    else if complete { continuation.resume(throwing: NetworkTransportError.closed) }
                    else { continuation.resume(returning: Data()) }
                }
            }
        } onCancel: { [connection] in
            connection.cancel()
        }
    }

    func receiveDatagram(
        maximumLength: Int = 65_535,
        timeoutMilliseconds: Int
    ) async throws -> Data? {
        guard let datagramInbox else {
            throw NetworkTransportError.datagramReceiveRequiresUDP
        }
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            try await datagramInbox.receive(
                maximumLength: maximumLength,
                timeoutMilliseconds: max(0, timeoutMilliseconds)
            )
        } onCancel: { [connection] in
            connection.cancel()
        }
    }

    func setPathUpdateHandler(_ handler: (@Sendable (NWPath) -> Void)?) {
        connection.pathUpdateHandler = handler
    }

    func cancel() {
        connection.pathUpdateHandler = nil
        connection.cancel()
    }
}

private actor DatagramInbox {
    private struct Waiter {
        let id: UUID
        let maximumLength: Int
        let continuation: CheckedContinuation<Data?, Error>
    }

    private let connection: NWConnection
    private var buffered: [Data] = []
    private var waiters: [Waiter] = []
    private var receiveInFlight = false
    private var terminalError: Error?

    init(connection: NWConnection) { self.connection = connection }

    func receive(maximumLength: Int, timeoutMilliseconds: Int?) async throws -> Data? {
        try Task.checkCancellation()
        if let terminalError { throw terminalError }
        if !buffered.isEmpty {
            return try bounded(buffered.removeFirst(), maximumLength: maximumLength)
        }
        if let timeoutMilliseconds, timeoutMilliseconds == 0 { return nil }

        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                waiters.append(Waiter(
                    id: id,
                    maximumLength: max(1, maximumLength),
                    continuation: continuation
                ))
                armReceiveIfNeeded()
                if let timeoutMilliseconds {
                    Task { [weak self] in
                        do {
                            try await Task.sleep(
                                nanoseconds: UInt64(timeoutMilliseconds) * 1_000_000
                            )
                        } catch { return }
                        await self?.expire(id)
                    }
                }
            }
        } onCancel: { [weak self] in
            Task { await self?.cancel(id) }
        }
    }

    private func armReceiveIfNeeded() {
        guard !receiveInFlight, terminalError == nil else { return }
        receiveInFlight = true
        connection.receiveMessage { [weak self] data, _, _, error in
            Task { await self?.complete(data: data ?? Data(), error: error) }
        }
    }

    private func complete(data: Data, error: Error?) {
        receiveInFlight = false
        if let error {
            terminalError = error
            let pending = waiters
            waiters.removeAll()
            pending.forEach { $0.continuation.resume(throwing: error) }
            return
        }
        if waiters.isEmpty {
            buffered.append(data)
            if buffered.count > 64 { buffered.removeFirst(buffered.count - 64) }
        } else {
            let waiter = waiters.removeFirst()
            do {
                waiter.continuation.resume(
                    returning: try bounded(data, maximumLength: waiter.maximumLength)
                )
            } catch {
                waiter.continuation.resume(throwing: error)
            }
        }
        if !waiters.isEmpty { armReceiveIfNeeded() }
    }

    private func expire(_ id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.id == id }) else { return }
        let waiter = waiters.remove(at: index)
        waiter.continuation.resume(returning: nil)
    }

    private func cancel(_ id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.id == id }) else { return }
        let waiter = waiters.remove(at: index)
        waiter.continuation.resume(throwing: CancellationError())
    }

    private func bounded(_ data: Data, maximumLength: Int) throws -> Data {
        guard data.count <= max(1, maximumLength) else {
            throw NetworkTransportError.datagramTooLarge(data.count)
        }
        return data
    }
}

private final class ContinuationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var resumed = false

    func resume(_ body: () -> Void) {
        lock.lock()
        guard !resumed else { lock.unlock(); return }
        resumed = true
        lock.unlock()
        body()
    }
}

enum NetworkTransportError: LocalizedError {
    case invalidPort(Int)
    case closed
    case timedOut(Int)
    case datagramReceiveRequiresUDP
    case datagramTooLarge(Int)

    var errorDescription: String? {
        switch self {
        case .invalidPort(let port): return "Invalid server port \(port)."
        case .closed: return "The server closed the transport."
        case .timedOut(let seconds): return "The server did not connect within \(seconds) seconds."
        case .datagramReceiveRequiresUDP: return "Timed datagram receive requires a UDP transport."
        case .datagramTooLarge(let count): return "UDP datagram exceeds the receive limit (\(count) bytes)."
        }
    }
}
