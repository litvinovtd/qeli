import Foundation

/// Provider-wide admission for non-cancellable Apple operations. A lease remains
/// owned until the real OS callback, even if the Swift caller cancels or times out.
actor ProviderOperationGate {
    struct Lease: Equatable, Sendable { fileprivate let id = UUID() }
    enum GateError: Error { case timedOut }
    private struct Waiter {
        let lease: Lease
        let continuation: CheckedContinuation<Lease, Error>
        let timer: Task<Void, Never>?
    }
    private var held: Lease?
    private var waiters: [Waiter] = []
    var queuedOperationCount: Int { waiters.count }

    func acquire(timeoutNanoseconds: UInt64? = nil) async throws -> Lease {
        try Task.checkCancellation()
        if timeoutNanoseconds == 0 { throw GateError.timedOut }
        let lease = Lease()
        if held == nil { held = lease; return lease }
        let granted: Lease = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Lease, Error>) in
                guard !Task.isCancelled else {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                let timer: Task<Void, Never>? = timeoutNanoseconds.map { duration in
                    Task { [weak self] in
                        do { try await Task.sleep(nanoseconds: duration) } catch { return }
                        await self?.expire(lease)
                    }
                }
                waiters.append(Waiter(lease: lease, continuation: continuation, timer: timer))
            }
        } onCancel: {
            Task { await self.cancel(lease) }
        }
        if Task.isCancelled {
            release(granted)
            throw CancellationError()
        }
        return granted
    }

    func release(_ lease: Lease) {
        guard held == lease else { return } // duplicate/late callbacks cannot unlock a newer operation
        if waiters.isEmpty { held = nil; return }
        let next = waiters.removeFirst()
        next.timer?.cancel()
        held = next.lease
        next.continuation.resume(returning: next.lease)
    }

    private func cancel(_ lease: Lease) { remove(lease, error: CancellationError()) }
    private func expire(_ lease: Lease) { remove(lease, error: GateError.timedOut) }
    private func remove(_ lease: Lease, error: Error) {
        guard let index = waiters.firstIndex(where: { $0.lease == lease }) else { return }
        let waiter = waiters.remove(at: index)
        waiter.timer?.cancel()
        waiter.continuation.resume(throwing: error)
    }
}
