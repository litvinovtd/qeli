import Foundation

/// Fences synchronous resource start against terminal completion and releases resource
/// captures before resuming Swift. It does not join an OS cancellation callback.
final class CancellableProbeCompletion<Value>: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var started = false
    private var finished = false
    private var cleanup: (() -> Void)?
    private let completion = AsyncResultCompletion<Value>()

    init(cleanup: @escaping () -> Void) { self.cleanup = cleanup }

    func park(_ value: CheckedContinuation<Result<Value, Error>, Never>) {
        completion.park(value)
    }

    func start(_ body: () -> Void) {
        lock.withLock {
            guard !started, !finished else { return }
            started = true
            body()
        }
    }

    func finish(_ result: Result<Value, Error>) {
        var action = lock.withLock { () -> (() -> Void)? in
            guard !finished else { return nil }
            finished = true
            defer { cleanup = nil }
            return cleanup
        }
        guard action != nil else { return }
        action?()
        action = nil
        completion.finish(result)
    }
}
