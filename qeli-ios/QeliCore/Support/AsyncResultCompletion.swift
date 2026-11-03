import Foundation

/// Exactly one outcome, including cancellation before the continuation is parked.
final class AsyncResultCompletion<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Result<Value, Error>, Never>?
    private var result: Result<Value, Error>?

    func park(_ value: CheckedContinuation<Result<Value, Error>, Never>) {
        let immediate = lock.withLock { () -> Result<Value, Error>? in
            if let result { return result }
            continuation = value
            return nil
        }
        if let immediate { value.resume(returning: immediate) }
    }

    func finish(_ value: Result<Value, Error>) {
        let pending = lock.withLock { () -> CheckedContinuation<Result<Value, Error>, Never>? in
            guard result == nil else { return nil }
            result = value
            defer { continuation = nil }
            return continuation
        }
        pending?.resume(returning: value)
    }
}
