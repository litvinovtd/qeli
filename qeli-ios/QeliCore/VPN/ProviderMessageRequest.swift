import Foundation

/// Bounds the Swift caller's wait, not the lifetime of an already-issued OS message.
@MainActor
enum ProviderMessageRequest {
    enum RequestError: Error { case timedOut }

    static func send(
        timeoutNanoseconds: UInt64,
        operation: @MainActor (@escaping (Data?) -> Void) throws -> Void
    ) async throws -> Data? {
        try Task.checkCancellation()
        guard timeoutNanoseconds > 0 else { throw RequestError.timedOut }
        let completion = AsyncResultCompletion<Data?>()
        let timeout = Task {
            do { try await Task.sleep(nanoseconds: timeoutNanoseconds) }
            catch { return }
            completion.finish(.failure(RequestError.timedOut))
        }
        defer { timeout.cancel() }
        let result = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                completion.park(continuation)
                guard !Task.isCancelled else {
                    completion.finish(.failure(CancellationError()))
                    return
                }
                do {
                    try operation { data in completion.finish(.success(data)) }
                } catch {
                    completion.finish(.failure(error))
                }
            }
        } onCancel: {
            completion.finish(.failure(CancellationError()))
        }
        try Task.checkCancellation()
        return try result.get()
    }
}
