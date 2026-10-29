/// Carries a failed initial lookup into the ordinary reconnect supervisor after the
/// bootstrap TUN is installed. Cancellation is never converted into a retryable failure.
struct InitialCarrierResolution {
    let addresses: [String]
    let failure: Error?

    static func capture(
        _ resolve: () async throws -> [String]
    ) async throws -> InitialCarrierResolution {
        try Task.checkCancellation()
        do {
            let addresses = try await resolve()
            try Task.checkCancellation()
            return InitialCarrierResolution(addresses: addresses, failure: nil)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            try Task.checkCancellation()
            return InitialCarrierResolution(addresses: [], failure: error)
        }
    }

    static func resolveRetry(
        lastKnown: [String],
        system: () async throws -> [String],
        scoped: () async throws -> [String]
    ) async throws -> [String] {
        try Task.checkCancellation()
        // With no carrier cache, the bootstrap TUN may capture system DNS. Require a
        // physical-interface-scoped lookup so the recovery cannot depend on that TUN.
        let addresses = try await (lastKnown.isEmpty ? scoped() : system())
        try Task.checkCancellation()
        return addresses
    }
}
