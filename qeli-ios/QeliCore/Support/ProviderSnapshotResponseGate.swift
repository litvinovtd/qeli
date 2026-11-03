/// Orders asynchronous provider replies and invalidates replies across tunnel transitions.
/// The container's MainActor owns this value; no provider callback mutates it directly.
struct ProviderSnapshotResponseGate {
    struct Token: Equatable {
        fileprivate let epoch: UInt64
        fileprivate let sequence: UInt64
    }

    private var epoch: UInt64 = 0
    private var issued: UInt64 = 0
    private var accepted: UInt64 = 0
    private var polling: Token?

    mutating func invalidate() {
        epoch &+= 1
        issued = 0
        accepted = 0
        polling = nil
    }

    mutating func issue() -> Token {
        issued &+= 1
        return Token(epoch: epoch, sequence: issued)
    }

    func isCurrent(_ token: Token) -> Bool {
        token.epoch == epoch && token.sequence <= issued
    }

    /// One unfinished poll per status epoch. A missing callback cannot grow the queue.
    mutating func beginPolling() -> Token? {
        guard polling == nil else { return nil }
        let token = issue()
        polling = token
        return token
    }

    mutating func finishPolling(_ token: Token) -> Bool {
        guard polling == token else { return false }
        polling = nil
        return isCurrent(token)
    }

    mutating func accept(_ token: Token) -> Bool {
        guard token.epoch == epoch, token.sequence > accepted,
              token.sequence <= issued else { return false }
        accepted = token.sequence
        return true
    }
}
