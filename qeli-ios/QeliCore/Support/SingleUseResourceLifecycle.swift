/// A cancelled OS resource must never be started again by a suspended old request.
struct SingleUseResourceLifecycle {
    private(set) var active = false
    private var stopped = false

    mutating func start() -> Bool {
        guard !stopped, !active else { return false }
        active = true
        return true
    }

    /// Returns whether the caller must cancel an active resource.
    mutating func stop() -> Bool {
        let wasActive = active
        stopped = true
        active = false
        return wasActive
    }
}
