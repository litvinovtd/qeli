import Foundation

protocol RelayClosable: AnyObject { func stop(_ error: Error?) }

/// A flow classifies against one policy generation before asynchronous open/connect.
/// Retiring that policy must also refuse its delayed registrations after closeAll.
final class RelayRegistry {
    private let lock = NSLock()
    private var epoch: UInt64 = 0
    private var flows: [UUID: RelayClosable] = [:]

    var generation: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return epoch
    }

    func add(_ relay: RelayClosable, id: UUID, generation: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard generation == epoch else { return false }
        flows[id] = relay
        return true
    }

    func remove(_ id: UUID) {
        lock.lock(); flows.removeValue(forKey: id); lock.unlock()
    }

    func retire() -> [RelayClosable] {
        lock.lock()
        epoch &+= 1
        let retired = Array(flows.values)
        flows.removeAll()
        lock.unlock()
        return retired
    }

    func closeAll() {
        // stop may invoke framework callbacks: retire under lock, close after release.
        for relay in retire() { relay.stop(nil) }
    }
}
