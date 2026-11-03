import Foundation

// The latch is the only cross-queue state. Descriptor/source ownership stays on a
// relay's serial queue; stop cannot race a publication through this gate.
enum RelayWorkError: Error { case stopped, timedOut }

final class RelayLifetime {
    private let lock = NSLock()
    private var stopped = false
    private var writeSerial: UInt64 = 0
    private var pendingWrite: UInt64?
    private var writeExpiry: UInt64 = 0
    var isStopped: Bool { lock.lock(); defer { lock.unlock() }; return stopped }
    @discardableResult func stop(writeTicket: UInt64? = nil) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if stopped || (writeTicket != nil && pendingWrite != writeTicket) { return false }
        stopped = true; return true
    }
    func beginWrite(now: UInt64 = DispatchTime.now().uptimeNanoseconds) -> UInt64? {
        lock.lock(); defer { lock.unlock() }
        guard !stopped else { return nil }
        writeSerial &+= 1; pendingWrite = writeSerial
        writeExpiry = now + 10_000_000_000; return writeSerial
    }
    func expiredWrite(now: UInt64 = DispatchTime.now().uptimeNanoseconds) -> UInt64? {
        lock.lock(); defer { lock.unlock() }
        guard !stopped, pendingWrite != nil, now >= writeExpiry else { return nil }
        return pendingWrite
    }
    func completeWrite(_ serial: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !stopped, pendingWrite == serial else { return false }
        pendingWrite = nil; return true
    }
    func check(_ deadline: RelayDeadline? = nil) throws {
        guard !isStopped else { throw RelayWorkError.stopped }
        try deadline?.check()
    }
    func publish<T>(_ body: () -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        guard !stopped else { throw RelayWorkError.stopped }
        return body()
    }
}

struct RelayDeadline {
    let expiry: UInt64
    init(milliseconds: UInt64, now: UInt64 = DispatchTime.now().uptimeNanoseconds) {
        precondition(milliseconds > 0 && milliseconds <= 60_000)
        expiry = now + milliseconds * 1_000_000
    }
    private init(expiry: UInt64) { self.expiry = expiry }
    func capped(milliseconds: UInt64, now: UInt64 = DispatchTime.now().uptimeNanoseconds) -> RelayDeadline {
        RelayDeadline(expiry: min(expiry, now + milliseconds * 1_000_000))
    }
    func waitSlice(now: UInt64 = DispatchTime.now().uptimeNanoseconds) -> Int32 {
        guard now < expiry else { return 0 }
        return Int32(min(100, (expiry - now + 999_999) / 1_000_000))
    }
    func check(now: UInt64 = DispatchTime.now().uptimeNanoseconds) throws {
        if now >= expiry { throw RelayWorkError.timedOut }
    }
}

// Queue-confined TCP EOF state: one direction may finish while its peer drains.
struct RelayDuplex {
    enum Direction { case inbound, outbound }
    private(set) var inboundEnded = false
    private(set) var outboundEnded = false
    var finished: Bool { inboundEnded && outboundEnded }
    @discardableResult mutating func end(_ direction: Direction) -> Bool {
        switch direction {
        case .inbound:
            guard !inboundEnded else { return false }
            inboundEnded = true
        case .outbound:
            guard !outboundEnded else { return false }
            outboundEnded = true
        }
        return true
    }
}
