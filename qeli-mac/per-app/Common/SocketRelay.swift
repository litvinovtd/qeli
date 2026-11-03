import Darwin
import Foundation
import NetworkExtension

enum RelayError: LocalizedError {
    case badEndpoint
    case resolveFailed(String)
    case socketFailed(String, Int32)
    case noTunnelDNS
    case destinationBlocked
    case stalePolicy

    var errorDescription: String? {
        switch self {
        case .badEndpoint: return "unsupported flow endpoint"
        case .resolveFailed(let host): return "could not resolve \(host) through tunnel DNS"
        case .socketFailed(let step, let code): return "socket \(step) failed (errno \(code))"
        case .noTunnelDNS: return "hostname flow has no tunnel DNS server"
        case .destinationBlocked: return "destination blocked by qeli routing policy"
        case .stalePolicy: return "flow routing policy was retired"
        }
    }
}

private func socketError(_ step: String, code: Int32 = errno) -> RelayError {
    .socketFailed(step, code)
}

private func waitSocket(_ fd: Int32, events: Int16, deadline: RelayDeadline, lifetime: RelayLifetime) throws {
    while true {
        try lifetime.check(deadline)
        var descriptor = pollfd(fd: fd, events: events, revents: 0)
        let rc = Darwin.poll(&descriptor, 1, deadline.waitSlice())
        if rc < 0 {
            if errno == EINTR { continue }
            throw socketError("poll")
        }
        if rc == 0 { continue }
        if descriptor.revents & Int16(POLLNVAL) != 0 { throw socketError("poll descriptor", code: EBADF) }
        if descriptor.revents & (events | Int16(POLLERR) | Int16(POLLHUP)) != 0 { return }
    }
}

private func connectSocket(_ fd: Int32, endpoint: inout SocketEndpoint,
                           deadline: RelayDeadline, lifetime: RelayLifetime) throws {
    try lifetime.check(deadline)
    if withSockAddr(&endpoint, { Darwin.connect(fd, $0, $1) }) == 0 { return }
    let code = errno
    guard code == EINPROGRESS || code == EINTR || code == EALREADY else {
        throw socketError("connect", code: code)
    }
    try waitSocket(fd, events: Int16(POLLOUT), deadline: deadline, lifetime: lifetime)
    try lifetime.check(deadline)
    var error: Int32 = 0
    var length = socklen_t(MemoryLayout.size(ofValue: error))
    guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 else { throw socketError("SO_ERROR") }
    guard error == 0 else { throw socketError("connect", code: error) }
}

struct SocketEndpoint {
    var storage: sockaddr_storage
    var length: socklen_t
    var family: Int32
    var host: String
    var port: UInt16

    static func resolveAll(
        host: String,
        port: UInt16,
        socketType: Int32,
        interface: String?,
        dnsServers: [String], deadline: RelayDeadline, lifetime: RelayLifetime
    ) throws -> [SocketEndpoint] {
        try lifetime.check(deadline)
        let numeric = numericResolve(host: host, port: port, socketType: socketType)
        if !numeric.isEmpty { return numeric }
        guard let interface, !dnsServers.isEmpty else {
            throw interface == nil ? RelayError.resolveFailed(host) : RelayError.noTunnelDNS
        }
        let resolved = try TunnelDNSResolver.resolveAddresses(
            name: host, servers: dnsServers, interface: interface, deadline: deadline, lifetime: lifetime)
        let endpoints = resolved.flatMap {
            numericResolve(host: $0, port: port, socketType: socketType)
        }
        guard !endpoints.isEmpty else {
            throw RelayError.resolveFailed(host)
        }
        return endpoints
    }

    static func numericResolve(host: String, port: UInt16, socketType: Int32) -> [SocketEndpoint] {
        var hints = addrinfo(
            ai_flags: AI_NUMERICHOST | AI_NUMERICSERV,
            ai_family: AF_UNSPEC,
            ai_socktype: socketType,
            ai_protocol: socketType == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP,
            ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var head: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &head) == 0, let first = head else {
            return []
        }
        defer { freeaddrinfo(first) }
        var results: [SocketEndpoint] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let item = cursor?.pointee {
            if let address = item.ai_addr {
                var storage = sockaddr_storage()
                memcpy(&storage, address, Int(item.ai_addrlen))
                results.append(SocketEndpoint(
                    storage: storage, length: item.ai_addrlen, family: item.ai_family,
                    host: host, port: port))
            }
            cursor = item.ai_next
        }
        return results
    }

}

func flowEndpoint(_ endpoint: NetworkExtension.NWEndpoint) -> (host: String, port: UInt16)? {
    guard let endpoint = endpoint as? NWHostEndpoint,
          let port = UInt16(endpoint.port) else { return nil }
    return (endpoint.hostname, port)
}

private func withSockAddr<T>(_ endpoint: inout SocketEndpoint,
                             _ body: (UnsafePointer<sockaddr>, socklen_t) -> T) -> T {
    let length = endpoint.length
    return withUnsafePointer(to: &endpoint.storage) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            body($0, length)
        }
    }
}

private func bindSocket(_ fd: Int32, family: Int32, to interface: String?) throws {
    guard let interface else { return }
    var index = if_nametoindex(interface)
    guard index != 0 else { throw socketError("if_nametoindex") }
    let rc: Int32
    if family == AF_INET6 {
        rc = setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &index,
                        socklen_t(MemoryLayout.size(ofValue: index)))
    } else {
        rc = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index,
                        socklen_t(MemoryLayout.size(ofValue: index)))
    }
    guard rc == 0 else { throw socketError("IP_BOUND_IF") }
}

private func makeSocket(family: Int32, type: Int32, interface: String?) throws -> Int32 {
    let proto = type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP
    let fd = Darwin.socket(family, type, proto)
    guard fd >= 0 else { throw socketError("create") }
    do {
        var one: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one,
                         socklen_t(MemoryLayout.size(ofValue: one))) == 0 else { throw socketError("SO_NOSIGPIPE") }
        let flags = fcntl(fd, F_GETFL)
        let descriptorFlags = fcntl(fd, F_GETFD)
        guard flags >= 0, descriptorFlags >= 0,
              fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
              fcntl(fd, F_SETFD, descriptorFlags | FD_CLOEXEC) == 0 else { throw socketError("nonblocking/CLOEXEC") }
        try bindSocket(fd, family: family, to: interface)
        return fd
    } catch {
        Darwin.close(fd)
        throw error
    }
}

final class TCPRelay: RelayClosable {
    let id = UUID()
    private let flow: NEAppProxyTCPFlow
    private let remote: NetworkExtension.NWEndpoint
    private let interface: String?
    private let dnsServers: [String]
    private let overrideHosts: [String]
    private let destinationPolicy: ((String) -> DestinationDecision)?
    private let registry: RelayRegistry
    private let generation: UInt64
    private let queue = DispatchQueue(label: "ru.qeli.perapp.tcp", qos: .userInitiated)
    private let lifetime = RelayLifetime()
    // Queue-confined: all native calls, source events and disposal use this queue.
    private var fd: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var readPaused = false
    private var directions = RelayDuplex()
    private var writeWatchdog: DispatchSourceTimer?
    private let releases = DispatchGroup()

    init(flow: NEAppProxyTCPFlow, remote: NetworkExtension.NWEndpoint, interface: String?,
         dnsServers: [String], overrideHosts: [String],
         destinationPolicy: ((String) -> DestinationDecision)? = nil,
         registry: RelayRegistry, generation: UInt64) {
        self.flow = flow; self.remote = remote; self.interface = interface
        self.dnsServers = dnsServers; self.overrideHosts = overrideHosts
        self.destinationPolicy = destinationPolicy; self.registry = registry; self.generation = generation
    }
    func start() {
        guard registry.add(self, id: id, generation: generation) else { stop(RelayError.stalePolicy); return }
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            guard let self else { return }
            if let error { self.stop(error); return }
            self.queue.async { self.connectAndRun() }
        }
    }
    private func connectAndRun() {
        do {
            try lifetime.check()
            guard let parsed = flowEndpoint(remote) else { throw RelayError.badEndpoint }
            let socket = try connectFirst(parsed)
            do {
                try lifetime.publish { fd = socket; installReadSource(socket) }
            } catch { Darwin.close(socket); throw error } // Never published, no source owns it.
            readFromFlow()
        } catch { stop(error) }
    }
    private func connectFirst(_ parsed: (host: String, port: UInt16)) throws -> Int32 {
        let deadline = RelayDeadline(milliseconds: 10_000)
        let candidates = overrideHosts.isEmpty ? [parsed.host] : overrideHosts
        var lastError: Error = RelayError.resolveFailed(parsed.host)
        for host in candidates {
            try lifetime.check(deadline)
            do {
                let endpoints = try SocketEndpoint.resolveAll(host: host, port: parsed.port,
                    socketType: SOCK_STREAM, interface: interface, dnsServers: dnsServers,
                    deadline: deadline, lifetime: lifetime)
                for var endpoint in endpoints {
                    try lifetime.check(deadline)
                    let decision = destinationPolicy?(endpoint.host) ?? .tunnel
                    if decision == .drop { lastError = RelayError.destinationBlocked; continue }
                    let socket = try makeSocket(family: endpoint.family, type: SOCK_STREAM,
                        interface: decision == .bypass ? nil : interface)
                    do {
                        try connectSocket(socket, endpoint: &endpoint, deadline: deadline, lifetime: lifetime)
                        return socket
                    } catch { lastError = error; Darwin.close(socket) }
                }
            } catch { lastError = error }
        }
        try lifetime.check(deadline)
        throw lastError
    }
    private func installReadSource(_ socket: Int32) {
        let source = DispatchSource.makeReadSource(fileDescriptor: socket, queue: queue)
        source.setEventHandler { [weak self] in self?.readFromSocket() }
        releases.enter()
        let releases = self.releases
        source.setCancelHandler { Darwin.close(socket); releases.leave() }
        readSource = source
        source.resume()
    }
    private func readFromSocket() {
        guard !lifetime.isStopped, !readPaused, fd >= 0 else { return }
        var buffer = [UInt8](repeating: 0, count: 65_536)
        let count = Darwin.recv(fd, &buffer, buffer.count, MSG_DONTWAIT)
        if count < 0 {
            if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR { stop(socketError("recv")) }
            return
        }
        if count == 0 {
            // Keep the socket/source owned for app-to-server traffic. A suspended
            // EOF source avoids a busy loop and is resumed only for final cancel.
            readPaused = true; readSource?.suspend()
            directions.end(.inbound); flow.closeWriteWithError(nil)
            if directions.finished { stop(nil) }
            return
        }
        readPaused = true; readSource?.suspend()
        guard let serial = lifetime.beginWrite() else { return }
        ensureWriteWatchdog()
        flow.write(Data(buffer[0..<count])) { [weak self] error in
            guard let self else { return }
            if let error { self.stop(error); return }
            guard self.lifetime.completeWrite(serial) else { return }
            self.queue.async {
                guard !self.lifetime.isStopped, !self.directions.inboundEnded, self.readPaused else { return }
                self.readPaused = false; self.readSource?.resume()
            }
        }
    }
    private func readFromFlow() {
        guard !lifetime.isStopped, !directions.outboundEnded else { return }
        flow.readData { [weak self] data, error in
            guard let self else { return }
            if let error { self.stop(error); return }
            self.queue.async {
                guard !self.lifetime.isStopped, !self.directions.outboundEnded else { return }
                guard let data, !data.isEmpty else {
                    // Propagate app EOF as FIN, preserving the server response.
                    if shutdown(self.fd, SHUT_WR) != 0 { self.stop(socketError("shutdown write")); return }
                    self.directions.end(.outbound); self.flow.closeReadWithError(nil)
                    if self.directions.finished { self.stop(nil) }
                    return
                }
                do { try self.sendAll(data); self.readFromFlow() }
                catch { self.stop(error) }
            }
        }
    }
    private func sendAll(_ data: Data) throws {
        let deadline = RelayDeadline(milliseconds: 5_000)
        var offset = 0
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            while offset < data.count {
                try lifetime.check(deadline)
                let sent = Darwin.send(fd, base.advanced(by: offset), data.count - offset, 0)
                if sent < 0 {
                    if errno == EINTR { continue }
                    if errno == EAGAIN || errno == EWOULDBLOCK {
                        try waitSocket(fd, events: Int16(POLLOUT), deadline: deadline, lifetime: lifetime); continue
                    }
                    throw socketError("send")
                }
                guard sent > 0 else { throw socketError("send zero", code: EPIPE) }
                offset += sent
            }
        }
    }
    private func ensureWriteWatchdog() {
        guard writeWatchdog == nil else { return }
        // One timer per relay, not one delayed closure per received packet.
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .userInitiated))
        timer.setEventHandler { [weak self] in
            guard let self, let serial = self.lifetime.expiredWrite() else { return }
            self.stop(RelayWorkError.timedOut, pendingWrite: serial)
        }
        timer.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
        writeWatchdog = timer; timer.resume()
    }
    func stop(_ error: Error?) { stop(error, pendingWrite: nil) }
    private func stop(_ error: Error?, pendingWrite: UInt64?) {
        guard lifetime.stop(writeTicket: pendingWrite) else { return }
        queue.async {
            self.writeWatchdog?.cancel(); self.writeWatchdog = nil
            let socket = self.fd; self.fd = -1
            if socket >= 0 { _ = shutdown(socket, SHUT_RDWR) }
            if let source = self.readSource {
                source.cancel()
                if self.readPaused { self.readPaused = false; source.resume() }
                self.readSource = nil // fd closes in the cancellation handler only.
            }
            if !self.directions.outboundEnded { self.flow.closeReadWithError(error) }
            if !self.directions.inboundEnded { self.flow.closeWriteWithError(error) }
            self.releases.notify(queue: self.queue) { self.registry.remove(self.id) }
        }
    }
}

final class UDPRelay: RelayClosable {
    let id = UUID()
    private let flow: NEAppProxyUDPFlow
    private let interface: String?
    private let dnsServers: [String]
    private let overrideHosts: [String]
    private let destinationPolicy: ((String) -> DestinationDecision)?
    private let registry: RelayRegistry
    private let generation: UInt64
    private let queue = DispatchQueue(label: "ru.qeli.perapp.udp", qos: .userInitiated)
    private let lifetime = RelayLifetime()
    private let releases = DispatchGroup()
    private var sockets: [Int64: Int32] = [:]
    private var sources: [Int64: DispatchSourceRead] = [:]
    private var dnsOrigins: [DNSOriginKey: DNSOrigin] = [:]
    private var readPaused = false
    private var writeWatchdog: DispatchSourceTimer?

    init(flow: NEAppProxyUDPFlow, interface: String?, dnsServers: [String],
         overrideHosts: [String], destinationPolicy: ((String) -> DestinationDecision)? = nil,
         registry: RelayRegistry, generation: UInt64) {
        self.flow = flow; self.interface = interface; self.dnsServers = dnsServers
        self.overrideHosts = overrideHosts; self.destinationPolicy = destinationPolicy
        self.registry = registry; self.generation = generation
    }
    func start() {
        guard registry.add(self, id: id, generation: generation) else { stop(RelayError.stalePolicy); return }
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            guard let self else { return }
            if let error { self.stop(error); return }
            self.queue.async { self.readFromFlow() }
        }
    }
    private func readFromFlow() {
        guard !lifetime.isStopped else { return }
        flow.readDatagrams { [weak self] (datagrams: [Data]?, endpoints: [NetworkExtension.NWEndpoint]?, error: Error?) in
            guard let self else { return }
            if let error { self.stop(error); return }
            guard let datagrams, let endpoints, !datagrams.isEmpty else { self.stop(nil); return }
            guard datagrams.count == endpoints.count else { self.stop(RelayError.badEndpoint); return }
            self.queue.async {
                do {
                    let deadline = RelayDeadline(milliseconds: 5_000)
                    for (data, remote) in zip(datagrams, endpoints) { try self.send(data, to: remote, deadline: deadline) }
                    self.readFromFlow()
                } catch { self.stop(error) }
            }
        }
    }
    private func send(_ data: Data, to remote: NetworkExtension.NWEndpoint, deadline: RelayDeadline) throws {
        try lifetime.check(deadline)
        guard let parsed = flowEndpoint(remote) else { throw RelayError.badEndpoint }
        let targetHost: String
        if overrideHosts.isEmpty { targetHost = parsed.host }
        else {
            guard let transaction = dnsTransactionId(data) else { throw RelayError.badEndpoint }
            targetHost = overrideHosts[stableResolverIndex(transaction: transaction, originalHost: parsed.host,
                originalPort: parsed.port, count: overrideHosts.count)]
        }
        let initialDecision = destinationPolicy?(targetHost) ?? .tunnel
        if initialDecision == .drop { return }
        let endpoints = try SocketEndpoint.resolveAll(host: targetHost, port: parsed.port, socketType: SOCK_DGRAM,
            interface: initialDecision == .bypass ? nil : interface, dnsServers: dnsServers,
            deadline: deadline, lifetime: lifetime)
        var lastError: Error?
        var allowedCandidate = false
        for var endpoint in endpoints {
            try lifetime.check(deadline)
            let decision = destinationPolicy?(endpoint.host) ?? initialDecision
            if decision == .drop { continue }
            allowedCandidate = true
            do {
                let socket = try socketForFamily(endpoint.family, interface: decision == .bypass ? nil : interface)
                let key = overrideHosts.isEmpty ? nil : makeDNSOriginKey(socket: socket, endpoint: &endpoint, data: data)
                if let key { rememberDNSOrigin(key, endpoint: remote) }
                do {
                    while true {
                        try lifetime.check(deadline)
                        let count = data.withUnsafeBytes { raw in
                            withSockAddr(&endpoint) { Darwin.sendto(socket, raw.baseAddress, data.count, 0, $0, $1) }
                        }
                        if count == data.count { return } // Includes a valid empty datagram.
                        if count < 0 && errno == EINTR { continue }
                        if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                            try waitSocket(socket, events: Int16(POLLOUT), deadline: deadline, lifetime: lifetime); continue
                        }
                        throw socketError("sendto")
                    }
                } catch { if let key { forgetDNSOrigin(key) }; throw error }
            } catch { lastError = error }
        }
        try lifetime.check(deadline)
        if !allowedCandidate { return }
        throw lastError ?? socketError("sendto")
    }
    private func socketForFamily(_ family: Int32, interface: String?) throws -> Int32 {
        try lifetime.check()
        let key = (Int64(family) << 1) | (interface == nil ? 0 : 1)
        if let existing = sockets[key] { return existing }
        let socket = try makeSocket(family: family, type: SOCK_DGRAM, interface: interface)
        do {
            return try lifetime.publish {
                let source = DispatchSource.makeReadSource(fileDescriptor: socket, queue: queue)
                source.setEventHandler { [weak self] in self?.readFromSocket(socket) }
                releases.enter(); let releases = self.releases
                source.setCancelHandler { Darwin.close(socket); releases.leave() }
                sockets[key] = socket; sources[key] = source
                source.resume(); if readPaused { source.suspend() }
                return socket
            }
        } catch { Darwin.close(socket); throw error }
    }
    private func readFromSocket(_ socket: Int32) {
        guard !lifetime.isStopped, !readPaused else { return }
        var buffer = [UInt8](repeating: 0, count: 65_536)
        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let count = withUnsafeMutablePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.recvfrom(socket, &buffer, buffer.count, MSG_DONTWAIT, $0, &length)
            }
        }
        if count < 0 {
            if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR { stop(socketError("recvfrom")) }
            return
        }
        guard let remote = endpointFrom(storage: storage, length: length) else { return }
        let response = Data(buffer[0..<count]) // Zero bytes are data, not UDP EOF.
        let source: NetworkExtension.NWEndpoint
        if overrideHosts.isEmpty { source = remote }
        else {
            guard let key = makeDNSOriginKey(socket: socket, storage: &storage, length: length, data: response),
                  let original = takeDNSOrigin(key) else { return }
            source = original
        }
        readPaused = true; sources.values.forEach { $0.suspend() }
        guard let serial = lifetime.beginWrite() else { return }
        ensureWriteWatchdog()
        flow.writeDatagrams([response], sentBy: [source]) { [weak self] error in
            guard let self else { return }
            if let error { self.stop(error); return }
            guard self.lifetime.completeWrite(serial) else { return }
            self.queue.async {
                guard !self.lifetime.isStopped, self.readPaused else { return }
                self.readPaused = false; self.sources.values.forEach { $0.resume() }
            }
        }
    }
    private func ensureWriteWatchdog() {
        guard writeWatchdog == nil else { return }
        // One timer per relay, not one delayed closure per received packet.
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .userInitiated))
        timer.setEventHandler { [weak self] in
            guard let self, let serial = self.lifetime.expiredWrite() else { return }
            self.stop(RelayWorkError.timedOut, pendingWrite: serial)
        }
        timer.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
        writeWatchdog = timer; timer.resume()
    }
    func stop(_ error: Error?) { stop(error, pendingWrite: nil) }
    private func stop(_ error: Error?, pendingWrite: UInt64?) {
        guard lifetime.stop(writeTicket: pendingWrite) else { return }
        queue.async {
            self.writeWatchdog?.cancel(); self.writeWatchdog = nil
            for source in self.sources.values {
                source.cancel(); if self.readPaused { source.resume() }
            }
            self.readPaused = false
            self.sockets.removeAll(); self.sources.removeAll(); self.dnsOrigins.removeAll()
            self.flow.closeReadWithError(error); self.flow.closeWriteWithError(error)
            self.releases.notify(queue: self.queue) { self.registry.remove(self.id) }
        }
    }

    private func rememberDNSOrigin(_ key: DNSOriginKey,
                                   endpoint: NetworkExtension.NWEndpoint) {
        let now = Date()
        dnsOrigins = dnsOrigins.filter { $0.value.expires > now }
        if dnsOrigins.count >= 4096, let oldest = dnsOrigins.min(by: {
            $0.value.expires < $1.value.expires })?.key {
            dnsOrigins.removeValue(forKey: oldest)
        }
        dnsOrigins[key] = DNSOrigin(endpoint: endpoint, expires: now.addingTimeInterval(30))
    }

    private func forgetDNSOrigin(_ key: DNSOriginKey) {
        dnsOrigins.removeValue(forKey: key)
    }

    private func takeDNSOrigin(_ key: DNSOriginKey) -> NetworkExtension.NWEndpoint? {
        let now = Date()
        let value = dnsOrigins.removeValue(forKey: key)
        if dnsOrigins.count > 512 { dnsOrigins = dnsOrigins.filter { $0.value.expires > now } }
        guard let value, value.expires > now else { return nil }
        return value.endpoint
    }
}

private struct DNSOriginKey: Hashable {
    let socket: Int32
    let resolver: String
    let transaction: UInt16
}

private struct DNSOrigin {
    let endpoint: NetworkExtension.NWEndpoint
    let expires: Date
}

private func dnsTransactionId(_ data: Data) -> UInt16? {
    guard data.count >= 2 else { return nil }
    return data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> UInt16 in
        let bytes = raw.bindMemory(to: UInt8.self)
        return UInt16(bytes[0]) << 8 | UInt16(bytes[1])
    }
}

private func stableResolverIndex(
    transaction: UInt16, originalHost: String, originalPort: UInt16, count: Int
) -> Int {
    var hash: UInt32 = 2_166_136_261
    func add(_ byte: UInt8) { hash ^= UInt32(byte); hash &*= 16_777_619 }
    add(UInt8(transaction >> 8)); add(UInt8(transaction & 0xff))
    for byte in originalHost.utf8 { add(byte) }
    add(UInt8(originalPort >> 8)); add(UInt8(originalPort & 0xff))
    return Int(hash % UInt32(count))
}

private func makeDNSOriginKey(
    socket: Int32, endpoint: inout SocketEndpoint, data: Data
) -> DNSOriginKey? {
    withSockAddr(&endpoint) { address, length in
        makeDNSOriginKey(socket: socket, address: address, length: length, data: data)
    }
}

private func makeDNSOriginKey(
    socket: Int32, storage: inout sockaddr_storage, length: socklen_t, data: Data
) -> DNSOriginKey? {
    withUnsafePointer(to: &storage) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            makeDNSOriginKey(socket: socket, address: $0, length: length, data: data)
        }
    }
}

private func makeDNSOriginKey(
    socket: Int32, address: UnsafePointer<sockaddr>, length: socklen_t, data: Data
) -> DNSOriginKey? {
    guard let transaction = dnsTransactionId(data) else { return nil }
    var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
    var service = [CChar](repeating: 0, count: Int(NI_MAXSERV))
    guard getnameinfo(address, length, &host, socklen_t(host.count), &service,
                      socklen_t(service.count), NI_NUMERICHOST | NI_NUMERICSERV) == 0 else {
        return nil
    }
    return DNSOriginKey(socket: socket,
                        resolver: "\(String(cString: host))#\(String(cString: service))",
                        transaction: transaction)
}

private func endpointFrom(storage: sockaddr_storage, length: socklen_t)
    -> NetworkExtension.NWEndpoint? {
    var value = storage
    var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
    var service = [CChar](repeating: 0, count: Int(NI_MAXSERV))
    let rc = withUnsafePointer(to: &value) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            getnameinfo($0, length, &host, socklen_t(host.count), &service,
                        socklen_t(service.count), NI_NUMERICHOST | NI_NUMERICSERV)
        }
    }
    guard rc == 0, UInt16(String(cString: service)) != nil else { return nil }
    return NWHostEndpoint(hostname: String(cString: host), port: String(cString: service))
}

private enum TunnelDNSResolver {
    static func resolveAddresses(
        name: String, servers: [String], interface: String, deadline: RelayDeadline, lifetime: RelayLifetime
    ) throws -> [String] {
        for server in servers {
            try lifetime.check(deadline)
            var result: [String] = []
            for type in [UInt16(1), UInt16(28)] {
                try lifetime.check(deadline)
                if let addresses = try? query(
                    name: name, type: type, server: server, interface: interface,
                    deadline: deadline.capped(milliseconds: 2_000), lifetime: lifetime
                ) {
                    result.append(contentsOf: addresses)
                }
            }
            if !result.isEmpty {
                var seen = Set<String>()
                return result.filter { seen.insert($0).inserted }
            }
        }
        throw RelayError.resolveFailed(name)
    }

    private static func query(
        name: String, type: UInt16, server: String, interface: String, deadline: RelayDeadline, lifetime: RelayLifetime
    ) throws -> [String] {
        try lifetime.check(deadline)
        guard var endpoint = SocketEndpoint.numericResolve(
            host: server, port: 53, socketType: SOCK_DGRAM).first else {
            throw RelayError.resolveFailed(server)
        }
        let fd = try makeSocket(family: endpoint.family, type: SOCK_DGRAM,
                                interface: interface)
        defer { Darwin.close(fd) }
        let id = UInt16.random(in: 1...UInt16.max)
        let packet = try makeQuery(name: name, type: type, id: id)
        try connectSocket(fd, endpoint: &endpoint, deadline: deadline, lifetime: lifetime)
        while true {
            try lifetime.check(deadline)
            let sent = packet.withUnsafeBytes { raw in Darwin.send(fd, raw.baseAddress, packet.count, 0) }
            if sent == packet.count { break }
            if sent < 0 && errno == EINTR { continue }
            if sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                try waitSocket(fd, events: Int16(POLLOUT), deadline: deadline, lifetime: lifetime); continue
            }
            throw socketError("DNS send")
        }
        var answer = [UInt8](repeating: 0, count: 4096)
        var count: Int = 0
        while true {
            try waitSocket(fd, events: Int16(POLLIN), deadline: deadline, lifetime: lifetime)
            try lifetime.check(deadline)
            count = Darwin.recv(fd, &answer, answer.count, 0)
            if count > 0 { break }
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) { continue }
            throw socketError("DNS recv")
        }
        return parseAddresses(Data(answer[0..<count]), id: id, type: type)
    }

    private static func makeQuery(name: String, type: UInt16, id: UInt16) throws -> Data {
        let absolute = name.hasSuffix(".") ? String(name.dropLast()) : name
        let labels = absolute.split(separator: ".", omittingEmptySubsequences: false)
        let qnameLength = 1 + labels.reduce(0) { $0 + 1 + $1.utf8.count }
        guard !labels.isEmpty,
              labels.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 63 }),
              qnameLength <= 255 else {
            throw RelayError.resolveFailed(name)
        }
        var bytes: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00,
                              0x00, 0x01, 0, 0, 0, 0, 0, 0]
        for label in labels {
            bytes.append(UInt8(label.utf8.count))
            bytes.append(contentsOf: label.utf8)
        }
        // Root-label terminator, QTYPE, QCLASS=IN. Omitting the first zero changes the first
        // QTYPE byte into a label length and makes every A/AAAA request malformed.
        bytes += [0, UInt8(type >> 8), UInt8(type & 0xff), 0, 1]
        return Data(bytes)
    }

    private static func parseAddresses(_ data: Data, id: UInt16, type expectedType: UInt16)
        -> [String] {
        let b = [UInt8](data)
        guard b.count >= 12, UInt16(b[0]) << 8 | UInt16(b[1]) == id,
              b[2] & 0x80 != 0, b[2] & 0x78 == 0, b[2] & 0x02 == 0,
              b[3] & 0x0f == 0 else { return [] }
        let questions = Int(UInt16(b[4]) << 8 | UInt16(b[5]))
        let answers = Int(UInt16(b[6]) << 8 | UInt16(b[7]))
        guard questions == 1 else { return [] }
        var offset = 12
        guard skipName(b, &offset), offset + 4 <= b.count else { return [] }
        let questionType = UInt16(b[offset]) << 8 | UInt16(b[offset + 1])
        let questionClass = UInt16(b[offset + 2]) << 8 | UInt16(b[offset + 3])
        guard questionType == expectedType, questionClass == 1 else { return [] }
        offset += 4
        var result: [String] = []
        for _ in 0..<answers {
            guard skipName(b, &offset), offset + 10 <= b.count else { break }
            let type = UInt16(b[offset]) << 8 | UInt16(b[offset + 1])
            let klass = UInt16(b[offset + 2]) << 8 | UInt16(b[offset + 3])
            let length = Int(UInt16(b[offset + 8]) << 8 | UInt16(b[offset + 9])); offset += 10
            guard offset + length <= b.count else { break }
            if type == expectedType && klass == 1 && length == 4 && type == 1 {
                result.append("\(b[offset]).\(b[offset+1]).\(b[offset+2]).\(b[offset+3])")
            } else if type == expectedType && klass == 1 && length == 16 && type == 28 {
                result.append(stride(from: 0, to: 16, by: 2).map {
                    String(format: "%x", UInt16(b[offset + $0]) << 8 | UInt16(b[offset + $0 + 1]))
                }.joined(separator: ":"))
            }
            offset += length
        }
        return result
    }

    private static func skipName(_ bytes: [UInt8], _ offset: inout Int) -> Bool {
        while offset < bytes.count {
            let length = Int(bytes[offset]); offset += 1
            if length == 0 { return true }
            if length & 0xc0 == 0xc0 { offset += 1; return offset <= bytes.count }
            offset += length
        }
        return false
    }
}
