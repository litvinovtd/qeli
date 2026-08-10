import Darwin
import Foundation
import NetworkExtension

enum RelayError: LocalizedError {
    case badEndpoint
    case resolveFailed(String)
    case socketFailed(String)
    case noTunnelDNS
    case destinationBlocked

    var errorDescription: String? {
        switch self {
        case .badEndpoint: return "unsupported flow endpoint"
        case .resolveFailed(let host): return "could not resolve \(host) through tunnel DNS"
        case .socketFailed(let step): return "socket \(step) failed (errno \(errno))"
        case .noTunnelDNS: return "hostname flow has no tunnel DNS server"
        case .destinationBlocked: return "destination blocked by qeli routing policy"
        }
    }
}

struct SocketEndpoint {
    var storage: sockaddr_storage
    var length: socklen_t
    var family: Int32
    var host: String
    var port: UInt16

    static func resolve(
        host: String,
        port: UInt16,
        socketType: Int32,
        interface: String?,
        dnsServers: [String]
    ) throws -> SocketEndpoint {
        let numeric = numericResolve(host: host, port: port, socketType: socketType)
        if let first = numeric.first { return first }
        guard let interface, !dnsServers.isEmpty else {
            throw interface == nil ? RelayError.resolveFailed(host) : RelayError.noTunnelDNS
        }
        let resolved = try TunnelDNSResolver.resolveA(
            name: host, servers: dnsServers, interface: interface)
        guard let address = resolved.first,
              let result = numericResolve(host: address, port: port, socketType: socketType).first else {
            throw RelayError.resolveFailed(host)
        }
        return result
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
    withUnsafePointer(to: &endpoint.storage) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            body($0, endpoint.length)
        }
    }
}

private func bindSocket(_ fd: Int32, family: Int32, to interface: String?) throws {
    guard let interface else { return }
    var index = if_nametoindex(interface)
    guard index != 0 else { throw RelayError.socketFailed("if_nametoindex") }
    let rc: Int32
    if family == AF_INET6 {
        rc = setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &index,
                        socklen_t(MemoryLayout.size(ofValue: index)))
    } else {
        rc = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index,
                        socklen_t(MemoryLayout.size(ofValue: index)))
    }
    guard rc == 0 else { throw RelayError.socketFailed("IP_BOUND_IF") }
}

private func makeSocket(family: Int32, type: Int32, interface: String?) throws -> Int32 {
    let proto = type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP
    let fd = Darwin.socket(family, type, proto)
    guard fd >= 0 else { throw RelayError.socketFailed("create") }
    do {
        var one: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one,
                       socklen_t(MemoryLayout.size(ofValue: one)))
        try bindSocket(fd, family: family, to: interface)
        return fd
    } catch {
        Darwin.close(fd)
        throw error
    }
}

private final class FlowLifetime {
    private let lock = NSLock()
    private var flows: [UUID: AnyObject] = [:]
    func retain(_ flow: AnyObject, id: UUID) { lock.lock(); flows[id] = flow; lock.unlock() }
    func release(id: UUID) { lock.lock(); flows.removeValue(forKey: id); lock.unlock() }
    func closeAll() {
        lock.lock(); let values = flows.values; flows.removeAll(); lock.unlock()
        for case let closable as RelayClosable in values { closable.stop(nil) }
    }
}

protocol RelayClosable: AnyObject { func stop(_ error: Error?) }

final class RelayRegistry {
    private let lifetime = FlowLifetime()
    func add(_ relay: RelayClosable, id: UUID) { lifetime.retain(relay, id: id) }
    func remove(_ id: UUID) { lifetime.release(id: id) }
    func closeAll() { lifetime.closeAll() }
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
    private let writeQueue = DispatchQueue(label: "ru.qeli.perapp.tcp.write", qos: .userInitiated)
    private let stateLock = NSLock()
    private var fd: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var inboundWritePending = false
    private var closed = false

    init(flow: NEAppProxyTCPFlow, remote: NetworkExtension.NWEndpoint, interface: String?,
         dnsServers: [String], overrideHosts: [String],
         destinationPolicy: ((String) -> DestinationDecision)? = nil,
         registry: RelayRegistry) {
        self.flow = flow; self.remote = remote; self.interface = interface
        self.dnsServers = dnsServers; self.overrideHosts = overrideHosts
        self.destinationPolicy = destinationPolicy; self.registry = registry
    }

    func start() {
        registry.add(self, id: id)
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            guard let self else { return }
            if let error { self.stop(error); return }
            self.writeQueue.async { self.connectAndRun() }
        }
    }

    private func connectAndRun() {
        do {
            guard let parsed = flowEndpoint(remote) else { throw RelayError.badEndpoint }
            let socket = try connectFirst(parsed)
            stateLock.lock()
            if closed { stateLock.unlock(); Darwin.close(socket); return }
            fd = socket
            stateLock.unlock()
            installReadSource(socket)
            readFromFlow()
        } catch { stop(error) }
    }

    private func connectFirst(_ parsed: (host: String, port: UInt16)) throws -> Int32 {
        let candidates = overrideHosts.isEmpty ? [parsed.host] : overrideHosts
        var lastError: Error = RelayError.resolveFailed(parsed.host)
        for host in candidates {
            do {
                var endpoint = try SocketEndpoint.resolve(
                    host: host, port: parsed.port,
                    socketType: SOCK_STREAM, interface: interface,
                    dnsServers: dnsServers)
                let decision = destinationPolicy?(endpoint.host) ?? .tunnel
                if decision == .drop { throw RelayError.destinationBlocked }
                let boundInterface = decision == .bypass ? nil : interface
                let socket = try makeSocket(
                    family: endpoint.family, type: SOCK_STREAM,
                    interface: boundInterface)
                if withSockAddr(&endpoint, { Darwin.connect(socket, $0, $1) }) == 0 {
                    return socket
                }
                Darwin.close(socket)
                throw RelayError.socketFailed("connect")
            } catch { lastError = error }
        }
        throw lastError
    }

    private func installReadSource(_ socket: Int32) {
        let source = DispatchSource.makeReadSource(fileDescriptor: socket,
                                                   queue: DispatchQueue.global(qos: .userInitiated))
        source.setEventHandler { [weak self] in self?.readFromSocket() }
        stateLock.lock(); readSource = source; stateLock.unlock()
        source.resume()
    }

    private func readFromSocket() {
        stateLock.lock()
        if closed || inboundWritePending { stateLock.unlock(); return }
        let socket = fd; inboundWritePending = true; stateLock.unlock()
        var buffer = [UInt8](repeating: 0, count: 65_536)
        let count = Darwin.recv(socket, &buffer, buffer.count, MSG_DONTWAIT)
        if count <= 0 {
            stateLock.lock(); inboundWritePending = false; stateLock.unlock()
            if count == 0 || errno != EAGAIN { stop(nil) }
            return
        }
        flow.write(Data(buffer[0..<count])) { [weak self] error in
            guard let self else { return }
            self.stateLock.lock(); self.inboundWritePending = false; self.stateLock.unlock()
            if let error { self.stop(error) }
        }
    }

    private func readFromFlow() {
        flow.readData { [weak self] data, error in
            guard let self else { return }
            if let error { self.stop(error); return }
            guard let data, !data.isEmpty else { self.stop(nil); return }
            self.writeQueue.async {
                do { try self.sendAll(data); self.readFromFlow() }
                catch { self.stop(error) }
            }
        }
    }

    private func sendAll(_ data: Data) throws {
        var offset = 0
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            while offset < data.count {
                let sent = Darwin.send(fd, base.advanced(by: offset), data.count - offset, 0)
                if sent < 0 && errno == EINTR { continue }
                guard sent > 0 else { throw RelayError.socketFailed("send") }
                offset += sent
            }
        }
    }

    func stop(_ error: Error?) {
        stateLock.lock()
        if closed { stateLock.unlock(); return }
        closed = true; let socket = fd; fd = -1; let source = readSource; readSource = nil
        stateLock.unlock()
        source?.cancel()
        if socket >= 0 { _ = shutdown(socket, SHUT_RDWR); Darwin.close(socket) }
        flow.closeReadWithError(error); flow.closeWriteWithError(error)
        registry.remove(id)
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
    private let queue = DispatchQueue(label: "ru.qeli.perapp.udp", qos: .userInitiated)
    private let lock = NSLock()
    private var sockets: [Int64: Int32] = [:]
    private var sources: [Int64: DispatchSourceRead] = [:]
    private var overrideIndex = 0
    private var closed = false

    init(flow: NEAppProxyUDPFlow, interface: String?, dnsServers: [String],
         overrideHosts: [String], destinationPolicy: ((String) -> DestinationDecision)? = nil,
         registry: RelayRegistry) {
        self.flow = flow; self.interface = interface; self.dnsServers = dnsServers
        self.overrideHosts = overrideHosts; self.destinationPolicy = destinationPolicy
        self.registry = registry
    }

    func start() {
        registry.add(self, id: id)
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            guard let self else { return }
            if let error { self.stop(error) } else { self.readFromFlow() }
        }
    }

    private func readFromFlow() {
        flow.readDatagrams { [weak self]
            (datagrams: [Data]?, endpoints: [NetworkExtension.NWEndpoint]?, error: Error?) in
            guard let self else { return }
            if let error { self.stop(error); return }
            guard let datagrams, let endpoints, !datagrams.isEmpty else { self.stop(nil); return }
            self.queue.async {
                do {
                    for (data, remote) in zip(datagrams, endpoints) { try self.send(data, to: remote) }
                    self.readFromFlow()
                } catch { self.stop(error) }
            }
        }
    }

    private func send(_ data: Data, to remote: NetworkExtension.NWEndpoint) throws {
        guard let parsed = flowEndpoint(remote) else { throw RelayError.badEndpoint }
        let targetHost: String
        if overrideHosts.isEmpty {
            targetHost = parsed.host
        } else {
            targetHost = overrideHosts[overrideIndex % overrideHosts.count]
            overrideIndex = (overrideIndex + 1) % overrideHosts.count
        }
        let initialDecision = destinationPolicy?(targetHost) ?? .tunnel
        if initialDecision == .drop { return }
        let initialInterface = initialDecision == .bypass ? nil : interface
        var endpoint = try SocketEndpoint.resolve(
            host: targetHost, port: parsed.port,
            socketType: SOCK_DGRAM, interface: initialInterface,
            dnsServers: dnsServers)
        let finalDecision = destinationPolicy?(endpoint.host) ?? initialDecision
        if finalDecision == .drop { return }
        let boundInterface = finalDecision == .bypass ? nil : interface
        let socket = try socketForFamily(endpoint.family, interface: boundInterface)
        let count = data.withUnsafeBytes { raw in
            withSockAddr(&endpoint) { Darwin.sendto(socket, raw.baseAddress, data.count, 0, $0, $1) }
        }
        guard count == data.count else { throw RelayError.socketFailed("sendto") }
    }

    private func socketForFamily(_ family: Int32, interface: String?) throws -> Int32 {
        let key = (Int64(family) << 1) | (interface == nil ? 0 : 1)
        lock.lock()
        if let existing = sockets[key] { lock.unlock(); return existing }
        lock.unlock()
        let socket = try makeSocket(family: family, type: SOCK_DGRAM, interface: interface)
        let source = DispatchSource.makeReadSource(fileDescriptor: socket,
                                                   queue: DispatchQueue.global(qos: .userInitiated))
        source.setEventHandler { [weak self] in self?.readFromSocket(socket) }
        lock.lock(); sockets[key] = socket; sources[key] = source; lock.unlock()
        source.resume()
        return socket
    }

    private func readFromSocket(_ socket: Int32) {
        var buffer = [UInt8](repeating: 0, count: 65_536)
        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let count = withUnsafeMutablePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.recvfrom(socket, &buffer, buffer.count, MSG_DONTWAIT, $0, &length)
            }
        }
        guard count > 0, let remote = endpointFrom(storage: storage, length: length) else {
            if count == 0 || (count < 0 && errno != EAGAIN) { stop(nil) }
            return
        }
        flow.writeDatagrams([Data(buffer[0..<count])], sentBy: [remote]) { [weak self] error in
            if let error { self?.stop(error) }
        }
    }

    func stop(_ error: Error?) {
        lock.lock()
        if closed { lock.unlock(); return }
        closed = true; let allSockets = Array(sockets.values); let allSources = Array(sources.values)
        sockets.removeAll(); sources.removeAll(); lock.unlock()
        allSources.forEach { $0.cancel() }; allSockets.forEach { Darwin.close($0) }
        flow.closeReadWithError(error); flow.closeWriteWithError(error)
        registry.remove(id)
    }
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
    static func resolveA(name: String, servers: [String], interface: String) throws -> [String] {
        for server in servers {
            if let result = try? query(name: name, server: server, interface: interface), !result.isEmpty {
                return result
            }
        }
        throw RelayError.resolveFailed(name)
    }

    private static func query(name: String, server: String, interface: String) throws -> [String] {
        var endpoint = try SocketEndpoint.resolve(
            host: server, port: 53, socketType: SOCK_DGRAM,
            interface: nil, dnsServers: [])
        let fd = try makeSocket(family: endpoint.family, type: SOCK_DGRAM,
                                interface: interface)
        defer { Darwin.close(fd) }
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       socklen_t(MemoryLayout.size(ofValue: timeout)))
        let id = UInt16.random(in: 1...UInt16.max)
        let packet = makeQuery(name: name, id: id)
        let sent = packet.withUnsafeBytes { raw in
            withSockAddr(&endpoint) { Darwin.sendto(fd, raw.baseAddress, packet.count, 0, $0, $1) }
        }
        guard sent == packet.count else { throw RelayError.socketFailed("DNS sendto") }
        var answer = [UInt8](repeating: 0, count: 4096)
        let count = Darwin.recv(fd, &answer, answer.count, 0)
        guard count > 0 else { throw RelayError.socketFailed("DNS recv") }
        return parseA(Data(answer[0..<count]), id: id)
    }

    private static func makeQuery(name: String, id: UInt16) -> Data {
        var bytes: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00,
                              0x00, 0x01, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") {
            bytes.append(UInt8(min(label.utf8.count, 63))); bytes.append(contentsOf: label.utf8.prefix(63))
        }
        bytes += [0, 0, 1, 0, 1]
        return Data(bytes)
    }

    private static func parseA(_ data: Data, id: UInt16) -> [String] {
        let b = [UInt8](data)
        guard b.count >= 12, UInt16(b[0]) << 8 | UInt16(b[1]) == id,
              b[3] & 0x0f == 0 else { return [] }
        let questions = Int(UInt16(b[4]) << 8 | UInt16(b[5]))
        let answers = Int(UInt16(b[6]) << 8 | UInt16(b[7]))
        var offset = 12
        for _ in 0..<questions {
            guard skipName(b, &offset), offset + 4 <= b.count else { return [] }
            offset += 4
        }
        var result: [String] = []
        for _ in 0..<answers {
            guard skipName(b, &offset), offset + 10 <= b.count else { break }
            let type = UInt16(b[offset]) << 8 | UInt16(b[offset + 1])
            let klass = UInt16(b[offset + 2]) << 8 | UInt16(b[offset + 3])
            let length = Int(UInt16(b[offset + 8]) << 8 | UInt16(b[offset + 9])); offset += 10
            guard offset + length <= b.count else { break }
            if type == 1 && klass == 1 && length == 4 {
                result.append("\(b[offset]).\(b[offset+1]).\(b[offset+2]).\(b[offset+3])")
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
