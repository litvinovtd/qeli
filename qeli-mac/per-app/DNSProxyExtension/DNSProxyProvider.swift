import Foundation
import NetworkExtension

/// DNS is a separate provider because macOS deliberately excludes port 53 from
/// NETransparentProxyProvider rules. The DNS provider still classifies every flow by the
/// same source signing identifier: selected apps use the profile/pushed resolver bound to
/// qeli's utun, unselected apps use their original system resolver without that binding.
final class DNSProxyProvider: NEDNSProxyProvider {
    private let lock = NSLock()
    private var state: RoutingState?
    private var leaseWasValid = false
    private let relays = RelayRegistry()
    private let monitorQueue = DispatchQueue(label: "ru.qeli.perapp.dns.state")
    private var stateMonitor: DispatchSourceTimer?

    override func startProxy(options: [String : Any]? = nil,
                             completionHandler: @escaping (Error?) -> Void) {
        // The manager can outlive both Qeli.app and its app-group state. Starting in bypass
        // mode is safer than making an enabled but unstartable DNS proxy black-hole lookups.
        let loaded = try? RoutingStateStore.load()
        lock.lock(); state = loaded; leaseWasValid = loaded?.leaseIsValid() ?? false; lock.unlock()
        startStateMonitor()
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason,
                            completionHandler: @escaping () -> Void) {
        stopStateMonitor()
        relays.closeAll()
        lock.lock(); state = nil; leaseWasValid = false; lock.unlock()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // DNS proxy managers have no NETunnelProviderSession message channel. Reload the
        // tiny app-group state on every new DNS flow; this also makes reconnect fail-close
        // effective without restarting the system extension.
        refreshState()
        lock.lock(); let current = state; lock.unlock()
        guard let current else { return false }
        // A persistent NEDNSProxyManager can be relaunched by macOS after qeli was killed,
        // removed, or the machine lost power. An expired owner lease must restore the system
        // resolver path, never reject or bind a flow to the vanished utun.
        guard current.leaseIsValid() else { return false }
        let selected = current.selects(flow.metaData.sourceAppSigningIdentifier)
        // An empty profile/push list means "leave the host resolver unchanged". Returning
        // false lets macOS handle the flow normally instead of forcing a LAN resolver into
        // the utun where it is usually unreachable.
        if selected && current.dnsServers.isEmpty { return false }
        if selected && !current.tunnelUp { return reject(flow, "Qeli tunnel reconnecting") }

        let interface = selected ? current.interfaceName : nil
        let resolvers = selected ? current.dnsServers : []
        // A resolver selected by the authenticated qeli plan is a tunnel endpoint even
        // when it lives in RFC1918 space (the common 10.8.0.1 case). Applying the ordinary
        // destination policy here would bind it to the physical interface and either leak
        // or time out. Unselected apps have a nil interface and keep their system path.
        if let tcp = flow as? NEAppProxyTCPFlow {
            TCPRelay(flow: tcp, remote: tcp.remoteEndpoint, interface: interface,
                     dnsServers: current.dnsServers, overrideHosts: resolvers,
                     destinationPolicy: nil,
                     registry: relays).start()
            return true
        }
        if let udp = flow as? NEAppProxyUDPFlow {
            UDPRelay(flow: udp, interface: interface, dnsServers: current.dnsServers,
                     overrideHosts: resolvers, destinationPolicy: nil,
                     registry: relays).start()
            return true
        }
        return false
    }

    /// NEDNSProxyManager has no provider-message channel. Poll the tiny atomically-written
    /// app-group state and retire relays from the previous transport generation. Existing
    /// UDP DNS flows would otherwise retain a removed utun and stale resolver list forever.
    private func startStateMonitor() {
        let timer = DispatchSource.makeTimerSource(queue: monitorQueue)
        timer.schedule(deadline: .now() + .milliseconds(250),
                       repeating: .milliseconds(500), leeway: .milliseconds(100))
        timer.setEventHandler { [weak self] in self?.refreshState() }
        lock.lock(); stateMonitor = timer; lock.unlock()
        timer.resume()
    }

    private func stopStateMonitor() {
        lock.lock(); let timer = stateMonitor; stateMonitor = nil; lock.unlock()
        timer?.cancel()
    }

    private func refreshState() {
        let loaded = try? RoutingStateStore.load()
        lock.lock()
        let leaseValid = loaded?.leaseIsValid() ?? false
        let policyChanged: Bool
        if let loaded, let state { policyChanged = !loaded.policyEquivalent(to: state) }
        else { policyChanged = (loaded != nil) != (state != nil) }
        let changed = policyChanged || leaseValid != leaseWasValid
        state = loaded
        leaseWasValid = leaseValid
        lock.unlock()
        if changed { relays.closeAll() }
    }

    private func reject(_ flow: NEAppProxyFlow, _ message: String) -> Bool {
        let error = NSError(domain: "ru.qeli.perapp.dns", code: 1,
                            userInfo: [NSLocalizedDescriptionKey: message])
        flow.closeReadWithError(error); flow.closeWriteWithError(error)
        return true
    }

}
