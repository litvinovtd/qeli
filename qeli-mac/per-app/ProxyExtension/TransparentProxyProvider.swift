import Foundation
import NetworkExtension

final class TransparentProxyProvider: NETransparentProxyProvider {
    private let lock = NSLock()
    private var state: RoutingState?
    private var leaseWasValid = false
    private let relays = RelayRegistry()
    private let monitorQueue = DispatchQueue(label: "ru.qeli.perapp.proxy.state")
    private var stateMonitor: DispatchSourceTimer?

    override func startProxy(options: [String : Any]? = nil,
                             completionHandler: @escaping (Error?) -> Void) {
        // Preferences may survive app deletion while app-group state does not. An absent or
        // corrupt state starts as bypass and is picked up by the monitor if it reappears.
        let loaded = try? RoutingStateStore.load()
        lock.lock(); state = loaded; leaseWasValid = loaded?.leaseIsValid() ?? false; lock.unlock()

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // DNS/53 is intentionally handled by the companion NEDNSProxyProvider. Apple
        // explicitly excludes DNS port rules from transparent-proxy network rules.
        settings.includedNetworkRules = [
            NENetworkRule(destinationNetwork: NWHostEndpoint(hostname: "0.0.0.0", port: "0"),
                          prefix: 0, protocol: .TCP),
            NENetworkRule(destinationNetwork: NWHostEndpoint(hostname: "0.0.0.0", port: "0"),
                          prefix: 0, protocol: .UDP),
            NENetworkRule(destinationNetwork: NWHostEndpoint(hostname: "::", port: "0"),
                          prefix: 0, protocol: .TCP),
            NENetworkRule(destinationNetwork: NWHostEndpoint(hostname: "::", port: "0"),
                          prefix: 0, protocol: .UDP),
        ]
        setTunnelNetworkSettings(settings) { [weak self] error in
            if error == nil { self?.startStateMonitor() }
            completionHandler(error)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason,
                            completionHandler: @escaping () -> Void) {
        stopStateMonitor()
        relays.closeAll()
        lock.lock(); state = nil; leaseWasValid = false; lock.unlock()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        refreshState()
        lock.lock(); let current = state; lock.unlock()
        guard let current, current.leaseIsValid(),
              current.selects(flow.metaData.sourceAppSigningIdentifier) else {
            return false
        }

        let endpoint: NetworkExtension.NWEndpoint
        if let tcp = flow as? NEAppProxyTCPFlow { endpoint = tcp.remoteEndpoint }
        else if let udp = flow as? NEAppProxyUDPFlow { return acceptUDP(udp, state: current) }
        else {
            return false // NetworkExtension exposes TCP/UDP flows, not per-app ICMP.
        }

        if let parsed = flowEndpoint(endpoint) {
            switch current.destinationDecision(parsed.host) {
            case .bypass: return false
            case .drop: return reject(flow, message: "IPv6 leak prevention")
            case .tunnel: break
            }
        }
        guard current.tunnelUp else { return reject(flow, message: "Qeli tunnel reconnecting") }

        if let tcp = flow as? NEAppProxyTCPFlow {
            TCPRelay(flow: tcp, remote: endpoint, interface: current.interfaceName,
                     dnsServers: current.dnsServers, overrideHosts: [],
                     destinationPolicy: current.destinationDecision, registry: relays).start()
            return true
        }
        return acceptUDP(flow as! NEAppProxyUDPFlow, state: current)
    }

    private func acceptUDP(_ flow: NEAppProxyUDPFlow, state: RoutingState) -> Bool {
        guard state.tunnelUp else { return reject(flow, message: "Qeli tunnel reconnecting") }
        UDPRelay(flow: flow, interface: state.interfaceName, dnsServers: state.dnsServers,
                 overrideHosts: [], destinationPolicy: state.destinationDecision,
                 registry: relays).start()
        return true
    }

    private func reject(_ flow: NEAppProxyFlow, message: String) -> Bool {
        let error = NSError(domain: "ru.qeli.perapp", code: 1,
                            userInfo: [NSLocalizedDescriptionKey: message])
        flow.closeReadWithError(error); flow.closeWriteWithError(error)
        return true
    }

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

    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)? = nil) {
        do {
            let updated = try RoutingStateStore.load()
            lock.lock()
            let changed = state.map { !updated.policyEquivalent(to: $0) } ?? true
            state = updated
            leaseWasValid = updated.leaseIsValid()
            lock.unlock()
            // A true -> true live update may replace the utun, DNS servers, route policy,
            // or selected-app set. Existing relays retain all of those values, so keeping
            // them alive would continue enforcing the old profile indefinitely.
            if changed { relays.closeAll() }
            completionHandler?(Data("ok".utf8))
        } catch {
            completionHandler?(Data("error:\(error.localizedDescription)".utf8))
        }
    }
}
