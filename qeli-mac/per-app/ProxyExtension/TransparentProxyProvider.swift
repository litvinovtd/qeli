import Foundation
import Network
import NetworkExtension

final class TransparentProxyProvider: NETransparentProxyProvider {
    private let lock = NSLock()
    private var state: RoutingState?
    private let relays = RelayRegistry()

    override func startProxy(options: [String : Any]? = nil,
                             completionHandler: @escaping (Error?) -> Void) {
        do {
            let loaded = try RoutingStateStore.load()
            lock.lock(); state = loaded; lock.unlock()

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
            setTunnelNetworkSettings(settings, completionHandler: completionHandler)
        } catch { completionHandler(error) }
    }

    override func stopProxy(with reason: NEProviderStopReason,
                            completionHandler: @escaping () -> Void) {
        relays.closeAll()
        lock.lock(); state = nil; lock.unlock()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        lock.lock(); let current = state; lock.unlock()
        guard let current, current.selects(flow.metaData.sourceAppSigningIdentifier) else {
            return false
        }

        let endpoint: NWEndpoint
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
                     dnsServers: current.dnsServers, overrideHost: nil,
                     destinationPolicy: current.destinationDecision, registry: relays).start()
            return true
        }
        return acceptUDP(flow as! NEAppProxyUDPFlow, state: current)
    }

    private func acceptUDP(_ flow: NEAppProxyUDPFlow, state: RoutingState) -> Bool {
        guard state.tunnelUp else { return reject(flow, message: "Qeli tunnel reconnecting") }
        UDPRelay(flow: flow, interface: state.interfaceName, dnsServers: state.dnsServers,
                 overrideHost: nil, destinationPolicy: state.destinationDecision,
                 registry: relays).start()
        return true
    }

    private func reject(_ flow: NEAppProxyFlow, message: String) -> Bool {
        let error = NSError(domain: "ru.qeli.perapp", code: 1,
                            userInfo: [NSLocalizedDescriptionKey: message])
        flow.closeReadWithError(error); flow.closeWriteWithError(error)
        return true
    }

    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)? = nil) {
        do {
            let updated = try RoutingStateStore.load()
            lock.lock(); state = updated; lock.unlock()
            if !updated.tunnelUp { relays.closeAll() }
            completionHandler?(Data("ok".utf8))
        } catch {
            completionHandler?(Data("error:\(error.localizedDescription)".utf8))
        }
    }
}
