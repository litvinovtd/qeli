import Foundation
import Network
import NetworkExtension

/// DNS is a separate provider because macOS deliberately excludes port 53 from
/// NETransparentProxyProvider rules. The DNS provider still classifies every flow by the
/// same source signing identifier: selected apps use the profile/pushed resolver bound to
/// qeli's utun, unselected apps use their original system resolver without that binding.
final class DNSProxyProvider: NEDNSProxyProvider {
    private let lock = NSLock()
    private var state: RoutingState?
    private let relays = RelayRegistry()

    override func startProxy(options: [String : Any]? = nil,
                             completionHandler: @escaping (Error?) -> Void) {
        do {
            let loaded = try RoutingStateStore.load()
            lock.lock(); state = loaded; lock.unlock()
            completionHandler(nil)
        } catch { completionHandler(error) }
    }

    override func stopProxy(with reason: NEProviderStopReason,
                            completionHandler: @escaping () -> Void) {
        relays.closeAll()
        lock.lock(); state = nil; lock.unlock()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // DNS proxy managers have no NETunnelProviderSession message channel. Reload the
        // tiny app-group state on every new DNS flow; this also makes reconnect fail-close
        // effective without restarting the system extension.
        let diskState = try? RoutingStateStore.load()
        lock.lock()
        if let diskState { state = diskState }
        let current = state
        lock.unlock()
        guard let current else { return reject(flow, "Qeli DNS state unavailable") }
        let selected = current.selects(flow.metaData.sourceAppSigningIdentifier)
        // An empty profile/push list means "leave the host resolver unchanged". Returning
        // false lets macOS handle the flow normally instead of forcing a LAN resolver into
        // the utun where it is usually unreachable.
        if selected && current.dnsServers.isEmpty { return false }
        if selected && !current.tunnelUp { return reject(flow, "Qeli tunnel reconnecting") }

        let interface = selected ? current.interfaceName : nil
        let resolvers = selected ? current.dnsServers : []
        let policy: ((String) -> DestinationDecision)? =
            selected ? current.destinationDecision : nil
        if let tcp = flow as? NEAppProxyTCPFlow {
            TCPRelay(flow: tcp, remote: tcp.remoteEndpoint, interface: interface,
                     dnsServers: current.dnsServers, overrideHosts: resolvers,
                     destinationPolicy: policy,
                     registry: relays).start()
            return true
        }
        if let udp = flow as? NEAppProxyUDPFlow {
            UDPRelay(flow: udp, interface: interface, dnsServers: current.dnsServers,
                     overrideHosts: resolvers, destinationPolicy: policy,
                     registry: relays).start()
            return true
        }
        return false
    }

    private func reject(_ flow: NEAppProxyFlow, _ message: String) -> Bool {
        let error = NSError(domain: "ru.qeli.perapp.dns", code: 1,
                            userInfo: [NSLocalizedDescriptionKey: message])
        flow.closeReadWithError(error); flow.closeWriteWithError(error)
        return true
    }

}
