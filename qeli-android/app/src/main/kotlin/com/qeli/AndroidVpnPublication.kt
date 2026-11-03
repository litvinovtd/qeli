package com.qeli

/** Callback facts belong to one Network. Never combine an old VPN's addresses with a new
 * network's availability; a lost network must supply fresh facts if it reappears. */
internal class AndroidVpnPublicationState(
    private val expectedAddresses: Set<String>,
    private val expectedMtu: Int,
) {
    private data class Facts(
        var available: Boolean = false,
        var vpn: Boolean = false,
        var matchingLinks: Boolean = false,
    )
    private val networks = mutableMapOf<Long, Facts>()

    @Synchronized fun available(network: Long) {
        networks.getOrPut(network) { Facts() }.available = true
    }
    @Synchronized fun capabilities(network: Long, vpn: Boolean) {
        networks.getOrPut(network) { Facts() }.vpn = vpn
    }
    @Synchronized fun links(network: Long, interfaceName: String?, mtu: Int?, addresses: Set<String>) {
        networks.getOrPut(network) { Facts() }.matchingLinks =
            !interfaceName.isNullOrEmpty() && (mtu == null || mtu == expectedMtu) &&
                expectedAddresses.isNotEmpty() && addresses.containsAll(expectedAddresses)
    }
    @Synchronized fun lost(network: Long) { networks.remove(network) }
    @Synchronized fun readyNetwork(): Long? = networks.entries.firstOrNull {
        it.value.available && it.value.vpn && it.value.matchingLinks
    }?.key
}
