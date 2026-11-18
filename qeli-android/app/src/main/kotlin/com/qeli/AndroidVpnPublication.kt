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
        var interfaceName: String? = null,
        var mtu: Int? = null,
        var addresses: Set<String> = emptySet(),
    )
    private val networks = mutableMapOf<Long, Facts>()

    @Synchronized fun available(network: Long) {
        networks.getOrPut(network) { Facts() }.available = true
    }
    @Synchronized fun capabilities(network: Long, vpn: Boolean) {
        networks.getOrPut(network) { Facts() }.vpn = vpn
    }
    @Synchronized fun links(network: Long, interfaceName: String?, mtu: Int?, addresses: Set<String>) {
        networks.getOrPut(network) { Facts() }.apply {
            this.interfaceName = interfaceName
            this.mtu = mtu
            this.addresses = addresses.toSet()
        }
    }
    @Synchronized fun lost(network: Long) { networks.remove(network) }

    // Android 10 sets the actual TUN MTU but does not copy it into VPN LinkProperties.
    // Its 0 means "not reported", not an interface with zero MTU. API 28 has no public
    // MTU getter (null). Neither is proof of a mismatch; positive mismatches still fail.
    private fun matchingLinks(facts: Facts): Boolean =
        !facts.interfaceName.isNullOrEmpty() &&
            (facts.mtu == null || facts.mtu == 0 || facts.mtu == expectedMtu) &&
            expectedAddresses.isNotEmpty() && facts.addresses.containsAll(expectedAddresses)

    @Synchronized fun readyNetwork(): Long? = networks.entries.firstOrNull {
        it.value.available && it.value.vpn && matchingLinks(it.value)
    }?.key

    /** Facts from the same callbacks used by the gate, not a racy system snapshot. */
    @Synchronized fun diagnostics(): String =
        "expected_mtu=$expectedMtu expected_addresses=${expectedAddresses.sorted()} " +
            "networks=" + if (networks.isEmpty()) "none" else networks.toSortedMap().entries.joinToString("; ") { (id, facts) ->
                val reportedMtu = when (facts.mtu) {
                    null -> "unavailable"
                    0 -> "0(not_reported)"
                    else -> facts.mtu.toString()
                }
                "{network=$id available=${facts.available} vpn=${facts.vpn} " +
                    "interface=${facts.interfaceName ?: "none"} reported_mtu=$reportedMtu " +
                    "addresses=${facts.addresses.sorted()} " +
                    "missing_addresses=${(expectedAddresses - facts.addresses).sorted()} " +
                    "links_match=${matchingLinks(facts)}}"
            }
}
