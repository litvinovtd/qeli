package com.qeli

import com.qeli.model.VpnConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class AndroidSessionContinuityTest {
    private fun config(
        appsMode: String = "all",
        apps: List<String> = emptyList(),
    ) = VpnConfig(
        serverAddress = "198.51.100.10",
        port = 443,
        username = "test",
        password = "test",
        appsMode = appsMode,
        apps = apps,
    )

    private fun plan(generation: Long = 1) = TransportCoreNetworkPlan(
        generation = generation,
        familyMode = "ipv4",
        addresses = listOf(TransportCoreNetworkAddress(
            family = "ipv4",
            address = "10.9.0.2",
            prefixLength = 32,
            onLinkPrefixLength = 24,
            gateway = "10.9.0.1",
        )),
        tunnelAddress = "10.9.0.2",
        prefixLength = 24,
        mtu = 1280,
        tunnelGateway = "10.9.0.1",
        routes = listOf(TransportCoreNetworkRoute("0.0.0.0/0", "10.9.0.1", 50)),
        pushedRoutes = emptyList(),
        dnsServers = listOf(TransportCoreNetworkDns("1.1.1.1", 53)),
        fullTunnel = true,
        killSwitch = false,
        allowIpv4Leak = false,
        allowIpv6Leak = false,
        maxStreams = 4,
        adaptive = true,
        dataPlane = TransportCoreDataPlaneFacts(),
        connectionLog = emptyList(),
    )

    @Test
    fun transportGenerationDoesNotForceTunReplacement() {
        val first = androidTunPlanFingerprint(config(), plan(1), false, 35)
        val reconnected = androidTunPlanFingerprint(config(), plan(2), false, 35)
        assertEquals(first, reconnected)
    }

    @Test
    fun routeDnsAndPerAppChangesForceTunReplacement() {
        val baseline = androidTunPlanFingerprint(config(), plan(), false, 35)
        assertNotEquals(
            baseline,
            androidTunPlanFingerprint(
                config(),
                plan().copy(routes = listOf(
                    TransportCoreNetworkRoute("10.20.0.0/16", "10.9.0.1", 50)
                )),
                false,
                35,
            ),
        )
        assertNotEquals(
            baseline,
            androidTunPlanFingerprint(
                config(),
                plan().copy(dnsServers = listOf(TransportCoreNetworkDns("9.9.9.9", 53))),
                false,
                35,
            ),
        )
        assertNotEquals(
            baseline,
            androidTunPlanFingerprint(
                config(appsMode = "include", apps = listOf("org.example.app")),
                plan(),
                false,
                35,
            ),
        )
    }

    @Test
    fun platformRouteApiAndLanPolicyArePartOfFingerprint() {
        val baseline = androidTunPlanFingerprint(config(), plan(), false, 32)
        assertNotEquals(baseline, androidTunPlanFingerprint(config(), plan(), false, 33))
        assertNotEquals(baseline, androidTunPlanFingerprint(config(), plan(), true, 32))
    }
}
