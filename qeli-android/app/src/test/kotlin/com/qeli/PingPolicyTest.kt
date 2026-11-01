package com.qeli

import org.junit.Assert.*
import org.junit.Test

class PingPolicyTest {
    @Test fun disconnectedProfilesUseTheirRealServerAndProtocol() {
        assertEquals(PingPolicy.Target(PingPolicy.Kind.SERVER_TCP, "vpn.example", 443), PingPolicy.target(false, false, "vpn.example", 443, "10.9.0.1"))
        assertEquals(PingPolicy.Target(PingPolicy.Kind.SERVER_UDP, "vpn.example", 8449), PingPolicy.target(false, true, "vpn.example", 8449, "10.9.7.1"))
    }
    @Test fun connectedTcpAndUdpUseTheSameTunnelEchoNotAGatewayListener() {
        for (udp in listOf(false, true)) for (gateway in listOf("10.9.0.1", "fd00::1")) {
            val target = PingPolicy.target(true, udp, "vpn.example", 443, gateway)
            assertEquals(PingPolicy.Kind.TUNNEL_ICMP, target.kind)
            assertEquals(gateway, target.host)
            assertNull("public TCP/UDP port must never be used for tunnel RTT", target.port)
        }
    }
    @Test fun blockedIcmpOrMissingGatewayDoesNotMarkAConnectedVpnDown() {
        for (gateway in listOf("", "10.9.0.1")) {
            val target = PingPolicy.target(true, false, "vpn.example", 443, gateway)
            assertEquals(PingPolicy.CONNECTED_WITHOUT_RTT, PingPolicy.result(target, -1))
            assertTrue(PingPolicy.reachable(PingPolicy.result(target, -1)))
        }
    }
    @Test fun serverFailureIsNotSilentlyTurnedIntoSuccess() {
        for (udp in listOf(false, true)) assertEquals(PingPolicy.UNREACHABLE,
            PingPolicy.result(PingPolicy.target(false, udp, "vpn.example", 443, ""), -1))
        assertFalse(PingPolicy.reachable(null)); assertFalse(PingPolicy.reachable(PingPolicy.CHECKING))
        assertFalse(PingPolicy.reachable(PingPolicy.UNREACHABLE))
    }
    @Test fun actualSubMillisecondRttCanBeZeroButConnectedStateCannotFabricateIt() {
        val target = PingPolicy.target(true, true, "vpn.example", 8449, "10.9.7.1")
        assertEquals(0, PingPolicy.result(target, 0)); assertEquals(37, PingPolicy.result(target, 37))
        assertNotEquals(0, PingPolicy.result(target, -1))
    }
    @Test fun newerTapWinsWithoutInvalidatingOtherProfileRequests() {
        val requests = PingRequests()
        val first = requests.begin(0); val other = requests.begin(1); val second = requests.begin(0)
        assertFalse(requests.current(0, first)); assertTrue(requests.current(0, second))
        assertTrue(requests.current(1, other)); assertFalse(requests.current(2, second))
    }
    @Test fun sessionSnapshotDistinguishesReconnectAndNetworkPlanReplacement() {
        val first = PingSession("connected", 1000, "10.9.0.1", "10.9.0.2")
        assertNotEquals(first, first.copy(status = "disconnected"))
        assertNotEquals(first, first.copy(since = 2000))
        assertNotEquals(first, first.copy(gateway = "10.9.1.1"))
        assertNotEquals(first, first.copy(localIp = "10.9.0.3"))
        assertEquals(first, first.copy())
    }
    private data class Network(val vpn: Boolean, val ownsAddress: Boolean)
    @Test fun tunnelProbeSelectsOnlyTheVpnWithItsAuthenticatedAddress() {
        val physical=Network(false,true);val foreign=Network(true,false);val own=Network(true,true)
        assertSame(own,PingPolicy.tunnelNetwork(listOf(physical,foreign,own),{it.vpn},{it.ownsAddress}))
    }
    @Test fun missingTunnelNeverFallsBackToThePhysicalNetwork() {
        assertNull(PingPolicy.tunnelNetwork(listOf(Network(false,true),Network(true,false)),{it.vpn},{it.ownsAddress}))
        assertNull(PingPolicy.tunnelNetwork(emptyList<Network>(),{it.vpn},{it.ownsAddress}))
    }
    @Test fun ambiguousVpnOwnershipIsRejectedRatherThanAdopted() {
        assertNull(PingPolicy.tunnelNetwork(listOf(Network(true,true),Network(true,true)),{it.vpn},{it.ownsAddress}))
    }
}
