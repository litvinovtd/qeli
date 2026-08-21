package com.qeli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RouteComplementsTest {
    @Test
    fun `only a missing non-leaking full-tunnel family needs a synthetic sink`() {
        assertTrue(RouteComplements.needsSyntheticSink(
            fullTunnel = true, hasAddress = false, allowLeak = false,
        ))
        assertFalse(RouteComplements.needsSyntheticSink(
            fullTunnel = true, hasAddress = false, allowLeak = true,
        ))
        assertFalse(RouteComplements.needsSyntheticSink(
            fullTunnel = true, hasAddress = true, allowLeak = false,
        ))
        assertFalse(RouteComplements.needsSyntheticSink(
            fullTunnel = false, hasAddress = false, allowLeak = false,
        ))
    }

    @Test
    fun `bare route uses the host prefix of its address family`() {
        assertEquals(32, RouteComplements.hostPrefix("192.0.2.7"))
        assertEquals(128, RouteComplements.hostPrefix("2001:db8::7"))
    }

    @Test
    fun `ipv4 LAN complement excludes the exact API 33 bypass ranges`() {
        val routes = RouteComplements.ipv4(listOf(
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "169.254.0.0/16", "224.0.0.0/24", "239.255.255.250/32",
        ))
        assertNotNull(routes)
        assertFalse(routes!!.any { contains(it, "10.1.2.3") })
        assertFalse(routes.any { contains(it, "169.254.8.9") })
        assertFalse(routes.any { contains(it, "224.0.0.251") })
        assertFalse(routes.any { contains(it, "239.255.255.250") })
        assertTrue(routes.any { contains(it, "8.8.8.8") })
        assertTrue(routes.any { contains(it, "224.0.1.1") })
        assertTrue(routes.any { contains(it, "239.255.255.249") })
    }

    @Test
    fun `IPv4 complement distinguishes all-space exclusion from malformed input`() {
        assertEquals(emptyList<String>(), RouteComplements.ipv4(listOf("0.0.0.0/0")))
        assertNull(RouteComplements.ipv4(listOf("vpn.example.com/24")))
    }

    @Test
    fun `ipv6 exclusion creates a real complement instead of an IPv4 fallback`() {
        val routes = RouteComplements.ipv6(listOf("2001:db8::/32"))
        assertNotNull(routes)
        assertTrue(routes!!.isNotEmpty())
        assertFalse(routes.contains("::/0"))
        assertFalse(routes.any { contains(it, "2001:db8::1") })
        assertTrue(routes.any { contains(it, "2001:4860:4860::8888") })
    }

    @Test
    fun `excluding all IPv6 produces no tunnel route`() {
        assertEquals(emptyList<String>(), RouteComplements.ipv6(listOf("::/0")))
    }

    @Test
    fun `multiple and malformed IPv6 excludes are handled deterministically`() {
        val routes = RouteComplements.ipv6(listOf("2001:db8::/32", "fd00::/8"))
        assertNotNull(routes)
        assertFalse(routes!!.any { contains(it, "2001:db8::42") })
        assertFalse(routes.any { contains(it, "fd00::1") })
        assertNull(RouteComplements.ipv6(listOf("vpn.example.com/64")))
    }

    @Test
    fun `two IPv6 host excludes do not trip the complexity guard`() {
        val routes = RouteComplements.ipv6(listOf("2001:db8::1/128", "fd00::1/128"))
        assertNotNull(routes)
        assertEquals(254, routes!!.size)
        assertFalse(routes.any { contains(it, "2001:db8::1") })
        assertFalse(routes.any { contains(it, "fd00::1") })
        assertTrue(routes.any { contains(it, "2001:4860:4860::8888") })
    }

    @Test
    fun `subtract preserves every non-excluded part of a broad IPv4 route`() {
        val routes = RouteComplements.subtract(
            "10.0.0.0/8",
            listOf("10.1.0.0/16", "2001:db8::/32"),
        )
        assertNotNull(routes)
        assertTrue(routes!!.any { contains(it, "10.0.255.255") })
        assertFalse(routes.any { contains(it, "10.1.2.3") })
        assertTrue(routes.any { contains(it, "10.2.0.1") })
        assertTrue(routes.any { contains(it, "10.255.255.255") })
        assertFalse(routes.any { contains(it, "11.0.0.1") })
    }

    @Test
    fun `subtract preserves every non-excluded part of a broad IPv6 route`() {
        val routes = RouteComplements.subtract(
            "2001:db8::/32",
            listOf("2001:db8:53::/48", "192.0.2.0/24"),
        )
        assertNotNull(routes)
        assertTrue(routes!!.any { contains(it, "2001:db8:52::ffff") })
        assertFalse(routes.any { contains(it, "2001:db8:53::1") })
        assertTrue(routes.any { contains(it, "2001:db8:54::1") })
        assertFalse(routes.any { contains(it, "2001:db9::1") })
    }

    @Test
    fun `subtract and overlap distinguish full partial disjoint and mixed families`() {
        assertEquals(
            emptyList<String>(),
            RouteComplements.subtract("192.0.2.0/24", listOf("0.0.0.0/0")),
        )
        assertTrue(RouteComplements.overlaps("192.0.2.0/24", "192.0.2.128/25"))
        assertFalse(RouteComplements.overlaps("192.0.2.0/24", "192.0.3.0/24"))
        assertTrue(RouteComplements.overlaps("2001:db8::/32", "2001:db8:1::/48"))
        assertFalse(RouteComplements.overlaps("2001:db8::/32", "192.0.2.0/24"))
        assertNull(RouteComplements.subtract("not-a-route", emptyList()))
    }

    @Test
    fun `installed pushed count follows exclusion fragments instead of original strings`() {
        val fragments = requireNotNull(RouteComplements.subtract(
            "10.0.0.0/8",
            listOf("10.1.0.0/16"),
        )).toSet()
        assertEquals(
            1,
            RouteComplements.countInstalledOriginals(
                originals = setOf("10.0.0.0/8"),
                installedFragments = fragments,
                excludes = listOf("10.1.0.0/16"),
                protectedCidrs = emptySet(),
            ),
        )
        assertEquals(
            0,
            RouteComplements.countInstalledOriginals(
                originals = setOf("10.0.0.0/8"),
                installedFragments = fragments.drop(1).toSet(),
                excludes = listOf("10.1.0.0/16"),
                protectedCidrs = emptySet(),
            ),
        )
        assertEquals(
            0,
            RouteComplements.countInstalledOriginals(
                originals = setOf("10.0.0.0/8"),
                installedFragments = emptySet(),
                excludes = listOf("0.0.0.0/0"),
                protectedCidrs = emptySet(),
            ),
        )
    }

    @Test
    fun `tunnel gateway can override only broader physical exclusions`() {
        assertEquals(false, RouteComplements.overridesOnLinkGateway("10.0.0.0/8", "10.8.0.1", 24))
        assertEquals(true, RouteComplements.overridesOnLinkGateway("10.8.0.0/24", "10.8.0.1", 24))
        assertEquals(true, RouteComplements.overridesOnLinkGateway("10.8.0.1/32", "10.8.0.1", 24))
        assertEquals(false, RouteComplements.overridesOnLinkGateway("fc00::/7", "fd71:e1::1", 64))
        assertEquals(true, RouteComplements.overridesOnLinkGateway("fd71:e1::/64", "fd71:e1::1", 64))
        assertEquals(false, RouteComplements.overridesOnLinkGateway("192.0.2.0/24", "fd71:e1::1", 64))
        assertEquals(null, RouteComplements.overridesOnLinkGateway("bad", "10.8.0.1", 24))
    }

    private fun contains(cidr: String, address: String): Boolean {
        val fields = cidr.split('/', limit = 2)
        val networkBytes = java.net.InetAddress.getByName(fields[0]).address
        val candidateBytes = java.net.InetAddress.getByName(address).address
        if (networkBytes.size != candidateBytes.size) return false
        val network = java.math.BigInteger(1, networkBytes)
        val candidate = java.math.BigInteger(1, candidateBytes)
        val prefix = fields[1].toInt()
        val hostBits = networkBytes.size * 8 - prefix
        return network.shiftRight(hostBits) == candidate.shiftRight(hostBits)
    }
}
