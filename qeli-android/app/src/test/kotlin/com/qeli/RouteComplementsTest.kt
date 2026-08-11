package com.qeli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RouteComplementsTest {
    @Test
    fun `bare route uses the host prefix of its address family`() {
        assertEquals(32, RouteComplements.hostPrefix("192.0.2.7"))
        assertEquals(128, RouteComplements.hostPrefix("2001:db8::7"))
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

    private fun contains(cidr: String, address: String): Boolean {
        val fields = cidr.split('/', limit = 2)
        val network = java.math.BigInteger(1, java.net.InetAddress.getByName(fields[0]).address)
        val candidate = java.math.BigInteger(1, java.net.InetAddress.getByName(address).address)
        val prefix = fields[1].toInt()
        val hostBits = 128 - prefix
        return network.shiftRight(hostBits) == candidate.shiftRight(hostBits)
    }
}
