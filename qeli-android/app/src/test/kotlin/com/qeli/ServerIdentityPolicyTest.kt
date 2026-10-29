package com.qeli

import org.junit.Assert.*
import org.junit.Test

class ServerIdentityPolicyTest {
    private val a = "aa".repeat(32)
    private val b = "bb".repeat(32)
    private fun rejects(block: () -> Unit) {
        try { block(); fail("expected a security rejection") } catch (_: SecurityException) { }
    }

    @Test fun tcpAndUdpOnOnePortKeepDifferentPins() {
        val pins = mapOf("tcp://vpn:443" to a, "udp://vpn:443" to b, "vpn:443" to b)
        assertTrue(ServerIdentityPolicy.checkKnownHost("tcp://vpn:443", a, pins::get))
        assertTrue(ServerIdentityPolicy.checkKnownHost("udp://vpn:443", b, pins::get))
        rejects { ServerIdentityPolicy.checkKnownHost("tcp://vpn:443", b, pins::get) }
        rejects { ServerIdentityPolicy.checkKnownHost("udp://vpn:443", a, pins::get) }
    }

    @Test fun legacyTrustMigratesOnlyAfterAMatchAndRemainsFailClosed() {
        val pins = mapOf("vpn:443" to a)
        assertFalse(ServerIdentityPolicy.checkKnownHost("tcp://vpn:443", a, pins::get))
        rejects { ServerIdentityPolicy.checkKnownHost("tcp://vpn:443", b, pins::get) }
        assertFalse(ServerIdentityPolicy.checkKnownHost("tcp://vpn:443", a) { null })
        assertEquals(mapOf("vpn:443" to a), pins)
    }

    @Test fun explicitKeyIsVerifiedWithoutAnUnrelatedTofuPin() {
        assertTrue(ServerIdentityPolicy.verifyExplicit(a, a.uppercase()))
        rejects { ServerIdentityPolicy.verifyExplicit(b, a) }
        assertFalse(ServerIdentityPolicy.verifyExplicit(a, null))
        assertFalse(ServerIdentityPolicy.verifyExplicit(a, "00".repeat(32)))
        assertTrue(ServerIdentityPolicy.isKeyMismatch("REALITY authentication failed: SERVER KEY MISMATCH"))
        assertFalse(ServerIdentityPolicy.isKeyMismatch("transport disconnected"))
    }

    @Test fun ipv6AndOldCoreEventsAreScopedAndForeignEndpointsAreRejected() {
        assertEquals("udp://[2001:db8::1]:443", ServerIdentityPolicy.endpointId("udp", "2001:db8::1", 443))
        assertEquals("tcp://vpn:443", ServerIdentityPolicy.storageId("vpn:443", "tcp", "vpn", 443))
        assertEquals("tcp://vpn:443", ServerIdentityPolicy.storageId("tcp://vpn:443", "tcp", "vpn", 443))
        rejects { ServerIdentityPolicy.storageId("udp://vpn:443", "tcp", "vpn", 443) }
        rejects { ServerIdentityPolicy.storageId("tcp://other:443", "tcp", "vpn", 443) }
        val legacy = mapOf("2001:db8::1:443" to a)
        assertFalse(ServerIdentityPolicy.checkKnownHost("udp://[2001:db8::1]:443", a, legacy::get))
        rejects { ServerIdentityPolicy.checkKnownHost("udp://[2001:db8::1]:443", b, legacy::get) }
    }
}
