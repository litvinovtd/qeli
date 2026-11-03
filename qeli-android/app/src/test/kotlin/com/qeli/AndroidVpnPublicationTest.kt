package com.qeli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AndroidVpnPublicationTest {
    private val addresses = setOf("10.9.0.2/32", "2001:db8::2/128")
    private fun state() = AndroidVpnPublicationState(addresses, 1280)

    @Test fun requiresAllCallbackFactsFromTheSameNetwork() {
        val gate = state()
        gate.available(1)
        gate.capabilities(2, true)
        gate.links(2, "tun0", 1280, addresses)
        assertNull(gate.readyNetwork())
        gate.available(2)
        assertEquals(2L, gate.readyNetwork())
    }

    @Test fun wrongOrIncompletePlanCannotPublish() {
        val gate = state()
        gate.available(1)
        gate.capabilities(1, true)
        gate.links(1, "tun0", 1280, setOf("10.9.0.2/32"))
        assertNull(gate.readyNetwork())
        gate.links(1, "tun0", 1500, addresses)
        assertNull(gate.readyNetwork())
        gate.links(1, null, 1280, addresses)
        assertNull(gate.readyNetwork())
        gate.links(1, "tun0", 1280, addresses + "198.18.0.1/32")
        assertEquals(1L, gate.readyNetwork())
        gate.capabilities(1, false)
        assertNull(gate.readyNetwork())
    }

    @Test fun lossDiscardsOldFactsAndReplacementMustPublishAgain() {
        val gate = state()
        gate.available(1)
        gate.capabilities(1, true)
        gate.links(1, "tun0", 1280, addresses)
        gate.lost(1)
        gate.available(1)
        assertNull(gate.readyNetwork())
        gate.capabilities(2, true)
        gate.links(2, "tun1", 1280, addresses)
        assertNull(gate.readyNetwork())
        gate.available(2)
        assertEquals(2L, gate.readyNetwork())
    }

    @Test fun api28StillRequiresPublishedAddressesWhenMtuIsNotPublic() {
        val gate = state()
        gate.available(1)
        gate.capabilities(1, true)
        gate.links(1, "tun0", null, emptySet())
        assertNull(gate.readyNetwork())
        gate.links(1, "tun0", null, addresses)
        assertEquals(1L, gate.readyNetwork())
    }

    @Test fun freshObserverAcceptsPublishedReusedTunWithoutNewNetworkId() {
        val reconnect = state()
        reconnect.available(42)
        reconnect.capabilities(42, true)
        reconnect.links(42, "tun0", 1280, addresses)
        assertEquals(42L, reconnect.readyNetwork())
        assertNull(state().readyNetwork())
    }
}
