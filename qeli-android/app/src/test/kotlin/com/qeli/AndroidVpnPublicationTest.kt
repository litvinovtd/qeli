package com.qeli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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

    @Test fun android10UnreportedMtuDoesNotRejectPublishedVpn() {
        val gate = state()
        gate.available(1)
        gate.capabilities(1, true)
        gate.links(1, "tun0", 0, addresses)
        assertEquals(1L, gate.readyNetwork())
        assertTrue(gate.diagnostics().contains("expected_mtu=1280"))
        assertTrue(gate.diagnostics().contains("reported_mtu=0(not_reported)"))
        // Unknown MTU must not bypass any of the other publication requirements.
        gate.links(1, "tun0", 0, addresses - "10.9.0.2/32")
        assertNull(gate.readyNetwork())
        assertTrue(gate.diagnostics().contains("missing_addresses=[10.9.0.2/32]"))
        gate.links(1, "", 0, addresses)
        assertNull(gate.readyNetwork())
        gate.links(1, "tun0", 0, addresses)
        gate.capabilities(1, false)
        assertNull(gate.readyNetwork())
    }

    @Test fun observedMtuMismatchAndInvalidNegativeMtuStillReject() {
        val gate = state()
        gate.available(1)
        gate.capabilities(1, true)
        for (mtu in listOf(1400, 1500, -1)) {
            gate.links(1, "tun0", mtu, addresses)
            assertNull(gate.readyNetwork())
            assertTrue(gate.diagnostics().contains("reported_mtu=$mtu"))
            assertTrue(gate.diagnostics().contains("links_match=false"))
        }
        gate.links(1, "tun0", 1280, addresses)
        assertEquals(1L, gate.readyNetwork())
    }

    @Test fun unknownMtuCannotCombineFactsAcrossNetworksOrSurviveLoss() {
        val gate = state()
        gate.available(1)
        gate.capabilities(1, true)
        gate.links(2, "tun0", 0, addresses)
        assertNull(gate.readyNetwork())
        gate.available(2)
        gate.capabilities(2, true)
        assertEquals(2L, gate.readyNetwork())
        gate.lost(2)
        assertNull(gate.readyNetwork())
        assertTrue(!gate.diagnostics().contains("network=2"))
    }

    @Test fun diagnosticsDistinguishNoCallbacksFromMissingLinkFacts() {
        val gate = state()
        assertTrue(gate.diagnostics().contains("networks=none"))
        gate.available(42)
        assertTrue(gate.diagnostics().contains("available=true vpn=false"))
        assertTrue(gate.diagnostics().contains("reported_mtu=unavailable"))
        gate.links(42, "tun0", null, addresses)
        assertTrue(gate.diagnostics().contains("links_match=true"))
        assertNull(gate.readyNetwork())
        gate.capabilities(42, true)
        assertEquals(42L, gate.readyNetwork())
    }

    @Test fun diagnosticsRetainCallbackAddressesAndAnEmptyPlanCannotPublish() {
        val supplied = addresses.toMutableSet()
        val gate = state()
        gate.available(1)
        gate.capabilities(1, true)
        gate.links(1, "tun0", 0, supplied)
        supplied.clear()
        assertEquals(1L, gate.readyNetwork())
        val emptyPlan = AndroidVpnPublicationState(emptySet(), 1280)
        emptyPlan.available(1)
        emptyPlan.capabilities(1, true)
        emptyPlan.links(1, "tun0", 0, addresses)
        assertNull(emptyPlan.readyNetwork())
    }
}
