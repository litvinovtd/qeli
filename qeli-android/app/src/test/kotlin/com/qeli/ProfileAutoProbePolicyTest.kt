package com.qeli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileAutoProbePolicyTest {
    @Test
    fun intervalIsClampedLikeDesktopClients() {
        assertEquals(10, ProfileAutoProbePolicy.clampIntervalSeconds(1))
        assertEquals(30, ProfileAutoProbePolicy.clampIntervalSeconds(30))
        assertEquals(3_600, ProfileAutoProbePolicy.clampIntervalSeconds(9_999))
    }

    @Test
    fun automaticSweepRequiresOptInAndDisconnectedTunnel() {
        assertFalse(ProfileAutoProbePolicy.DEFAULT_ENABLED)
        assertFalse(ProfileAutoProbePolicy.canStartSweep(false, false, 20_000, 0))
        assertFalse(ProfileAutoProbePolicy.canStartSweep(true, true, 20_000, 0))
        assertTrue(ProfileAutoProbePolicy.canStartSweep(true, false, 20_000, 0))
    }

    @Test
    fun eventDrivenSweepsAreDebouncedButClockChangesRecover() {
        assertFalse(ProfileAutoProbePolicy.canStartSweep(true, false, 19_999, 10_000))
        assertTrue(ProfileAutoProbePolicy.canStartSweep(true, false, 20_000, 10_000))
        assertTrue(ProfileAutoProbePolicy.canStartSweep(true, false, 5_000, 10_000))
    }
}
