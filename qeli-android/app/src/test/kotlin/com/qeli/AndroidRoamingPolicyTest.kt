package com.qeli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidRoamingPolicyTest {
    @Test
    fun pathCapabilityIsTransportAgnosticWhenCoreSupportsIt() {
        assertEquals(
            AndroidRoamingPolicy.PLATFORM_ROAMING_PATH,
            AndroidRoamingPolicy.platformCapabilities(
                coreSupportsPathTransactions = true,
            ),
        )
    }

    @Test
    fun leavesOnlyAnOldCoreWithoutThePathContract() {
        assertEquals(
            0L,
            AndroidRoamingPolicy.platformCapabilities(
                coreSupportsPathTransactions = false,
            ),
        )
    }

    @Test
    fun schedulesOnlyInsideAnAcknowledgedGeneration() {
        assertTrue(AndroidRoamingPolicy.canSchedulePathUpdate(true, 7))
        assertFalse(AndroidRoamingPolicy.canSchedulePathUpdate(false, 7))
        assertFalse(AndroidRoamingPolicy.canSchedulePathUpdate(true, 0))
    }
}
