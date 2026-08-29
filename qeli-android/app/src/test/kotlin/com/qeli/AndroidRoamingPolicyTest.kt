package com.qeli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidRoamingPolicyTest {
    @Test
    fun pathCapabilityIsTransportAgnosticWhenCoreSupportsIt() {
        assertEquals(
            AndroidRoamingPolicy.PLATFORM_ROAMING_PATH or
                AndroidRoamingPolicy.PLATFORM_PATH_REFRESH,
            AndroidRoamingPolicy.platformCapabilities(
                pathAllowedByConfig = true,
                coreSupportsPathTransactions = true,
                coreSupportsPathRefreshRequests = true,
            ),
        )
    }

    @Test
    fun keepsPathTransactionsWhenCoreCannotRequestARefresh() {
        assertEquals(
            AndroidRoamingPolicy.PLATFORM_ROAMING_PATH,
            AndroidRoamingPolicy.platformCapabilities(
                pathAllowedByConfig = true,
                coreSupportsPathTransactions = true,
                coreSupportsPathRefreshRequests = false,
            ),
        )
    }

    @Test
    fun leavesOnlyAnOldCoreWithoutThePathContract() {
        assertEquals(
            0L,
            AndroidRoamingPolicy.platformCapabilities(
                pathAllowedByConfig = true,
                coreSupportsPathTransactions = false,
                coreSupportsPathRefreshRequests = true,
            ),
        )
    }

    @Test
    fun configCanDisableTheNativeExecutor() {
        assertEquals(
            0L,
            AndroidRoamingPolicy.platformCapabilities(
                pathAllowedByConfig = false,
                coreSupportsPathTransactions = true,
                coreSupportsPathRefreshRequests = true,
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
