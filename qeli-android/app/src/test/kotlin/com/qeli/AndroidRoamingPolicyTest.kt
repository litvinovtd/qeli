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

    @Test
    fun lateReplacementAfterWifiLossIsStillARoamingPath() {
        assertEquals(
            AndroidRoamingPolicy.AvailableNetworkAction.ROAM,
            AndroidRoamingPolicy.availableNetworkAction(
                hadCurrentNetwork = false,
                waitingForReplacement = true,
                networkChanged = true,
                enteringTrustedWifi = false,
            ),
        )
    }

    @Test
    fun initialNetworkDoesNotLookLikeARoamingPath() {
        assertEquals(
            AndroidRoamingPolicy.AvailableNetworkAction.KEEP,
            AndroidRoamingPolicy.availableNetworkAction(
                hadCurrentNetwork = false,
                waitingForReplacement = false,
                networkChanged = true,
                enteringTrustedWifi = false,
            ),
        )
    }

    @Test
    fun trustedWifiKeepsPausePolicyInChargeDuringReplacement() {
        assertEquals(
            AndroidRoamingPolicy.AvailableNetworkAction.KEEP,
            AndroidRoamingPolicy.availableNetworkAction(
                hadCurrentNetwork = false,
                waitingForReplacement = true,
                networkChanged = true,
                enteringTrustedWifi = true,
            ),
        )
    }

    @Test
    fun currentNetworkLossWaitsOnlyInsideALiveGeneration() {
        assertTrue(
            AndroidRoamingPolicy.shouldWaitForReplacement(
                connected = true,
                generation = 9,
                hasServiceScope = true,
                replacementAvailable = false,
            ),
        )
        assertFalse(
            AndroidRoamingPolicy.shouldWaitForReplacement(
                connected = true,
                generation = 0,
                hasServiceScope = true,
                replacementAvailable = false,
            ),
        )
        assertFalse(
            AndroidRoamingPolicy.shouldWaitForReplacement(
                connected = true,
                generation = 9,
                hasServiceScope = true,
                replacementAvailable = true,
            ),
        )
    }

    @Test
    fun breakBeforeMakeReplacementSkipsTheOrdinarySettleDelay() {
        assertEquals(0L, AndroidRoamingPolicy.pathPreparationDelayMs(carrierWasLost = true))
        assertEquals(350L, AndroidRoamingPolicy.pathPreparationDelayMs(carrierWasLost = false))
    }
}
