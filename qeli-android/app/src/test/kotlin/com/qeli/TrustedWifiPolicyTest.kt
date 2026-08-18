package com.qeli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustedWifiPolicyTest {
    @Test
    fun parsesOneExactSsidPerLine() {
        assertEquals(
            listOf("Home", "Office, 5G"),
            TrustedWifiPolicy.parse(" Home \n\nOffice, 5G\nHome"),
        )
    }

    @Test
    fun quotedAndroidSsidIsNormalized() {
        assertEquals("Home", TrustedWifiPolicy.normalizeObservedSsid("\"Home\""))
    }

    @Test
    fun redactedWifiIsNeverTrusted() {
        assertEquals(
            TrustedWifiPolicy.NetworkKind.UNKNOWN_WIFI,
            TrustedWifiPolicy.classify(
                enabled = true,
                configuredSsids = listOf("Home"),
                hasNetwork = true,
                isWifi = true,
                observedSsid = "<unknown ssid>",
            ),
        )
    }

    @Test
    fun onlyAnExactWifiMatchPausesVpn() {
        assertEquals(
            TrustedWifiPolicy.NetworkKind.TRUSTED_WIFI,
            TrustedWifiPolicy.classify(true, listOf("Home"), true, true, "\"Home\""),
        )
        assertEquals(
            TrustedWifiPolicy.NetworkKind.OTHER_NETWORK,
            TrustedWifiPolicy.classify(true, listOf("Home"), true, true, "\"home\""),
        )
        assertEquals(
            TrustedWifiPolicy.NetworkKind.OTHER_NETWORK,
            TrustedWifiPolicy.classify(true, listOf("Home"), true, false, null),
        )
    }

    @Test
    fun lockdownNeverAllowsAnAbsentTun() {
        assertTrue(TrustedWifiPolicy.canPause(configKillSwitch = false, systemLockdown = false))
        assertFalse(TrustedWifiPolicy.canPause(configKillSwitch = true, systemLockdown = false))
        assertFalse(TrustedWifiPolicy.canPause(configKillSwitch = false, systemLockdown = true))
    }

    @Test
    fun pauseCompletionHonorsDisconnectAndChangesDuringTeardown() {
        assertEquals(
            TrustedWifiPolicy.PauseCompletionAction.STOP,
            TrustedWifiPolicy.pauseCompletionAction(
                connectionDesired = false,
                pauseAllowed = true,
                networkKind = TrustedWifiPolicy.NetworkKind.TRUSTED_WIFI,
            ),
        )
        assertEquals(
            TrustedWifiPolicy.PauseCompletionAction.RESUME,
            TrustedWifiPolicy.pauseCompletionAction(
                connectionDesired = true,
                pauseAllowed = false,
                networkKind = TrustedWifiPolicy.NetworkKind.TRUSTED_WIFI,
            ),
        )
        assertEquals(
            TrustedWifiPolicy.PauseCompletionAction.RESUME,
            TrustedWifiPolicy.pauseCompletionAction(
                connectionDesired = true,
                pauseAllowed = true,
                networkKind = TrustedWifiPolicy.NetworkKind.OTHER_NETWORK,
            ),
        )
        assertEquals(
            TrustedWifiPolicy.PauseCompletionAction.RESUME_AFTER_REDACTION,
            TrustedWifiPolicy.pauseCompletionAction(
                connectionDesired = true,
                pauseAllowed = true,
                networkKind = TrustedWifiPolicy.NetworkKind.UNKNOWN_WIFI,
            ),
        )
        assertEquals(
            TrustedWifiPolicy.PauseCompletionAction.RESUME,
            TrustedWifiPolicy.pauseCompletionAction(
                connectionDesired = true,
                pauseAllowed = true,
                networkKind = TrustedWifiPolicy.NetworkKind.TRUSTED_WIFI,
                observerAvailable = false,
            ),
        )
    }

    @Test
    fun forcedResumeDoesNotWaitForeverWithoutANetworkObserver() {
        assertTrue(
            TrustedWifiPolicy.shouldResumeAfterDelay(
                TrustedWifiPolicy.NetworkKind.NO_NETWORK,
                forced = true,
            ),
        )
        assertTrue(
            TrustedWifiPolicy.shouldResumeAfterDelay(
                TrustedWifiPolicy.NetworkKind.TRUSTED_WIFI,
                forced = true,
            ),
        )
        assertFalse(
            TrustedWifiPolicy.shouldResumeAfterDelay(
                TrustedWifiPolicy.NetworkKind.NO_NETWORK,
                forced = false,
            ),
        )
    }

    @Test
    fun secondaryNetworkCallbacksCannotDriveTrustedWifiPolicy() {
        assertTrue(TrustedWifiPolicy.shouldEvaluateCallback(isCurrentUnderlyingNetwork = true))
        assertFalse(TrustedWifiPolicy.shouldEvaluateCallback(isCurrentUnderlyingNetwork = false))
    }
}
