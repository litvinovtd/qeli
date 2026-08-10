package com.qeli

import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidKillSwitchPolicyTest {
    @Test
    fun `disabled and split tunnel profiles do not claim lockdown`() {
        assertEquals(
            AndroidKillSwitchReadiness.NOT_REQUESTED,
            AndroidKillSwitchPolicy.evaluate(false, true, 37, alwaysOn = false, lockdown = false),
        )
        assertEquals(
            AndroidKillSwitchReadiness.SPLIT_TUNNEL_IGNORED,
            AndroidKillSwitchPolicy.evaluate(true, false, 37, alwaysOn = true, lockdown = true),
        )
    }

    @Test
    fun `full tunnel kill switch fails closed unless lockdown is observable and active`() {
        assertEquals(
            AndroidKillSwitchReadiness.LOCKDOWN_NOT_OBSERVABLE,
            AndroidKillSwitchPolicy.evaluate(true, true, 28, alwaysOn = true, lockdown = true),
        )
        assertEquals(
            AndroidKillSwitchReadiness.ALWAYS_ON_DISABLED,
            AndroidKillSwitchPolicy.evaluate(true, true, 37, alwaysOn = false, lockdown = false),
        )
        assertEquals(
            AndroidKillSwitchReadiness.LOCKDOWN_DISABLED,
            AndroidKillSwitchPolicy.evaluate(true, true, 37, alwaysOn = true, lockdown = false),
        )
        assertEquals(
            AndroidKillSwitchReadiness.READY,
            AndroidKillSwitchPolicy.evaluate(true, true, 37, alwaysOn = true, lockdown = true),
        )
        // Never accept a contradictory observation. The service supplies either the paired
        // pre-establishment proof or the paired post-establishment owner API state.
        assertEquals(
            AndroidKillSwitchReadiness.ALWAYS_ON_DISABLED,
            AndroidKillSwitchPolicy.evaluate(true, true, 37, alwaysOn = false, lockdown = true),
        )
    }
}
