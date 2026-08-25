package com.qeli

import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class TunBuilderInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @After
    fun cleanUp() {
        context.stopService(Intent(context, VpnServiceImpl::class.java))
        VpnServiceImpl.debugTunSelfTestResult = null
    }

    @Test
    fun productionTunBuilderEstablishesSplitFullAndDualPlans() {
        assertNull(
            "CI must grant ACTIVATE_VPN before running instrumentation",
            VpnService.prepare(context),
        )
        VpnServiceImpl.debugTunSelfTestResult = null
        assertNotNull(
            context.startService(
                Intent(context, VpnServiceImpl::class.java)
                    .setAction(VpnServiceImpl.ACTION_DEBUG_TUN_SELF_TEST),
            ),
        )

        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
        var result: String?
        do {
            result = VpnServiceImpl.debugTunSelfTestResult
            if (result == null) Thread.sleep(50)
        } while (result == null && System.nanoTime() < deadline)

        assertEquals("Android TUN self-test failed: $result", "ok", result)
    }
}
