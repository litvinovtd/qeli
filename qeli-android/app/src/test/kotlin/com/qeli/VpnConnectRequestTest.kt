package com.qeli

import com.qeli.model.VpnConfig
import org.junit.Assert.*
import org.junit.Test

class VpnConnectRequestTest {
    private val first = VpnConfig(serverAddress = "original.test", port = 443, username = "fixture", password = "fixture")
    private val next = first.copy(serverAddress = "replacement.test")
    private val notification = VpnConnectRequest.Permission.NOTIFICATION
    private val vpn = VpnConnectRequest.Permission.VPN

    @Test fun directStartConsumesOnlyTheValidatedSnapshotOnce() {
        val request = VpnConnectRequest();assertTrue(request.begin(first))
        assertSame(first, request.takeConfiguration());assertNull(request.takeConfiguration())
    }
    @Test fun bothPermissionStagesRetainTheSameSnapshot() {
        val request = VpnConnectRequest();request.begin(first);request.awaitPermission(notification)
        assertNull(request.takeConfiguration());assertTrue(request.finishPermission(notification, true))
        request.awaitPermission(vpn);assertTrue(request.finishPermission(vpn, true))
        assertSame(first, request.takeConfiguration())
    }
    @Test fun cancelCannotBeReversedByEitherPermissionResult() {
        for (permission in listOf(notification, vpn)) {
            val request = VpnConnectRequest();request.begin(first);request.awaitPermission(permission);request.cancel()
            assertFalse(request.finishPermission(permission, true));assertNull(request.takeConfiguration())
        }
    }
    @Test fun oldCallbackCannotAuthorizeANewRequest() {
        val request = VpnConnectRequest();request.begin(first);request.awaitPermission(notification);request.cancel()
        assertFalse(request.begin(next));assertFalse(request.finishPermission(notification, true))
        assertTrue(request.begin(next));assertFalse(request.finishPermission(notification, true))
        assertSame(next, request.takeConfiguration())
    }
    @Test fun denialClearsIntentAndAllowsAnotherAttempt() {
        for (permission in listOf(notification, vpn)) {
            val request = VpnConnectRequest();request.begin(first);request.awaitPermission(permission)
            assertTrue(request.finishPermission(permission, false));assertFalse(request.isActive)
            assertTrue(request.begin(next));assertSame(next, request.takeConfiguration())
        }
    }
    @Test fun wrongCallbackCannotAdvanceAnotherPermissionStage() {
        val request = VpnConnectRequest();request.begin(first);request.awaitPermission(vpn)
        assertFalse(request.finishPermission(notification, true));assertNull(request.takeConfiguration())
        assertTrue(request.finishPermission(vpn, true));assertSame(first, request.takeConfiguration())
    }
    @Test fun failedLauncherDoesNotLeaveAnUndrainableRequest() {
        val request = VpnConnectRequest();request.begin(first);request.awaitPermission(notification)
        request.launchFailed(notification);assertFalse(request.hasOutstandingResult);assertFalse(request.isActive)
        assertTrue(request.begin(next))
    }
    @Test fun reconfigurationModeBelongsToThePermissionSnapshot() {
        val request = VpnConnectRequest(); assertTrue(request.begin(first, true))
        request.awaitPermission(notification)
        assertFalse(request.begin(next, false)); assertTrue(request.reconfigure)
        assertTrue(request.finishPermission(notification, true)); request.awaitPermission(vpn)
        assertTrue(request.finishPermission(vpn, true)); assertTrue(request.reconfigure)
        assertSame(first, request.takeConfiguration())
    }
    @Test fun cancelledReconfigurationCannotMarkANewOrdinaryConnect() {
        val request = VpnConnectRequest(); assertTrue(request.begin(first, true))
        request.awaitPermission(notification); request.cancel()
        assertFalse(request.begin(next, false)); assertFalse(request.finishPermission(notification, true))
        assertTrue(request.begin(next)); assertFalse(request.reconfigure)
        assertSame(next, request.takeConfiguration())
    }
}
