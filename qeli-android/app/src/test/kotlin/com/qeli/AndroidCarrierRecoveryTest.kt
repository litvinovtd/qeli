package com.qeli

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidCarrierRecoveryTest {
    @Test
    fun readyCarrierDoesNotEnterOfflineWait() = runBlocking {
        val gate = AndroidCarrierGate()
        assertFalse(gate.awaitUsable(isUsable = { true }, onWaiting = { error("unexpected wait") }))
    }

    @Test
    fun sameNetworkCapabilityChangeWakesParkedAttempt() = runBlocking {
        // The long recheck interval makes a lost callback fail the test, not pass by polling.
        val gate = AndroidCarrierGate(recheckMs = 60_000)
        val snapshots = AndroidCarrierSnapshots<Int, Boolean, String>()
        snapshots.capabilities(1, false, current = 1)
        snapshots.links(1, "has-address", current = 1)
        val parked = CompletableDeferred<Unit>()
        var waitNotifications = 0
        val attempt = async(start = CoroutineStart.UNDISPATCHED) {
            gate.awaitUsable(isUsable = {
                snapshots[1]?.let { it.capabilities == true && it.links == "has-address" } == true
            }, onWaiting = {
                waitNotifications++
                parked.complete(Unit)
            })
        }
        parked.await()
        // Same identity, only NOT_SUSPENDED/readiness changed. No repeated link callback.
        snapshots.capabilities(1, true, current = 1)
        gate.signalChange()
        assertTrue(withTimeout(2_000) { attempt.await() })
        assertEquals(1, waitNotifications)
    }

    @Test
    fun boundedRecheckRecoversWhenFrameworkOmitsCallback() = runBlocking {
        val gate = AndroidCarrierGate(recheckMs = 20)
        var usable = false
        val attempt = async(start = CoroutineStart.UNDISPATCHED) {
            gate.awaitUsable(isUsable = { usable })
        }
        usable = true // Deliberately omit signalChange.
        assertTrue(withTimeout(2_000) { attempt.await() })
    }

    @Test
    fun notificationBetweenReadinessCheckAndReceiveIsNotLost() = runBlocking {
        val gate = AndroidCarrierGate(recheckMs = 60_000)
        var usable = false
        assertTrue(withTimeout(2_000) {
            gate.awaitUsable(isUsable = { usable }, onWaiting = {
                usable = true
                gate.signalChange()
            })
        })
    }

    @Test
    fun staleAndSpuriousNotificationsDoNotMakeCarrierUsable() = runBlocking {
        val gate = AndroidCarrierGate(recheckMs = 60_000)
        gate.signalChange() // A signal from a carrier that disappeared before this attempt.
        var checks = 0
        val reachedSecondCheck = CompletableDeferred<Unit>()
        val attempt = launch(start = CoroutineStart.UNDISPATCHED) {
            gate.awaitUsable(isUsable = {
                if (++checks == 2) reachedSecondCheck.complete(Unit)
                false
            })
            error("unusable carrier was accepted")
        }
        withTimeout(2_000) { reachedSecondCheck.await() }
        assertTrue(attempt.isActive)
        withTimeout(2_000) { attempt.cancelAndJoin() }
        assertTrue(attempt.isCancelled)
    }

    @Test
    fun disconnectCancelsWaitWithoutWaitingForRecheck() = runBlocking {
        val gate = AndroidCarrierGate(recheckMs = 60_000)
        val attempt = launch(start = CoroutineStart.UNDISPATCHED) {
            gate.awaitUsable(isUsable = { false })
            error("cancellation was swallowed")
        }
        withTimeout(2_000) { attempt.cancelAndJoin() }
        assertTrue(attempt.isCancelled)
    }

    private fun carrier(kind: AndroidCarrierKind, validated: Boolean = true, usable: Boolean = true) =
        AndroidCarrierPreference(usable, validated, kind)

    @Test
    fun validatedWifiCanReplaceStillAvailableCellular() {
        assertTrue(AndroidCarrierPreferencePolicy.shouldReplace(
            carrier(AndroidCarrierKind.CELLULAR), carrier(AndroidCarrierKind.WIFI),
        ))
    }

    @Test
    fun activeCellularDoesNotMaskPreferredWifiDuringRetrySelection() {
        val active = carrier(AndroidCarrierKind.CELLULAR)
        val preferred = carrier(AndroidCarrierKind.WIFI)
        assertEquals(preferred, AndroidCarrierPreferencePolicy.bestOf(listOf(active, preferred)) { it })
        assertEquals(preferred, AndroidCarrierPreferencePolicy.bestOf(listOf(preferred, active)) { it })
    }

    @Test
    fun secondaryRadioDoesNotReplaceHealthyWifi() {
        assertFalse(AndroidCarrierPreferencePolicy.shouldReplace(
            carrier(AndroidCarrierKind.WIFI), carrier(AndroidCarrierKind.CELLULAR),
        ))
        assertFalse(AndroidCarrierPreferencePolicy.shouldReplace(
            carrier(AndroidCarrierKind.WIFI), carrier(AndroidCarrierKind.WIFI),
        ))
    }

    @Test
    fun captiveAndSuspendedWifiDoNotReplaceWorkingCellular() {
        val cellular = carrier(AndroidCarrierKind.CELLULAR)
        assertFalse(AndroidCarrierPreferencePolicy.shouldReplace(cellular,
            carrier(AndroidCarrierKind.WIFI, validated = false)))
        assertFalse(AndroidCarrierPreferencePolicy.shouldReplace(cellular,
            carrier(AndroidCarrierKind.WIFI, usable = false)))
    }

    @Test
    fun validationAndReadinessWinOverTransportPreference() {
        assertTrue(AndroidCarrierPreferencePolicy.shouldReplace(
            carrier(AndroidCarrierKind.WIFI, validated = false), carrier(AndroidCarrierKind.CELLULAR),
        ))
        assertTrue(AndroidCarrierPreferencePolicy.shouldReplace(
            carrier(AndroidCarrierKind.ETHERNET, usable = false),
            carrier(AndroidCarrierKind.CELLULAR, validated = false),
        ))
        assertTrue(AndroidCarrierPreferencePolicy.shouldReplace(null,
            carrier(AndroidCarrierKind.WIFI, validated = false)))
    }

    @Test
    fun supersededNetworksWithoutLostCallbacksRemainBounded() {
        val cache = AndroidNetworkSignatureCache<Int>(capacity = 8)
        repeat(10_000) { id -> cache[id] = AndroidPhysicalNetworkSignature("path-$id", 1500) }
        assertEquals(8, cache.size())
        assertNull(cache[0])
        assertEquals(AndroidPhysicalNetworkSignature("path-9999", 1500), cache[9999])
        cache.retainOnly(9999)
        assertEquals(1, cache.size())
        cache.clear()
        assertEquals(0, cache.size())
    }

    @Test
    fun baselineIsPreservedUntilAnObservedChangeIsHandled() {
        val cache = AndroidNetworkSignatureCache<Int>()
        val baseline = AndroidPhysicalNetworkSignature("path", 1500)
        cache[1] = baseline
        cache.putIfAbsent(1, baseline.copy(mtu = 1280))
        assertEquals(baseline, cache[1])
        cache[1] = baseline.copy(mtu = 1280)
        assertEquals(1280, cache[1]!!.mtu)
        cache.remove(1)
        assertNull(cache[1])
    }

    @Test
    fun mtuOnlyObservationIsDistinctFromPathMigration() {
        val baseline = AndroidPhysicalNetworkSignature("addresses/routes/dns", 1500)
        assertTrue(baseline.copy(mtu = 1280).isMtuOnlyChange(baseline))
        assertFalse(baseline.copy(path = "new address", mtu = 1280).isMtuOnlyChange(baseline))
        assertFalse(baseline.isMtuOnlyChange(baseline))
    }

    @Test
    fun callbacksMergeCapabilitiesBeforeLinks() {
        val snapshots = AndroidCarrierSnapshots<Int, String, Int>()
        assertNull(snapshots.capabilities(1, "usable", current = null).links)
        assertEquals(AndroidCarrierSnapshot("usable", 1500), snapshots.links(1, 1500, current = 1))
    }

    @Test
    fun callbacksMergeLinksBeforeCapabilities() {
        val snapshots = AndroidCarrierSnapshots<Int, String, Int>()
        assertNull(snapshots.links(1, 1500, current = null).capabilities)
        assertEquals(AndroidCarrierSnapshot("usable", 1500), snapshots.capabilities(1, "usable", current = 1))
    }

    @Test
    fun callbackSnapshotsStayBoundedWithoutEvictingCurrentCarrier() {
        val snapshots = AndroidCarrierSnapshots<Int, String, Int>(capacity = 8)
        snapshots.capabilities(0, "current", current = 0)
        snapshots.links(0, 1500, current = 0)
        repeat(10_000) { id -> snapshots.capabilities(id + 1, "secondary", current = 0) }
        assertEquals(8, snapshots.size())
        assertEquals(AndroidCarrierSnapshot("current", 1500), snapshots[0])
        assertNull(snapshots[1])
        snapshots.remove(0)
        assertNull(snapshots[0])
        snapshots.retainOnly(10_000)
        assertEquals(1, snapshots.size())
    }
}
