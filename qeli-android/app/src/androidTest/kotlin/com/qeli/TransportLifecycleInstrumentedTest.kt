package com.qeli

import android.content.Context
import android.content.ContextWrapper
import android.os.ParcelFileDescriptor
import android.system.Os
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.qeli.model.VpnConfig
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Packaged JNI and direct production adapter fixtures, not full service lifecycle E2E. */
@RunWith(AndroidJUnit4::class)
class TransportLifecycleInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val config = VpnConfig(serverAddress = "198.51.100.17", port = 443,
        username = "lifecycle-fixture", password = "fixture", reconnectEnabled = false,
        mtuProbe = false, killSwitch = false)
    private fun core(tun: Boolean = false, protect: Boolean = false) = TransportCore.create(
        config.toTransportCoreIni(), ByteArray(16) { 1 },
        TransportCore.PLATFORM_ROUTES or TransportCore.PLATFORM_DNS or
            TransportCore.PLATFORM_IPV6_TUN or TransportCore.PLATFORM_IPV6_ROUTES or
            TransportCore.PLATFORM_IPV6_DNS or
            (if (tun) TransportCore.PLATFORM_TUN_FD else 0L) or
            (if (protect) TransportCore.PLATFORM_SOCKET_PROTECT else 0L),
    ).also { it.start(); it.drainEvents() }

    private fun event(core: TransportCore): TransportCoreEvent {
        val handle = TransportCore::class.java.getDeclaredField("handle").apply { isAccessible = true }.getLong(core)
        val bytes = org.json.JSONObject()
            .put("auth_ok", """OK:{"client_ip":"10.71.0.2","server_ip":"10.71.0.1","prefix":24,"mtu":1400,"dns":"10.71.0.1"}""")
            .put("effective_mtu", 1400).put("fallback_dns_servers", org.json.JSONArray())
            .toString().toByteArray()
        val method = TransportCore::class.java.getDeclaredMethod("nativePublishHandshakeNetwork",
            Long::class.javaPrimitiveType, ByteArray::class.java).apply { isAccessible = true }
        try { val generation = method.invoke(null, handle, bytes) as Long; assertTrue("native publish rc=$generation", generation > 0) } finally { bytes.fill(0) }
        return generateSequence { core.pollEvent() }.first { it.kind == TransportCoreEventCodec.KIND_NETWORK_PLAN }
    }
    private fun field(service: VpnServiceImpl, name: String, value: Any?) {
        VpnServiceImpl::class.java.getDeclaredField(name).apply { isAccessible = true }.set(service, value)
    }
    private fun fixture(core: TransportCore) = VpnServiceImpl().also {
        // Documented protected SDK method; no ActivityThread internals or debug product hook.
        ContextWrapper::class.java.getDeclaredMethod("attachBaseContext", Context::class.java)
            .apply { isAccessible = true }.invoke(it, context)
        field(it, "activeConfig", config); field(it, "transportCore", core); field(it, "stopping", true)
    }
    private val applyPlan = VpnServiceImpl::class.java.getDeclaredMethod("applyNativeNetworkPlan",
        TransportCore::class.java, TransportCoreEvent::class.java).apply { isAccessible = true }
    private fun clean(service: VpnServiceImpl, core: TransportCore) {
        core.close()
        (VpnServiceImpl::class.java.getDeclaredField("vpnInterface").apply { isAccessible = true }
            .get(service) as? ParcelFileDescriptor)?.close()
        field(service, "vpnInterface", null); field(service, "transportCore", null)
        service.setUnderlyingNetworks(emptyArray())
        (VpnServiceImpl::class.java.getDeclaredField("carrierDnsExecutor").apply { isAccessible = true }
            .get(service) as java.util.concurrent.ExecutorService).shutdownNow()
    }
    @Test fun stoppedServiceRejectsQueuedPlanWithoutEstablishingOrConnecting() {
        val core = core(tun = true); val event = event(core); val service = fixture(core)
        val oldStatus = VpnServiceImpl.liveStatus
        try {
            applyPlan.invoke(service, core, event)
            assertEquals("late plan must be rejected by the production adapter", 6, core.state())
            assertNull(VpnServiceImpl::class.java.getDeclaredField("vpnInterface")
                .apply { isAccessible = true }.get(service))
            assertEquals(oldStatus, VpnServiceImpl.liveStatus)
            assertNull("stopped adapter must not even select or bind a carrier",
                VpnServiceImpl::class.java.getDeclaredField("currentNetwork")
                    .apply { isAccessible = true }.get(service))
        } finally { clean(service, core); VpnServiceImpl.liveStatus = oldStatus }
    }
    @Test fun planCannotEnterWhileLifecycleTransitionOwnsServiceMonitor() {
        val core = core(tun = true); val event = event(core); val service = fixture(core)
        val entered = CountDownLatch(1); val finished = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>(); val oldStatus = VpnServiceImpl.liveStatus
        val worker = Thread {
            entered.countDown()
            try { applyPlan.invoke(service, core, event) } catch (error: Throwable) { failure.set(error) }
            finally { finished.countDown() }
        }
        try {
            synchronized(service) {
                worker.start(); assertTrue(entered.await(2, TimeUnit.SECONDS))
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
                while (worker.state != Thread.State.BLOCKED && finished.count > 0 &&
                    System.nanoTime() < deadline) Thread.sleep(10)
                assertEquals("NetworkPlan must wait for lifecycle transition", Thread.State.BLOCKED, worker.state)
                // Existing carrier selection also takes this monitor, but too late: logging
                // and plan preparation have already begun. Check the actual blocked frame.
                assertEquals("plan entry must wait before any platform side effects", "applyNativeNetworkPlan",
                    worker.stackTrace.firstOrNull { it.className == VpnServiceImpl::class.java.name }?.methodName)
            }
            assertTrue(finished.await(5, TimeUnit.SECONDS)); failure.get()?.let { throw it }
            assertEquals(6, core.state())
        } finally { worker.join(5000); assertFalse(worker.isAlive); clean(service, core); VpnServiceImpl.liveStatus = oldStatus }
    }
    @Test fun staleAndCancelledNetworkAckCannotEnterRunning() {
        core().use { core ->
            val plan = TransportCoreEventCodec.decodeNetworkPlan(event(core))
            assertThrows(IllegalStateException::class.java) { core.networkPlanResult(plan.generation + 1, true) }
            assertEquals(2, core.state()); core.stop()
            assertThrows(IllegalStateException::class.java) { core.networkPlanResult(plan.generation, true) }
            assertEquals(5, core.state())
        }
    }
    @Test fun nativeOwnsItsDescriptorDuplicateUntilStop() {
        val pipe = ParcelFileDescriptor.createPipe()
        fun refs(): Int {
            val name = Os.readlink("/proc/self/fd/${pipe[1].fd}")
            return File("/proc/self/fd").listFiles()!!.count {
                runCatching { Os.readlink(it.path) == name }.getOrDefault(false) }
        }
        val core = core(tun = true)
        try {
            val plan = TransportCoreEventCodec.decodeNetworkPlan(event(core)); val before = refs()
            core.setTunFd(plan.generation, pipe[0].fd); assertEquals(before + 1, refs())
            pipe[0].close(); assertEquals(before, refs()); core.stop(); assertEquals(before - 1, refs())
            Os.fstat(pipe[1].fileDescriptor); core.close(); core.close()
        } finally { core.close(); pipe.forEach { it.close() } }
    }
    @Test fun stopAndFreeCancelBlockingNativeRunnerAwaitingProtection() {
        for (free in listOf(false, true)) {
            val core = core(protect = true); val finished = CountDownLatch(1)
            val failure = AtomicReference<Throwable?>()
            val worker = Thread {
                try { core.runTransport(carrierAddresses = listOf("198.51.100.17")) }
                catch (error: Throwable) { failure.set(error) } finally { finished.countDown() }
            }
            try {
                worker.start(); val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                var request: TransportCoreEvent? = null
                while (request == null && System.nanoTime() < deadline) {
                    val next = core.pollEvent()
                    if (next?.kind == TransportCoreEventCodec.KIND_SOCKET_PROTECT) request = next else Thread.sleep(10)
                }
                assertNotNull("runner must enter JNI and request socket protection", request)
                if (free) core.close() else core.stop()
                assertTrue("native cancellation did not release runner", finished.await(5, TimeUnit.SECONDS))
                failure.get()?.let { throw it }; if (!free) assertEquals(5, core.state())
            } finally { core.close(); worker.join(5000); assertFalse(worker.isAlive) }
        }
    }

    /** Native socket request is real; service attachment/state are explicit adapter fixtures. */
    private fun withProtectRequest(block: (TransportCore, TransportCoreEvent) -> Unit) {
        val core = core(protect = true)
        val finished = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        val runner = Thread {
            try { core.runTransport(carrierAddresses = listOf("198.51.100.17")) }
            catch (error: Throwable) { failure.set(error) }
            finally { finished.countDown() }
        }
        try {
            runner.start()
            var request: TransportCoreEvent? = null
            val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (request == null && System.nanoTime() < until) {
                val next = core.pollEvent()
                if (next?.kind == TransportCoreEventCodec.KIND_SOCKET_PROTECT) request = next
                else Thread.sleep(10)
            }
            block(core, requireNotNull(request) { "native protection request absent" })
        } finally {
            core.stop()
            assertTrue("native protection runner remained", finished.await(5, TimeUnit.SECONDS))
            runner.join(5000); assertFalse(runner.isAlive)
            core.close()
            failure.get()?.let { throw it }
        }
    }
    private val dispatch = VpnServiceImpl::class.java.getDeclaredMethod("dispatchTransportCoreEvent",
        TransportCore::class.java, TransportCoreEvent::class.java).apply { isAccessible = true }
    private fun selectedCarrier(service: VpnServiceImpl) = VpnServiceImpl::class.java
        .getDeclaredField("currentNetwork").apply { isAccessible = true }.get(service)

    @Test fun stoppedServiceRejectsLateProtectBeforeCarrierMutation() = withProtectRequest { core, request ->
        val service = fixture(core)
        try {
            dispatch.invoke(service, core, request)
            assertNull("late protect selected a carrier after stop", selectedCarrier(service))
        } finally { clean(service, core) }
    }
    @Test fun replacedCoreCannotProtectOnBehalfOfCurrentConnection() = withProtectRequest { oldCore, request ->
        val current = core()
        val service = fixture(current)
        field(service, "stopping", false)
        try {
            dispatch.invoke(service, oldCore, request)
            assertNull("stale core mutated the current carrier", selectedCarrier(service))
        } finally { clean(service, current) }
    }
    @Test fun protectionWaitsAtOwnerCheckWhileLifecycleOwnsMonitor() = withProtectRequest { core, request ->
        val service = fixture(core)
        val entered = CountDownLatch(1); val finished = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        val worker = Thread {
            entered.countDown()
            try { dispatch.invoke(service, core, request) }
            catch (error: Throwable) { failure.set(error) }
            finally { finished.countDown() }
        }
        try {
            synchronized(service) {
                worker.start(); assertTrue(entered.await(2, TimeUnit.SECONDS))
                val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
                while (worker.state != Thread.State.BLOCKED && finished.count > 0 &&
                    System.nanoTime() < until) Thread.sleep(10)
                assertEquals(Thread.State.BLOCKED, worker.state)
                assertEquals("protect must wait before selecting/binding a carrier",
                    "protectAndBindCarrierSocket", worker.stackTrace.firstOrNull {
                        it.className == VpnServiceImpl::class.java.name }?.methodName)
            }
            assertTrue(finished.await(5, TimeUnit.SECONDS)); failure.get()?.let { throw it }
            assertNull(selectedCarrier(service))
        } finally {
            worker.join(5000); assertFalse(worker.isAlive); clean(service, core)
        }
    }

    private fun observer(method: String, replace: Boolean = false, stopping: Boolean = false) {
        val core = core(); val service = fixture(core)
        val register = VpnServiceImpl::class.java.getDeclaredMethod("registerNetworkCallback")
            .apply { isAccessible = true }
        val unregister = VpnServiceImpl::class.java.getDeclaredMethod("unregisterNetworkCallback")
            .apply { isAccessible = true }
        val callbackField = VpnServiceImpl::class.java.getDeclaredField("netCallback")
            .apply { isAccessible = true }
        val cm = context.getSystemService(android.net.ConnectivityManager::class.java)
        val network = requireNotNull(cm.allNetworks.firstOrNull {
            val caps = cm.getNetworkCapabilities(it)
            caps?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) == true &&
                caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }) { "real physical Wi-Fi required" }
        val caps = requireNotNull(cm.getNetworkCapabilities(network))
        val links = requireNotNull(cm.getLinkProperties(network))
        val instrumentation = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation()
        try {
            instrumentation.runOnMainSync {
                field(service, "stopping", false)
                assertTrue(register.invoke(service) as Boolean)
                val old = callbackField.get(service) as android.net.ConnectivityManager.NetworkCallback
                if (replace) assertTrue(register.invoke(service) as Boolean)
                else if (!stopping) unregister.invoke(service)
                // Before API31 the live replacement callback runs off the main looper.
                // Hold the production lifecycle monitor so it cannot publish a legitimate
                // carrier between our sentinel write and the retired-callback assertion.
                synchronized(service) {
                    field(service, "stopping", stopping)
                    field(service, "currentNetwork", if (method == "lost") network else null)
                    when (method) {
                        "available" -> old.onAvailable(network)
                        "capabilities" -> old.onCapabilitiesChanged(network, caps)
                        "links" -> old.onLinkPropertiesChanged(network, links)
                        "lost" -> old.onLost(network)
                        else -> error("unknown callback fixture")
                    }
                    assertEquals("retired/stopped observer must not mutate the selected carrier ($method)",
                        if (method == "lost") network else null, selectedCarrier(service))
                }
            }
        } finally {
            instrumentation.runOnMainSync { field(service, "stopping", true); unregister.invoke(service) }
            clean(service, core)
        }
    }
    @Test fun stoppedObserverCannotPublishCarrier() = observer("available", stopping = true)
    @Test fun unregisteredObserverCannotPublishCarrier() = observer("available")
    @Test fun replacedObserverCannotPublishCarrier() = observer("available", replace = true)
    @Test fun retiredObserverCapabilitiesAndLinksCannotPublishCarrier() {
        observer("capabilities"); observer("links")
    }
    @Test fun retiredObserverLostCannotEraseCarrier() = observer("lost")
}
