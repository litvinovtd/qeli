package com.qeli

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.qeli.model.VpnConfig
import java.io.Closeable
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Real settings Save, service and native pre-auth sockets. Connected UI state is injected. */
@RunWith(AndroidJUnit4::class)
class SettingsReconnectInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private var scenario: ActivityScenario<MainActivity>? = null
    private val prefs get() = context.getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
    private fun call(owner: MainActivity, method: String) = MainActivity::class.java
        .getDeclaredMethod(method).apply { isAccessible = true }.invoke(owner)
    @Suppress("DEPRECATION") private fun serviceRunning() = context.getSystemService(ActivityManager::class.java)
        .getRunningServices(100).any { it.service.className == VpnServiceImpl::class.java.name }
    private fun await(message: String, predicate: () -> Boolean) {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
        while (!predicate() && System.nanoTime() < until) Thread.sleep(25)
        assertTrue(message, predicate())
    }
    @Before fun prepare() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("q29_private_fixture") == "1")
        context.stopService(Intent(context, VpnServiceImpl::class.java))
        await("old service remained") { !serviceRunning() }
        assertTrue(prefs.edit().putBoolean("battery_opt_requested", true)
            .putBoolean(MainActivity.PREF_AUTO_CONNECT_LAUNCH, false)
            .putBoolean(MainActivity.PREF_AUTO_PROBE, false)
            .putBoolean(MainActivity.PREF_TRUSTED_WIFI_ENABLED, false)
            .putBoolean(MainActivity.PREF_CONNECTION_DESIRED, false)
            .putBoolean(MainActivity.PREF_CLEAR_LOG_ON_DISCONNECT, true)
            .putBoolean(MainActivity.PREF_ALLOW_LAN, false).commit())
        VpnServiceImpl.liveStatus = VpnServiceImpl.STATUS_DISCONNECTED
    }
    @After fun clean() {
        scenario?.close(); scenario = null
        context.startService(Intent(context, VpnServiceImpl::class.java).setAction(VpnServiceImpl.ACTION_DISCONNECT))
        await("service remained after settings test") { !serviceRunning() }
    }
    private fun config(port: Int) = VpnConfig.parse("""[qeli]
server = 127.0.0.1:$port
user = settings-fixture
pass = fixture
proto = tcp
mode = fake-tls
reconnect = false
kill_switch = false
bind_static = false
timeout = 30
""")
    private fun launch(cfg: VpnConfig) {
        val blob = JSONObject().put("active", 0).put("profiles", JSONArray().put(
            JSONObject().put("name", "settings fixture").put("cfg", cfg.toIni()))).toString()
        assertTrue(ProfileStore.open(context).edit().putString(ProfileStore.KEY_PROFILES, blob).commit())
        scenario = ActivityScenario.launch(MainActivity::class.java)
    }
    private fun children(view: View): List<View> = listOf(view) + if (view is ViewGroup)
        (0 until view.childCount).flatMap { children(view.getChildAt(it)) } else emptyList()
    private fun saveLanChange(owner: MainActivity) {
        call(owner, "showSettingsDialog")
        val type = Class.forName("android.view.WindowManagerGlobal")
        val manager = type.getDeclaredMethod("getInstance").invoke(null)
        @Suppress("UNCHECKED_CAST") val views = type.getDeclaredField("mViews").apply { isAccessible = true }
            .get(manager) as List<View>
        val root = views.last { it.findViewById<View>(android.R.id.button1) != null }
        children(root).filterIsInstance<CheckBox>().single { it.text.toString() == context.getString(R.string.allow_lan) }
            .isChecked = true
        root.findViewById<View>(android.R.id.button1).performClick()
    }
    private class StallPeer : Closeable {
        private val listener = ServerSocket(0, 2, InetAddress.getByName("127.0.0.1"))
        val port get() = listener.localPort
        val firstHello = CountDownLatch(1)
        val secondHello = CountDownLatch(1)
        private val sockets = java.util.concurrent.CopyOnWriteArrayList<Socket>()
        private val readers = java.util.concurrent.CopyOnWriteArrayList<Thread>()
        private val acceptor = Thread {
            try { repeat(2) { index ->
                val socket = listener.accept(); sockets += socket
                val reader = Thread {
                    try { socket.getInputStream().use { input ->
                        if (input.read() >= 0) (if (index == 0) firstHello else secondHello).countDown()
                        while (input.read() >= 0) { }
                    } } catch (_: Exception) { }
                }.apply { isDaemon = true }
                readers += reader; reader.start()
            } } catch (_: Exception) { }
        }.apply { isDaemon = true; start() }
        override fun close() {
            listener.close(); sockets.forEach { it.close() }; acceptor.join(3000)
            readers.forEach { it.join(3000); assertFalse("peer reader remained", it.isAlive) }
            assertFalse("peer acceptor remained", acceptor.isAlive)
        }
    }
    @Test fun lanSettingsSaveReplacesAnActiveConnectionAttempt() {
        StallPeer().use { peer ->
            launch(config(peer.port))
            DiagnosticLogStore.append(context.noBackupFilesDir, "settings reconnect history")
            scenario!!.onActivity { call(it, "connect") }
            assertTrue("initial native hello missing", peer.firstHello.await(15, TimeUnit.SECONDS))
            scenario!!.onActivity { owner ->
                // No Auth/TUN is published by the stall peer. Exercise the connected UI guard explicitly.
                call(owner, "setConnectedState")
                saveLanChange(owner)
            }
            instrumentation.waitForIdleSync()
            assertTrue(prefs.getBoolean(MainActivity.PREF_ALLOW_LAN, false))
            assertTrue("LAN Save never restarted the native connection", peer.secondHello.await(15, TimeUnit.SECONDS))
            assertTrue("settings reconnect cleared history before a final disconnect",
                DiagnosticLogStore.read(context.noBackupFilesDir).any { it.message == "settings reconnect history" })
        }
    }
    @Test fun disconnectCancelsSettingsReconfiguration() {
        StallPeer().use { peer ->
            launch(config(peer.port))
            scenario!!.onActivity { call(it, "connect") }
            assertTrue("initial native hello missing", peer.firstHello.await(15, TimeUnit.SECONDS))
            scenario!!.onActivity { owner ->
                call(owner, "setConnectedState"); saveLanChange(owner)
            }
            instrumentation.waitForIdleSync()
            context.startService(Intent(context, VpnServiceImpl::class.java).setAction(VpnServiceImpl.ACTION_DISCONNECT))
            await("cancelled reconfiguration left service running") { !serviceRunning() }
            Thread.sleep(250)
            assertFalse("settings reconfiguration resurrected a cancelled service", serviceRunning())
            assertFalse(prefs.getBoolean(MainActivity.PREF_CONNECTION_DESIRED, true))
        }
    }
    @Test fun lanSettingsSaveCannotStealAPendingPermissionResult() {
        val cfg = config(443); launch(cfg)
        lateinit var request: VpnConnectRequest
        scenario!!.onActivity { owner ->
            request = MainActivity::class.java.getDeclaredField("connectRequest\$delegate").let { field ->
                field.isAccessible = true
                @Suppress("UNCHECKED_CAST") val value = field.get(owner) as Lazy<VpnConnectRequest>
                value.value
            }
            assertTrue(request.begin(cfg)); request.awaitPermission(VpnConnectRequest.Permission.NOTIFICATION)
            call(owner, "setConnectingState"); saveLanChange(owner)
        }
        instrumentation.waitForIdleSync()
        assertTrue(prefs.getBoolean(MainActivity.PREF_ALLOW_LAN, false))
        assertTrue(request.isActive); assertTrue(request.hasOutstandingResult); assertFalse(serviceRunning())
        assertTrue(request.finishPermission(VpnConnectRequest.Permission.NOTIFICATION, true))
        assertSame(cfg, request.takeConfiguration())
    }
}
