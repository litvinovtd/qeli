package com.qeli

import android.app.ActivityManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.IntentFilter
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.qeli.model.VpnConfig
import java.net.ServerSocket
import java.lang.reflect.InvocationTargetException
import kotlin.coroutines.Continuation
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlinx.coroutines.runBlocking
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Disposable app fixture: actual Settings, service teardown, durable file and visible log. */
@RunWith(AndroidJUnit4::class)
class DisconnectLogSettingsInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val prefs get() = context.getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
    private var scenario: ActivityScenario<MainActivity>? = null
    private var receiver: BroadcastReceiver? = null
    private val ownedKeys = listOf(
        MainActivity.PREF_CLEAR_LOG_ON_DISCONNECT, MainActivity.PREF_LOG_LEVEL,
        MainActivity.PREF_AUTO_CONNECT_LAUNCH, MainActivity.PREF_AUTO_PROBE,
        MainActivity.PREF_TRUSTED_WIFI_ENABLED, MainActivity.PREF_CONNECTION_DESIRED,
        "battery_opt_requested",
    )
    private var previous = emptyMap<String, Any?>()

    private fun call(owner: MainActivity, method: String) = MainActivity::class.java
        .getDeclaredMethod(method).apply { isAccessible = true }.invoke(owner)

    @Suppress("DEPRECATION")
    private fun serviceRunning() = context.getSystemService(ActivityManager::class.java)
        .getRunningServices(100).any { it.service.className == VpnServiceImpl::class.java.name }

    private fun awaitStopped() {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
        while (serviceRunning() && System.nanoTime() < until) Thread.sleep(25)
        assertFalse("service did not stop", serviceRunning())
        instrumentation.waitForIdleSync()
    }

    @Before fun prepare() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("q29_private_fixture") == "1")
        context.stopService(Intent(context, VpnServiceImpl::class.java))
        awaitStopped()
        previous = ownedKeys.associateWith { prefs.all[it] }
        assertTrue(prefs.edit()
            .remove(MainActivity.PREF_CLEAR_LOG_ON_DISCONNECT)
            .putString(MainActivity.PREF_LOG_LEVEL, "debug")
            .putBoolean(MainActivity.PREF_AUTO_CONNECT_LAUNCH, false)
            .putBoolean(MainActivity.PREF_AUTO_PROBE, false)
            .putBoolean(MainActivity.PREF_TRUSTED_WIFI_ENABLED, false)
            .putBoolean(MainActivity.PREF_CONNECTION_DESIRED, false)
            .putBoolean("battery_opt_requested", true).commit())
        DiagnosticLogStore.clear(context.noBackupFilesDir)
        DiagnosticLogStore.append(context.noBackupFilesDir, "retained test history")
        VpnServiceImpl.liveStatus = VpnServiceImpl.STATUS_DISCONNECTED
        scenario = ActivityScenario.launch(MainActivity::class.java)
    }

    @After fun clean() {
        receiver?.let(context::unregisterReceiver); receiver = null
        scenario?.close(); scenario = null
        if (previous.isEmpty()) return // Assumption skipped before fixture ownership.
        context.stopService(Intent(context, VpnServiceImpl::class.java))
        awaitStopped()
        DiagnosticLogStore.clear(context.noBackupFilesDir)
        val edit = prefs.edit()
        previous.forEach { (key, value) ->
            when (value) {
                null -> edit.remove(key)
                is Boolean -> edit.putBoolean(key, value)
                is String -> edit.putString(key, value)
                else -> error("unexpected fixture preference type")
            }
        }
        assertTrue(edit.commit())
    }

    private fun settings(owner: MainActivity): Pair<View, CheckBox> {
        call(owner, "showSettingsDialog")
        val type = Class.forName("android.view.WindowManagerGlobal")
        val manager = type.getDeclaredMethod("getInstance").invoke(null)
        @Suppress("UNCHECKED_CAST")
        val windows = type.getDeclaredField("mViews").apply { isAccessible = true }.get(manager) as List<View>
        val root = windows.last { it.findViewById<View>(android.R.id.button1) != null }
        fun children(view: View): List<View> = listOf(view) + if (view is ViewGroup)
            (0 until view.childCount).flatMap { children(view.getChildAt(it)) } else emptyList()
        val toggle = children(root).filterIsInstance<CheckBox>().single {
            it.text.toString() == owner.getString(R.string.clear_log_on_disconnect)
        }
        return root to toggle
    }

    @Test fun defaultsToClearAndOnlySavePersistsAcrossActivityRecreation() {
        scenario!!.onActivity { owner ->
            val (root, toggle) = settings(owner)
            assertTrue(toggle.isChecked)
            toggle.isChecked = false
            root.findViewById<View>(android.R.id.button2).performClick()
            assertFalse(prefs.contains(MainActivity.PREF_CLEAR_LOG_ON_DISCONNECT))
            val (savedRoot, savedToggle) = settings(owner)
            savedToggle.isChecked = false
            savedRoot.findViewById<View>(android.R.id.button1).performClick()
        }
        instrumentation.waitForIdleSync()
        assertFalse(prefs.getBoolean(MainActivity.PREF_CLEAR_LOG_ON_DISCONNECT, true))
        assertTrue(DiagnosticLogStore.read(context.noBackupFilesDir).isNotEmpty())
        scenario!!.recreate()
        scenario!!.onActivity { owner ->
            val (root, toggle) = settings(owner)
            assertFalse(toggle.isChecked)
            toggle.isChecked = true
            root.findViewById<View>(android.R.id.button1).performClick()
        }
        instrumentation.waitForIdleSync()
        assertTrue(prefs.getBoolean(MainActivity.PREF_CLEAR_LOG_ON_DISCONNECT, false))
    }

    private fun stopAndCheck(enabled: Boolean?, withActivity: Boolean = true, fail: Boolean = false) {
        enabled?.let { assertTrue(prefs.edit().putBoolean(MainActivity.PREF_CLEAR_LOG_ON_DISCONNECT, it).commit()) }
        if (!withActivity) { scenario!!.close(); scenario = null }
        val ended = CountDownLatch(1)
        var cleared = false
        receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val expected = if (fail) VpnServiceImpl.STATUS_ERROR else VpnServiceImpl.STATUS_DISCONNECTED
                if (intent.getStringExtra(VpnServiceImpl.EXTRA_STATUS) == expected) {
                    cleared = intent.getBooleanExtra(VpnServiceImpl.EXTRA_LOG_CLEARED, false)
                    ended.countDown()
                }
            }
        }
        ContextCompat.registerReceiver(context, receiver, IntentFilter(VpnServiceImpl.BROADCAST_STATUS), ContextCompat.RECEIVER_NOT_EXPORTED)
        if (fail) {
            ServerSocket(0).use { peer ->
                val worker = Thread { peer.accept().close() }.apply { isDaemon = true; start() }
                val config = VpnConfig.parse("""[qeli]
server = 127.0.0.1:${peer.localPort}
user = log-test
pass = fixture
mode = fake-tls
reconnect = false
kill_switch = false
bind_static = false
timeout = 3
""")
                ContextCompat.startForegroundService(context, Intent(context, VpnServiceImpl::class.java)
                    .setAction(VpnServiceImpl.ACTION_CONNECT).putExtra(VpnServiceImpl.EXTRA_CONFIG, config))
                assertTrue("terminal error missing", ended.await(15, TimeUnit.SECONDS))
                worker.join(3000)
                assertFalse(worker.isAlive)
            }
        } else {
            context.startService(Intent(context, VpnServiceImpl::class.java).setAction(VpnServiceImpl.ACTION_DISCONNECT))
            assertTrue("disconnect broadcast missing", ended.await(15, TimeUnit.SECONDS))
        }
        awaitStopped()
        val shouldClear = !fail && (enabled ?: true)
        assertEquals(shouldClear, cleared)
        val messages = DiagnosticLogStore.read(context.noBackupFilesDir).map { it.message }
        if (shouldClear) assertTrue("late teardown log recreated history: $messages", messages.isEmpty())
        else assertTrue(messages.contains("retained test history"))
        if (fail) {
            assertTrue("connection attempt missing: $messages", messages.any { it.contains("VPN session") })
            assertTrue("terminal reason missing: $messages", messages.any { it.contains("VPN session ending:") })
            assertTrue("underlying connection error missing: $messages", messages.any { it.startsWith("ERR:") })
        }
        scenario?.onActivity { owner ->
            val text = owner.findViewById<TextView>(R.id.tvLog).text.toString()
            if (shouldClear) assertEquals("", text) else assertTrue(text.contains("retained test history"))
        }
    }

    @Test fun absentPreferenceClearsFileAndVisibleLogOnDisconnect() = stopAndCheck(null)
    @Test fun disabledOptionRetainsHistoryAfterServiceDestruction() = stopAndCheck(false)
    @Test fun enabledOptionClearsWithActivityClosed() = stopAndCheck(true, withActivity = false)
    @Test fun terminalConnectionErrorRetainsHistoryWhenEnabled() = stopAndCheck(true, fail = true)
    @Test fun terminalConnectionErrorRetainsHistoryWithDefaultPreference() = stopAndCheck(null, fail = true)
    @Test fun terminalConnectionErrorRetainsHistoryWithActivityClosed() = stopAndCheck(true, withActivity = false, fail = true)
    @Test fun terminalConnectionErrorRetainsHistoryWhenDisabled() = stopAndCheck(false, fail = true)

    @Test fun serverKeyMismatchRetainsLogAndSealsServiceWriterWithDefaultPreference() {
        val service = VpnServiceImpl()
        ContextWrapper::class.java.getDeclaredMethod("attachBaseContext", Context::class.java)
            .apply { isAccessible = true }.invoke(service, context)
        val pins = context.getSharedPreferences("qeli_known_hosts", Context.MODE_PRIVATE)
        val server = "log-fixture.invalid:443"
        val previousPin = pins.getString(server, null)
        try {
            assertTrue(pins.edit().putString(server, "11".repeat(32)).commit())
            val verify = VpnServiceImpl::class.java.getDeclaredMethod(
                "checkKnownHost", String::class.java, String::class.java).apply { isAccessible = true }
            val error = try {
                verify.invoke(service, server, "22".repeat(32))
                throw AssertionError("changed server key was accepted")
            } catch (wrapped: InvocationTargetException) {
                wrapped.cause as SecurityException
            }
            assertTrue(error.message!!.contains("SERVER KEY MISMATCH"))
            val log = VpnServiceImpl::class.java.getDeclaredMethod(
                "broadcastLog", String::class.java, String::class.java).apply { isAccessible = true }
            log.invoke(service, "[SECURITY] ${error.message}", "error")
            val finish = VpnServiceImpl::class.java.getDeclaredMethod(
                "finishDiagnosticSession", Boolean::class.javaPrimitiveType, Continuation::class.java
            ).apply { isAccessible = true }
            val cleared = runBlocking {
                suspendCoroutineUninterceptedOrReturn<Boolean> { continuation ->
                    finish.invoke(service, true, continuation)
                }
            }
            assertFalse("security failure must not announce log cleanup", cleared)
            log.invoke(service, "late teardown callback", "info")
            val entries = DiagnosticLogStore.read(context.noBackupFilesDir)
            assertTrue(entries.any { it.level == "error" && it.message.contains("SERVER KEY MISMATCH") })
            assertFalse(entries.any { it.message == "late teardown callback" })
            instrumentation.waitForIdleSync()
            scenario!!.onActivity { owner ->
                assertTrue(owner.findViewById<TextView>(R.id.tvLog).text.contains("SERVER KEY MISMATCH"))
            }
            scenario!!.recreate()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            var restored = false
            while (!restored && System.nanoTime() < deadline) {
                scenario!!.onActivity { owner ->
                    restored = owner.findViewById<TextView>(R.id.tvLog).text.contains("SERVER KEY MISMATCH")
                }
                if (!restored) Thread.sleep(25)
            }
            assertTrue("security failure log was lost after Activity recreation", restored)
        } finally {
            assertTrue(pins.edit().apply {
                if (previousPin == null) remove(server) else putString(server, previousPin)
            }.commit())
            (VpnServiceImpl::class.java.getDeclaredField("carrierDnsExecutor").apply { isAccessible = true }
                .get(service) as java.util.concurrent.ExecutorService).shutdownNow()
        }
    }
}
