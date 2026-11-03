package com.qeli

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.qeli.model.VpnConfig
import java.io.Closeable
import java.io.FileInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Before
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Start the actual framework-owned service and blocking JNI; no reflected service objects. */
@RunWith(AndroidJUnit4::class)
class ForegroundServiceLifecycleInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val prefs get() = context.getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
    private var originalClearLog: Boolean? = null
    @Suppress("DEPRECATION")
    private fun service() = context.getSystemService(ActivityManager::class.java)
        .getRunningServices(100).firstOrNull { it.service.className == VpnServiceImpl::class.java.name }
    private fun waitFor(message: String, timeoutMs: Long = 10_000, condition: () -> Boolean) {
        val until = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        while (!condition() && System.nanoTime() < until) Thread.sleep(20)
        assertTrue(message, condition())
    }
    private fun shell(command: String): String = instrumentation.uiAutomation.executeShellCommand(command).use {
        FileInputStream(it.fileDescriptor).use { input -> input.readBytes().toString(Charsets.UTF_8) }
    }
    @Before fun prepare() {
        originalClearLog = if (prefs.contains(MainActivity.PREF_CLEAR_LOG_ON_DISCONNECT))
            prefs.getBoolean(MainActivity.PREF_CLEAR_LOG_ON_DISCONNECT, true) else null
        assertNull("grant ACTIVATE_VPN on the disposable AVD", VpnService.prepare(context))
        context.stopService(Intent(context, VpnServiceImpl::class.java))
        waitFor("preceding service still running") { service() == null }
        assertTrue(prefs.edit().putBoolean(MainActivity.PREF_CONNECTION_DESIRED, false)
            .putBoolean(MainActivity.PREF_TRUSTED_WIFI_ENABLED, false).commit())
        VpnServiceImpl.liveStatus = VpnServiceImpl.STATUS_DISCONNECTED
    }
    @After fun clean() {
        if (service() != null) context.startService(Intent(context, VpnServiceImpl::class.java)
            .setAction(VpnServiceImpl.ACTION_DISCONNECT))
        waitFor("service did not stop during cleanup", 15_000) { service() == null }
        assertTrue(prefs.edit().putBoolean(MainActivity.PREF_CONNECTION_DESIRED, false).commit())
        val editor = prefs.edit()
        originalClearLog?.let { editor.putBoolean(MainActivity.PREF_CLEAR_LOG_ON_DISCONNECT, it) }
            ?: editor.remove(MainActivity.PREF_CLEAR_LOG_ON_DISCONNECT)
        assertTrue(editor.commit())
        VpnServiceImpl.liveStatus = VpnServiceImpl.STATUS_DISCONNECTED
    }
    private class StallPeer : Closeable {
        private val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port get() = server.localPort
        val firstByte = CountDownLatch(1)
        val clientClosed = CountDownLatch(1)
        @Volatile private var accepted: Socket? = null
        @Volatile private var localClose = false
        private val worker = Thread {
            try {
                val socket = server.accept(); accepted = socket
                socket.getInputStream().use { input ->
                    if (input.read() >= 0) firstByte.countDown()
                    while (input.read() >= 0) { /* Deliberately no server handshake response. */ }
                }
                if (!localClose) clientClosed.countDown()
            } catch (_: Exception) { if (accepted != null && !localClose) clientClosed.countDown() }
        }.apply { name = "qeli-service-stall-peer"; isDaemon = true; start() }
        override fun close() {
            localClose = true; server.close(); accepted?.close(); worker.join(3000)
            assertFalse("stall peer thread remained", worker.isAlive)
        }
    }
    private fun config(peer: StallPeer) = VpnConfig(
        serverAddress = "127.0.0.1", port = peer.port, username = "service-fixture", password = "fixture",
        protocol = "tcp", wireMode = "fake-tls", bindStaticToSession = false,
        connectionTimeoutSecs = 30, reconnectEnabled = false, killSwitch = false, mtuProbe = false,
    )
    private fun connect(peer: StallPeer) {
        val config = config(peer); config.validate()
        assertNotNull(context.startForegroundService(Intent(context, VpnServiceImpl::class.java)
            .setAction(VpnServiceImpl.ACTION_CONNECT).putExtra(VpnServiceImpl.EXTRA_CONFIG, config)))
        assertTrue("real native transport did not send ClientHello", peer.firstByte.await(10, TimeUnit.SECONDS))
        waitFor("foreground service not connecting") {
            service()?.foreground == true && VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_CONNECTING
        }
        assertTrue(prefs.getBoolean(MainActivity.PREF_CONNECTION_DESIRED, false))
    }
    private fun disconnect(peer: StallPeer) {
        context.startService(Intent(context, VpnServiceImpl::class.java).setAction(VpnServiceImpl.ACTION_DISCONNECT))
        waitFor("manual disconnect did not finish") {
            service() == null && VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_DISCONNECTED
        }
        assertTrue("manual disconnect left native socket open", peer.clientClosed.await(3, TimeUnit.SECONDS))
        assertFalse(prefs.getBoolean(MainActivity.PREF_CONNECTION_DESIRED, true))
    }
    @Test fun rejectedCommandsDoNotReplaceLiveConnectingStatus() {
        StallPeer().use { peer ->
            connect(peer)
            for (bad in listOf<VpnConfig?>(null, config(peer).copy(port = 0))) {
                shell("logcat -c")
                val intent = Intent(context, VpnServiceImpl::class.java).setAction(VpnServiceImpl.ACTION_CONNECT)
                if (bad != null) intent.putExtra(VpnServiceImpl.EXTRA_CONFIG, bad)
                context.startForegroundService(intent)
                waitFor("invalid command was not processed") { shell("logcat -d -s VpnSvc:E").contains("Invalid profile:") }
                instrumentation.waitForIdleSync()
                assertEquals("rejecting a new command must preserve the active session status",
                    VpnServiceImpl.STATUS_CONNECTING, VpnServiceImpl.liveStatus)
                assertTrue(service()?.foreground == true)
                assertTrue(prefs.getBoolean(MainActivity.PREF_CONNECTION_DESIRED, false))
                assertEquals(1L, peer.clientClosed.count)
            }
            context.startService(Intent(context, VpnServiceImpl::class.java).setAction("com.qeli.FIXTURE_UNKNOWN"))
            instrumentation.waitForIdleSync()
            assertEquals(VpnServiceImpl.STATUS_CONNECTING, VpnServiceImpl.liveStatus)
            disconnect(peer)
        }
    }
    @Test fun manualDisconnectCancelsHandshakeAndFreshStartWorks() {
        repeat(3) { StallPeer().use { peer -> connect(peer); disconnect(peer) } }
    }
    @Test fun systemStopDestroysServiceCancelsNativeAndPreservesDesiredIntent() {
        StallPeer().use { peer ->
            connect(peer)
            assertTrue(context.stopService(Intent(context, VpnServiceImpl::class.java)))
            waitFor("framework did not destroy the service") { service() == null }
            assertTrue("onDestroy left native runner/socket alive", peer.clientClosed.await(5, TimeUnit.SECONDS))
            assertTrue("unexpected destruction erased reconnect intent",
                prefs.getBoolean(MainActivity.PREF_CONNECTION_DESIRED, false))
        }
        StallPeer().use { peer -> connect(peer); disconnect(peer) }
    }
    @Test fun exhaustedRetryStopsServiceAndPublishesTerminalError() {
        // This case inspects retained diagnostics. Default-on cleanup is covered separately.
        assertTrue(prefs.edit().putBoolean(MainActivity.PREF_CLEAR_LOG_ON_DISCONNECT, false).commit())
        StallPeer().use { peer -> connect(peer) } // Server EOF causes the real handshake to fail.
        waitFor("disabled reconnect did not finish teardown", 15_000) {
            service() == null && VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_ERROR
        }
        assertTrue("failure must preserve user connection intent",
            prefs.getBoolean(MainActivity.PREF_CONNECTION_DESIRED, false))
        assertTrue(DiagnosticLogStore.read(context.noBackupFilesDir).any {
            it.message.contains("Reconnect is disabled")
        })
    }
    @Test fun initialInvalidForegroundCommandStopsWithError() {
        context.startForegroundService(Intent(context, VpnServiceImpl::class.java)
            .setAction(VpnServiceImpl.ACTION_CONNECT))
        waitFor("invalid initial command did not stop with ERROR") {
            service() == null && VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_ERROR
        }
        assertFalse(prefs.getBoolean(MainActivity.PREF_CONNECTION_DESIRED, true))
    }
}
