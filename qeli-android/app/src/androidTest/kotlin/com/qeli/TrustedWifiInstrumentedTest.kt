package com.qeli

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.net.wifi.WifiManager
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.qeli.model.VpnConfig
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.FileInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Real SSID, carrier callbacks, framework service and authenticated JNI in the private lab. */
@RunWith(AndroidJUnit4::class)
class TrustedWifiInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val args = InstrumentationRegistry.getArguments()
    private val prefs get() = context.getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
    private val cm get() = context.getSystemService(ConnectivityManager::class.java)
    private var armed = false
    private var scenario: ActivityScenario<MainActivity>? = null
    private lateinit var ssid: String
    @Suppress("DEPRECATION")
    private fun service() = context.getSystemService(ActivityManager::class.java)
        .getRunningServices(100).firstOrNull { it.service.className == VpnServiceImpl::class.java.name }
    private fun waitFor(message: String, timeoutMs: Long = 20_000, condition: () -> Boolean) {
        val until = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        while (!condition() && System.nanoTime() < until) Thread.sleep(30)
        assertTrue(message, condition())
    }
    private fun shell(command: String) = instrumentation.uiAutomation.executeShellCommand(command).use {
        FileInputStream(it.fileDescriptor).use { input -> input.readBytes().toString(Charsets.UTF_8) }
    }
    private fun hasTun() = Regex("(?m)^\\d+: tun\\d").containsMatchIn(shell("su 0 ip -o link show"))
    @Suppress("DEPRECATION")
    private fun observedSsid() = TrustedWifiPolicy.normalizeObservedSsid(
        context.getSystemService(WifiManager::class.java).connectionInfo.ssid)
    @Before fun prepare() {
        assumeTrue("private lab arguments required", args.getString("q29_private_fixture") == "1")
        armed = true
        assertNull(VpnService.prepare(context))
        context.stopService(Intent(context, VpnServiceImpl::class.java))
        waitFor("previous service remained") { service() == null }
        assertTrue(prefs.edit().putBoolean(MainActivity.PREF_CONNECTION_DESIRED, false)
            .putBoolean(MainActivity.PREF_TRUSTED_WIFI_ENABLED, false)
            .putBoolean(MainActivity.PREF_AUTO_CONNECT_LAUNCH, false)
            .putBoolean("battery_opt_requested", true).commit())
        shell("svc wifi enable")
        scenario = ActivityScenario.launch(MainActivity::class.java)
        waitFor("visible UI or real Wi-Fi SSID absent") {
            MainActivity.uiVisible && observedSsid() != null && cm.activeNetwork?.let {
                cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
            } == true
        }
        ssid = requireNotNull(observedSsid())
        assertFalse(ssid.isBlank())
        android.util.Log.i("Q29Trusted", "OBSERVED_SSID=$ssid")
    }
    @After fun cleanup() {
        if (!armed) return
        if (service() != null) context.startService(Intent(context, VpnServiceImpl::class.java)
            .setAction(VpnServiceImpl.ACTION_DISCONNECT))
        waitFor("trusted controller remained after cleanup") { service() == null }
        assertFalse("native/Java TUN remained", hasTun())
        assertTrue(prefs.edit().putBoolean(MainActivity.PREF_CONNECTION_DESIRED, false)
            .putBoolean(MainActivity.PREF_TRUSTED_WIFI_ENABLED, false).commit())
        scenario?.close(); scenario = null
        shell("cmd location set-location-enabled true")
        shell("svc wifi enable")
    }
    private fun config(killSwitch: Boolean = false) = VpnConfig(
        serverAddress = "10.0.2.2", port = 24966, protocol = "tcp", wireMode = "fake-tls",
        username = "fixture", password = "fixture-password",
        serverPublicKeyHex = requireNotNull(args.getString("q29_key_tcp")),
        bindStaticToSession = true, connectionTimeoutSecs = 15, reconnectEnabled = true,
        killSwitch = killSwitch, mtuProbe = false, ipv6 = "required", roaming = "off",
        routingMode = "full-tunnel", addDefaultGateway = true, dnsMode = "off",
        loggingLevel = "debug").also { it.validate() }
    private fun trust(enabled: Boolean) {
        assertTrue(prefs.edit().putBoolean(MainActivity.PREF_TRUSTED_WIFI_ENABLED, enabled)
            .putString(MainActivity.PREF_TRUSTED_WIFI_SSIDS, ssid).commit())
    }
    private fun start(killSwitch: Boolean = false) {
        context.startForegroundService(Intent(context, VpnServiceImpl::class.java)
            .setAction(VpnServiceImpl.ACTION_CONNECT).putExtra(VpnServiceImpl.EXTRA_CONFIG, config(killSwitch)))
    }
    private fun reevaluate() = context.startService(Intent(context, VpnServiceImpl::class.java)
        .setAction(VpnServiceImpl.ACTION_REEVALUATE_TRUSTED))
    private fun waiting() {
        waitFor("trusted SSID did not pause the real service") {
            service()?.foreground == true && VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_WAITING_TRUSTED
        }
        assertEquals(ssid, VpnServiceImpl.liveTrustedSsid)
        assertTrue(prefs.getBoolean(MainActivity.PREF_CONNECTION_DESIRED, false))
        assertFalse("trusted pause left TUN open", hasTun())
        assertEquals("", VpnServiceImpl.liveIp)
    }
    private fun connected() {
        waitFor("real service did not restore authenticated TUN", 30_000) {
            service()?.foreground == true && VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_CONNECTED
        }
        assertTrue(hasTun())
        assertTrue(VpnServiceImpl.liveIp.startsWith("10.86.0."))
        assertEquals("", VpnServiceImpl.liveTrustedSsid)
    }
    private fun traffic(stage: String) {
        val network = requireNotNull(cm.activeNetwork)
        assertTrue(cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true)
        for (address in listOf("198.19.0.1", "2001:db8:29::1")) {
            val host = InetAddress.getByName(address)
            val data = ByteArray(257) { ((it * 31 + 17) % 251).toByte() }
            waitFor("VPN source not ready") {
                DatagramSocket().use { socket ->
                    network.bindSocket(socket); socket.connect(host, 26000)
                    socket.localAddress.hostAddress.orEmpty().let { it.startsWith("10.86.0.") || it.startsWith("fd86:29:1:") }
                }
            }
            DatagramSocket().use { socket ->
                network.bindSocket(socket); socket.connect(host, 26000); socket.soTimeout = 8000
                socket.send(DatagramPacket(data, data.size))
                val reply = DatagramPacket(ByteArray(1024), 1024); socket.receive(reply)
                assertArrayEquals("UDP $stage $address", "Q29:".toByteArray() + data,
                    reply.data.copyOfRange(reply.offset, reply.offset + reply.length))
            }
            val payload = ByteArray(16384) { ((it * 31 + 17) % 251).toByte() }
            network.socketFactory.createSocket().use { socket ->
                socket.soTimeout = 8000; socket.connect(InetSocketAddress(host, 26000), 8000)
                DataOutputStream(socket.getOutputStream()).apply { writeInt(payload.size); write(payload); flush() }
                val input = DataInputStream(socket.getInputStream()); assertEquals(payload.size, input.readInt())
                val reply = ByteArray(payload.size); input.readFully(reply)
                assertArrayEquals("TCP $stage $address", payload.reversedArray(), reply)
            }
        }
        android.util.Log.i("Q29Trusted", "FULL_PAYLOAD_PASS stage=$stage ipv4_ipv6_tcp_udp=4")
    }
    private fun disconnect() {
        context.startService(Intent(context, VpnServiceImpl::class.java).setAction(VpnServiceImpl.ACTION_DISCONNECT))
        waitFor("manual stop did not finish") { service() == null && VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_DISCONNECTED }
        assertFalse(prefs.getBoolean(MainActivity.PREF_CONNECTION_DESIRED, true))
        assertFalse(hasTun())
    }
    @Test fun coldTrustedPauseSurvivesBackgroundAndActualCarrierCycle() {
        trust(true); start(); waiting()
        scenario!!.moveToState(Lifecycle.State.CREATED)
        assertFalse(MainActivity.uiVisible)
        Thread.sleep(1200); waiting() // Location foreground type retains real SSID visibility.
        shell("svc wifi disable"); connected(); traffic("cold-cellular")
        shell("svc wifi enable"); waiting()
        scenario!!.moveToState(Lifecycle.State.RESUMED)
        trust(false); reevaluate(); connected(); traffic("policy-disabled")
        disconnect()
    }
    @Test fun livePauseAndDisconnectCancelDelayedResume() {
        start(); connected(); traffic("before-live-pause")
        trust(true); reevaluate(); waiting()
        trust(false); reevaluate() // Arms the real 250ms resume job.
        context.startService(Intent(context, VpnServiceImpl::class.java).setAction(VpnServiceImpl.ACTION_DISCONNECT))
        waitFor("disconnect during delayed resume left service") { service() == null }
        Thread.sleep(1200)
        assertNull("delayed trusted resume resurrected service", service())
        assertFalse(hasTun()); assertFalse(prefs.getBoolean(MainActivity.PREF_CONNECTION_DESIRED, true))
        start(); connected(); traffic("explicit-restart"); disconnect()
    }
    @Test fun killSwitchCannotBeBypassedByTrustedSsid() {
        trust(true); start(killSwitch = true)
        waitFor("kill-switch refused connection did not terminate") {
            service() == null && VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_ERROR
        }
        assertFalse(hasTun())
        assertNotEquals(VpnServiceImpl.STATUS_WAITING_TRUSTED, VpnServiceImpl.liveStatus)
    }

    @Test fun actualLocationRedactionRestoresTunAndReadableSsidCanPauseAgain() {
        trust(true); start(); waiting()
        shell("cmd location set-location-enabled false")
        waitFor("Android did not redact the SSID") { observedSsid() == null }
        reevaluate(); connected(); traffic("ssid-redacted")
        shell("cmd location set-location-enabled true")
        waitFor("SSID visibility did not return") { observedSsid() == ssid }
        reevaluate(); waiting()
        trust(false); reevaluate(); connected(); traffic("ssid-readable-restored")
        disconnect()
    }
    @Test fun queuedPauseThenDisconnectDoesNotResurrectConnection() {
        start(); connected()
        trust(true); reevaluate()
        context.startService(Intent(context, VpnServiceImpl::class.java)
            .setAction(VpnServiceImpl.ACTION_DISCONNECT))
        waitFor("queued disconnect did not remove the controller") { service() == null }
        Thread.sleep(1200)
        assertNull(service()); assertFalse(hasTun())
        assertFalse(prefs.getBoolean(MainActivity.PREF_CONNECTION_DESIRED, true))
        trust(false); start(); connected(); traffic("queued-stop-explicit-restart")
        disconnect()
    }
}
