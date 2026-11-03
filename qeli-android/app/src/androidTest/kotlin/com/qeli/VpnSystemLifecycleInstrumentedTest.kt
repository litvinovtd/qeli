package com.qeli

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Process
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.qeli.model.VpnConfig
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Ordered by the private lab driver; no in-process stop/revoke simulation or cleanup. */
@RunWith(AndroidJUnit4::class)
class VpnSystemLifecycleInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val args = InstrumentationRegistry.getArguments()
    private val prefs get() = context.getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
    private fun fixture() = assumeTrue("private fixture arguments required", args.getString("q29_private_fixture") == "1")
    @Suppress("DEPRECATION")
    private fun service() = context.getSystemService(ActivityManager::class.java).getRunningServices(100)
        .firstOrNull { it.service.className == VpnServiceImpl::class.java.name }
    private fun await(message: String, condition: () -> Boolean) {
        val until = System.nanoTime() + 30_000_000_000L
        while (System.nanoTime() < until) {
            if (condition()) return
            Thread.sleep(25)
        }
        fail(message)
    }
    private fun traffic(profile: String) {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        await("framework VPN not ready") {
            cm.activeNetwork?.let { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) } == true
        }
        assertNull(cm.boundNetworkForProcess)
        for (address in listOf("198.19.0.1", "2001:db8:29::1")) {
            val host = InetAddress.getByName(address)
            await("ordinary source not ready for $address") {
                DatagramSocket().use { probe ->
                    probe.connect(host, 26000)
                    probe.localAddress.hostAddress == VpnServiceImpl.liveIp || probe.localAddress.hostAddress?.startsWith(if (profile == "tcp") "fd86:29:1:" else "fd86:29:2:") == true
                }
            }
            val payload = ByteArray(16384) { ((it * 31 + 17) % 251).toByte() }
            Socket().use { socket ->
                socket.soTimeout = 8000
                socket.connect(InetSocketAddress(host, 26000), 8000)
                DataOutputStream(socket.getOutputStream()).apply { writeInt(payload.size); write(payload); flush() }
                val input = DataInputStream(socket.getInputStream()); assertEquals(payload.size, input.readInt())
                val reply = ByteArray(payload.size); input.readFully(reply); assertArrayEquals(payload.reversedArray(), reply)
            }
            DatagramSocket().use { socket ->
                socket.soTimeout = 8000; socket.connect(host, 26000)
                val data = payload.copyOf(257); socket.send(DatagramPacket(data, data.size))
                val packet = DatagramPacket(ByteArray(2048), 2048); socket.receive(packet)
                assertArrayEquals("Q29:".toByteArray() + data, packet.data.copyOfRange(0, packet.length))
            }
        }
        Log.i("Q29System", "PAYLOAD_PASS pid=${Process.myPid()} lockdown=${VpnServiceImpl.liveLockdown}")
    }
    @Test fun bootstrapSavedProfileAndLeaveConnected() {
        fixture()
        assertNull(VpnService.prepare(context))
        val transport = args.getString("q29_transport", "tcp")
        require(transport in listOf("tcp", "udp", "quic"))
        val profile = if (transport == "tcp") "tcp" else "udp"
        val roaming = args.getString("q29_roaming", "off")
        require(roaming in listOf("off", "required"))
        val key = requireNotNull(args.getString("q29_key_$profile"))
        val config = VpnConfig(serverAddress = "10.0.2.2", port = if (profile == "tcp") 24966 else 24967, protocol = profile, quicEnabled = transport == "quic", wireMode = "fake-tls",
            username = "fixture", password = "fixture-password", serverPublicKeyHex = key, bindStaticToSession = true,
            routingMode = "full-tunnel", addDefaultGateway = true, killSwitch = true, ipv6 = "required",
            dnsMode = "off", roaming = roaming, mtuProbe = false, reconnectEnabled = true,
            reconnectBaseDelaySecs = 1, reconnectMaxDelaySecs = 2, connectionTimeoutSecs = 15, loggingLevel = "debug")
        config.validate()
        val text = config.toIni("system fixture")
        val saved = JSONObject().put("active", 0).put("profiles", JSONArray().put(JSONObject().put("name", "system fixture").put("cfg", text))).toString()
        assertTrue(ProfileStore.open(context).edit().putString(ProfileStore.KEY_PROFILES, saved).commit())
        assertEquals(text, ProfileStore.activeProfileConfigText(context))
        assertTrue(prefs.edit().putBoolean(MainActivity.PREF_TRUSTED_WIFI_ENABLED, false)
            .putBoolean(MainActivity.PREF_CONNECTION_DESIRED, true).commit())
        context.startForegroundService(Intent(context, VpnServiceImpl::class.java).setAction(VpnServiceImpl.ACTION_CONNECT)
            .putExtra(VpnServiceImpl.EXTRA_CONFIG, config.copy(killSwitch = false)))
        await("bootstrap did not connect") { service()?.foreground == true && VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_CONNECTED }
        traffic(profile)
    }
}
