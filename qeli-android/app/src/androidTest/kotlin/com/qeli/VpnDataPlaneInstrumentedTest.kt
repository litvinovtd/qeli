package com.qeli

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Network
import android.util.Log
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
import java.net.Socket
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assume.assumeTrue
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Requires scripts/audit_android_data_plane_lab.py's private server and disposable AVD. */
@RunWith(AndroidJUnit4::class)
class VpnDataPlaneInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val args = InstrumentationRegistry.getArguments()
    private val prefs get() = context.getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
    private var armed = false
    @Suppress("DEPRECATION")
    private fun service() = context.getSystemService(ActivityManager::class.java)
        .getRunningServices(100).firstOrNull { it.service.className == VpnServiceImpl::class.java.name }
    private fun waitFor(message: String, timeoutMs: Long = 15_000, condition: () -> Boolean) {
        val until = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        while (!condition() && System.nanoTime() < until) Thread.sleep(25)
        assertTrue(message, condition())
    }
    private fun shell(command: String) = instrumentation.uiAutomation.executeShellCommand(command).use {
        FileInputStream(it.fileDescriptor).use { input -> input.readBytes().toString(Charsets.UTF_8) }
    }
    @Before fun prepare() {
        assumeTrue("private fixture arguments required", args.getString("q29_private_fixture") == "1")
        armed = true
        assertNull("fixture must grant ACTIVATE_VPN", VpnService.prepare(context))
        context.stopService(Intent(context, VpnServiceImpl::class.java))
        waitFor("previous service remained") { service() == null }
        assertTrue(prefs.edit().putBoolean(MainActivity.PREF_CONNECTION_DESIRED, false)
            .putBoolean(MainActivity.PREF_TRUSTED_WIFI_ENABLED, false).commit())
    }
    @After fun cleanup() {
        if (!armed) return
        if (service() != null) context.startService(Intent(context, VpnServiceImpl::class.java)
            .setAction(VpnServiceImpl.ACTION_DISCONNECT))
        waitFor("service did not finish teardown") { service() == null }
        assertTrue(prefs.edit().putBoolean(MainActivity.PREF_CONNECTION_DESIRED, false).commit())
    }
    private fun disconnect() {
        context.startService(Intent(context, VpnServiceImpl::class.java).setAction(VpnServiceImpl.ACTION_DISCONNECT))
        waitFor("manual disconnect did not finish") {
            service() == null && VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_DISCONNECTED
        }
        assertFalse(prefs.getBoolean(MainActivity.PREF_CONNECTION_DESIRED, true))
        assertFalse("Java/native TUN remained", Regex("(?m)^\\d+: tun\\d").containsMatchIn(shell("su 0 ip -o link show")))
    }
    private fun traffic(address: String, explicitNetwork: Boolean = true) {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val network: Network = requireNotNull(cm.activeNetwork)
        assertTrue(cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true)
        val host = InetAddress.getByName(address)
        // LinkProperties publication can precede netd route/source selection on a fresh VPN.
        // Inspect an unsent UDP socket; do not start a TCP stream with a physical source.
        waitFor("kernel VPN route/source not ready for $address") {
            DatagramSocket().use { probe ->
                if (explicitNetwork) network.bindSocket(probe)
                probe.connect(host, 26000)
                val source = probe.localAddress.hostAddress.orEmpty()
                source == VpnServiceImpl.liveIp || (address.contains(':') && source.startsWith("fd86:29:"))
            }
        }
        val payload = ByteArray(16_384) { ((it * 31 + 17) % 251).toByte() }
        (if (explicitNetwork) network.socketFactory.createSocket() else Socket()).use { socket ->
            socket.soTimeout = 8000
            socket.connect(InetSocketAddress(host, 26000), 8000)
            Log.i("Q29Traffic", "TCP destination=$address source=${socket.localAddress.hostAddress} explicit=$explicitNetwork vpn=$network default=${cm.activeNetwork} process=${cm.boundNetworkForProcess}")
            assertTrue("TCP socket must originate from assigned TUN", socket.localAddress.hostAddress?.let {
                it == VpnServiceImpl.liveIp || it.startsWith("fd86:29:")
            } == true)
            DataOutputStream(socket.getOutputStream()).apply { writeInt(payload.size); write(payload); flush() }
            val input = DataInputStream(socket.getInputStream())
            assertEquals(payload.size, input.readInt())
            val reply = ByteArray(payload.size); input.readFully(reply)
            assertArrayEquals("TCP reply through $address", payload.reversedArray(), reply)
        }
        DatagramSocket().use { socket ->
            socket.soTimeout = 8000
            if (explicitNetwork) network.bindSocket(socket)
            socket.connect(host, 26000)
            Log.i("Q29Traffic", "UDP destination=$address source=${socket.localAddress.hostAddress} explicit=$explicitNetwork vpn=$network")
            for (size in listOf(32, 257, 1024)) {
                val data = payload.copyOf(size)
                socket.send(DatagramPacket(data, data.size))
                val packet = DatagramPacket(ByteArray(2048), 2048); socket.receive(packet)
                assertArrayEquals("UDP reply through $address", "Q29:".toByteArray() + data,
                    packet.data.copyOfRange(packet.offset, packet.offset + packet.length))
            }
        }
    }
    private fun exercise(protocol: String, quic: Boolean, profile: String, explicitNetwork: Boolean = true, fullTunnel: Boolean = false, routed: Boolean = false) {
        val key = requireNotNull(args.getString("q29_key_$profile"))
        assertTrue(key.matches(Regex("[0-9a-f]{64}")))
        val config = VpnConfig(serverAddress = "10.0.2.2", port = if (profile == "tcp") 24966 else 24967,
            protocol = protocol, quicEnabled = quic, wireMode = "fake-tls", username = "fixture",
            password = "fixture-password", serverPublicKeyHex = key, bindStaticToSession = true,
            connectionTimeoutSecs = 15, reconnectEnabled = false, killSwitch = false,
            mtuProbe = false, ipv6 = "required", roaming = "off", routingMode = if (fullTunnel) "full-tunnel" else "split-tunnel",
            addDefaultGateway = fullTunnel, dnsMode = if (routed) "tunnel" else "off",
            dnsServers = if (routed) listOf("198.19.0.53") else emptyList(), heartbeatEnabled = true,
            includeRoutes = if (routed) {
                if (fullTunnel) emptyList() else listOf("198.19.0.1/32", "2001:db8:29::1/128")
            } else if (profile == "tcp") listOf("10.86.0.0/24", "fd86:29:1::/120")
                else listOf("10.87.0.0/24", "fd86:29:2::/120"),
            loggingLevel = "debug")
        config.validate()
        // TCP also verifies a completed teardown followed by a new authenticated start.
        repeat(if (explicitNetwork && profile == "tcp") 2 else 1) {
            assertNotNull(context.startForegroundService(Intent(context, VpnServiceImpl::class.java)
                .setAction(VpnServiceImpl.ACTION_CONNECT).putExtra(VpnServiceImpl.EXTRA_CONFIG, config)))
            waitFor("authenticated dual TUN did not enter CONNECTED", 25_000) {
                service()?.foreground == true && VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_CONNECTED
            }
            val cm = context.getSystemService(ConnectivityManager::class.java)
            val connectedObserved = System.nanoTime()
            if (!explicitNetwork) {
                assertNull("default socket test must not bind the process", cm.boundNetworkForProcess)
                val destinations = if (routed) listOf("198.19.0.1", "2001:db8:29::1") else if (profile == "tcp") listOf("10.86.0.1", "fd86:29:1::1")
                    else listOf("10.87.0.1", "fd86:29:2::1")
                for (address in destinations) {
                    var firstSource: String? = null
                    var attempts = 0
                    waitFor("ordinary socket route/source not ready for $address") {
                        DatagramSocket().use { probe ->
                            probe.connect(InetAddress.getByName(address), 26000)
                            val source = probe.localAddress.hostAddress.orEmpty()
                            if (firstSource == null) firstSource = source
                            attempts++
                            source == VpnServiceImpl.liveIp || (address.contains(':') && source.startsWith("fd86:29:"))
                        }
                    }
                    Log.i("Q29Traffic", "DEFAULT_READY destination=$address full=$fullTunnel first=$firstSource attempts=$attempts elapsedMs=${TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - connectedObserved)} default=${cm.activeNetwork} process=${cm.boundNetworkForProcess}")
                }
            }
            waitFor("framework VPN default network not published") {
                cm.activeNetwork?.let { network ->
                    cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true &&
                        cm.getLinkProperties(network)?.linkAddresses?.any { it.address.hostAddress == VpnServiceImpl.liveIp } == true
                } == true
            }
            if (routed) {
                val links = requireNotNull(cm.getLinkProperties(requireNotNull(cm.activeNetwork)))
                assertEquals(listOf("198.19.0.53"), links.dnsServers.map { it.hostAddress })
                val defaultRoutes = links.routes.filter { it.isDefaultRoute }
                val defaults = defaultRoutes.map { it.destination.toString() }.toSet()
                if (fullTunnel) assertTrue("both default routes missing: $defaults", defaultRoutes.any { it.destination.address is java.net.Inet4Address } && defaultRoutes.any { it.destination.address is java.net.Inet6Address })
                else assertTrue("split tunnel has a default route: $defaults", defaults.isEmpty())
                val name = "q29-${System.nanoTime()}.test"
                val resolved = InetAddress.getAllByName(name).map { it.hostAddress }.toSet()
                assertTrue("system DNS did not return fixture A: $resolved", "198.19.0.1" in resolved)
                Log.i("Q29Traffic", "SYSTEM_DNS name=$name answers=$resolved routes=${links.routes}")
            }
            val properties = VpnServiceImpl.liveConnectionProperties
            assertNotNull(properties)
            assertTrue(VpnServiceImpl.liveIp.startsWith(if (profile == "tcp") "10.86.0." else "10.87.0."))
            traffic(if (routed) "198.19.0.1" else if (profile == "tcp") "10.86.0.1" else "10.87.0.1", explicitNetwork)
            traffic(if (routed) "2001:db8:29::1" else if (profile == "tcp") "fd86:29:1::1" else "fd86:29:2::1", explicitNetwork)
            // Verify F278 on CONNECTED after real traffic, with receipt of the rejected command.
            val precedingErrors = shell("logcat -d -s VpnSvc:E").split("Invalid profile:").size
            context.startForegroundService(Intent(context, VpnServiceImpl::class.java)
                .setAction(VpnServiceImpl.ACTION_CONNECT).putExtra(VpnServiceImpl.EXTRA_CONFIG, config.copy(port = 0)))
            waitFor("invalid command not processed") { shell("logcat -d -s VpnSvc:E").split("Invalid profile:").size > precedingErrors }
            instrumentation.waitForIdleSync()
            assertEquals(VpnServiceImpl.STATUS_CONNECTED, VpnServiceImpl.liveStatus)
            assertSame("rejected command replaced negotiated properties", properties, VpnServiceImpl.liveConnectionProperties)
            assertTrue(service()?.foreground == true)
            assertTrue(prefs.getBoolean(MainActivity.PREF_CONNECTION_DESIRED, false))
            traffic(if (routed) "198.19.0.1" else if (profile == "tcp") "10.86.0.1" else "10.87.0.1", explicitNetwork)
            disconnect()
        }
    }
    @Test fun tcpDualStackPayloadAndCompletedRestart() = exercise("tcp", false, "tcp")
    @Test fun udpDualStackPayload() = exercise("udp", false, "udp")
    @Test fun quicDualStackPayload() = exercise("udp", true, "udp")
    @Test fun tcpOrdinarySplitPayload() = exercise("tcp", false, "tcp", explicitNetwork = false)
    @Test fun udpOrdinarySplitPayload() = exercise("udp", false, "udp", explicitNetwork = false)
    @Test fun quicOrdinarySplitPayload() = exercise("udp", true, "udp", explicitNetwork = false)
    @Test fun tcpOrdinaryFullPayload() = exercise("tcp", false, "tcp", explicitNetwork = false, fullTunnel = true)
    @Test fun udpOrdinaryFullPayload() = exercise("udp", false, "udp", explicitNetwork = false, fullTunnel = true)
    @Test fun quicOrdinaryFullPayload() = exercise("udp", true, "udp", explicitNetwork = false, fullTunnel = true)

    @Test fun tcpRoutedSplitPayloadDns() = exercise("tcp", false, "tcp", explicitNetwork = false, routed = true)
    @Test fun udpRoutedSplitPayloadDns() = exercise("udp", false, "udp", explicitNetwork = false, routed = true)
    @Test fun quicRoutedSplitPayloadDns() = exercise("udp", true, "udp", explicitNetwork = false, routed = true)
    @Test fun tcpRoutedFullPayloadDns() = exercise("tcp", false, "tcp", explicitNetwork = false, fullTunnel = true, routed = true)
    @Test fun udpRoutedFullPayloadDns() = exercise("udp", false, "udp", explicitNetwork = false, fullTunnel = true, routed = true)
    @Test fun quicRoutedFullPayloadDns() = exercise("udp", true, "udp", explicitNetwork = false, fullTunnel = true, routed = true)
    @Test fun fullKillSwitchRefusesWithoutSystemLockdown() {
        val before = shell("logcat -d -s VpnSvc:E").split("Refusing unprotected kill-switch connection:").size
        val config = VpnConfig(serverAddress = "10.0.2.2", port = 24966, protocol = "tcp",
            username = "fixture", password = "fixture-password", serverPublicKeyHex = args.getString("q29_key_tcp"),
            bindStaticToSession = true, killSwitch = true, routingMode = "full-tunnel", addDefaultGateway = true)
        config.validate()
        context.startForegroundService(Intent(context, VpnServiceImpl::class.java)
            .setAction(VpnServiceImpl.ACTION_CONNECT).putExtra(VpnServiceImpl.EXTRA_CONFIG, config))
        waitFor("unprotected kill-switch request was not rejected") {
            shell("logcat -d -s VpnSvc:E").split("Refusing unprotected kill-switch connection:").size > before
        }
        waitFor("rejected foreground service did not stop") { service() == null }
        assertEquals(VpnServiceImpl.STATUS_ERROR, VpnServiceImpl.liveStatus)
        assertNull(VpnServiceImpl.liveConnectionProperties)
        assertFalse("refusal left a TUN", Regex("(?m)^\\d+: tun\\d").containsMatchIn(shell("su 0 ip -o link show")))
    }

}
