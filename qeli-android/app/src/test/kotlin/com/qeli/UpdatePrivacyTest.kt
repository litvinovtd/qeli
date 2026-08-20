package com.qeli

import com.qeli.model.VpnConfig
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdatePrivacyTest {
    private fun config(
        fullTunnel: Boolean = true,
        appsMode: String = "all",
        ipv4Leak: Boolean = false,
        ipv6Leak: Boolean = false,
        allowLan: Boolean = false,
        excludes: List<String> = emptyList(),
    ) = VpnConfig(
        serverAddress = "vpn.example.com",
        port = 443,
        username = "alice",
        password = "secret",
        routingMode = if (fullTunnel) "full-tunnel" else "split-tunnel",
        addDefaultGateway = fullTunnel,
        appsMode = appsMode,
        allowIpv4Leak = ipv4Leak,
        allowIpv6Leak = ipv6Leak,
        allowLan = allowLan,
        excludeRoutes = excludes,
    )

    @Test
    fun `only an unqualified full capture is private`() {
        assertTrue(UpdateChecker.hasPrivatePath(config()))
        assertTrue(UpdateChecker.hasPrivatePath(config(appsMode = "exclude")))
        assertFalse(UpdateChecker.hasPrivatePath(config(fullTunnel = false)))
        assertFalse(UpdateChecker.hasPrivatePath(config(appsMode = "include")))
        assertFalse(UpdateChecker.hasPrivatePath(config(ipv4Leak = true)))
        assertFalse(UpdateChecker.hasPrivatePath(config(ipv6Leak = true)))
        assertFalse(UpdateChecker.hasPrivatePath(config(allowLan = true)))
        assertFalse(UpdateChecker.hasPrivatePath(config(), globalAllowLan = true))
        assertFalse(UpdateChecker.hasPrivatePath(config(excludes = listOf("203.0.113.0/24"))))
    }
}
