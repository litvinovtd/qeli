package com.qeli

import com.qeli.model.VpnConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Guards for the config-hardening pass that brought this client in line with the iOS and
 * Rust ones. Each test here pins a divergence that was live in the shipped app, so a
 * regression shows up as a red test rather than as a profile that silently misbehaves.
 */
class ConfigHardeningTest {

    private fun profile(
        pass: String = "secret",
        sni: String? = null,
        mode: String = "fake-tls"
    ) = VpnConfig(
        serverAddress = "vpn.example.com",
        port = 443,
        username = "alice",
        password = pass,
        wireMode = mode,
        sni = sni
    )

    /**
     * The INI-forgery guard. `toIni` writes `key = value` verbatim, so a newline inside a
     * value used to append attacker-chosen keys to the emitted profile — `bind_static =
     * false` turns off binding the session to the pinned server key, and the forged line
     * would come back as trusted config on the next load.
     */
    @Test
    fun `emitting refuses a value carrying a newline`() {
        val forged = profile(pass = "p\nbind_static = false")
        try {
            forged.toIni()
            fail("expected toIni to refuse a password containing a newline")
        } catch (e: IllegalArgumentException) {
            assertTrue("message should name the offending key: ${e.message}",
                e.message!!.contains("pass"))
        }
    }

    @Test
    fun `emitting refuses a carriage return and a NUL`() {
        for (bad in listOf("a\rb", "a\u0000b")) {
            try {
                profile(sni = bad).toIni()
                fail("expected toIni to refuse ${bad.map { it.code }}")
            } catch (_: IllegalArgumentException) { /* expected */ }
        }
    }

    /** A forged link must be rejected at import, before it ever reaches the profile store. */
    @Test
    fun `importing a link with an encoded newline is refused`() {
        try {
            VpnConfig.fromQeliUri("qeli://alice:p%0Abind_static%20%3D%20false@vpn.example.com:443?proto=tcp&mode=fake-tls")
            fail("expected a link with an encoded newline to be refused")
        } catch (_: IllegalArgumentException) { /* expected */ }
    }

    /**
     * `mtu_probe = off` used to mean "probing ON" here while the Rust and iOS clients read
     * it as OFF — the user got the exact opposite of what they wrote.
     */
    @Test
    fun `mtu_probe honours the full false-set`() {
        for (word in listOf("false", "0", "no", "off", "FALSE", "Off")) {
            val cfg = VpnConfig.fromIni("[qeli]\nserver = h:443\nuser = u\npass = p\nmtu_probe = $word\n")
            assertFalse("mtu_probe = $word must disable probing", cfg.mtuProbe)
        }
        assertTrue(VpnConfig.fromIni("[qeli]\nserver = h:443\nuser = u\npass = p\n").mtuProbe)
        // An unrecognised word keeps the default (on) — what Rust's bool_or and the iOS
        // client do. Reading it as "off" would silently disable probing on a config the
        // desktop client happily accepts.
        assertTrue(VpnConfig.fromIni("[qeli]\nserver = h:443\nuser = u\npass = p\nmtu_probe = maybe\n").mtuProbe)
    }

    @Test
    fun `required ipv6 refuses an explicit mtu below 1280`() {
        try {
            profile().copy(ipv6 = "required", mtu = 1200).validate()
            fail("expected required IPv6 with mtu 1200 to be refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("at least 1280"))
        }
        profile().copy(ipv6 = "auto", mtu = 1200).validate()
    }

    @Test
    fun `roaming policy round trips and required rejects source pins`() {
        val disabled = VpnConfig.fromIni(
            "[qeli]\nserver = h:443\nuser = u\npass = p\nroaming = off\n"
        )
        assertEquals("off", disabled.roaming)
        assertFalse(disabled.allowsNativePathRoaming)
        assertEquals("off", VpnConfig.fromIni(disabled.toIni()).roaming)

        val required = VpnConfig.fromIni(
            "[qeli]\nserver = h:443\nuser = u\npass = p\nroaming = required\n"
        )
        required.validate()
        assertEquals("required", VpnConfig.fromIni(required.toIni()).roaming)

        for (pin in listOf("local = 192.0.2.10", "lport = 41000")) {
            val pinned = VpnConfig.fromIni(
                "[qeli]\nserver = h:443\nuser = u\npass = p\nroaming = required\n$pin\n"
            )
            try {
                pinned.validate()
                fail("expected required roaming with $pin to be refused")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message!!.contains("cannot be combined"))
            }
        }
    }

    /** The `[logging]` section used to be parsed and thrown away, losing it on every save. */
    @Test
    fun `logging section survives a round trip`() {
        val src = """
            [qeli]
            server = h:443
            user = u
            pass = p

            [logging]
            level = debug
            time_format = rfc3339
        """.trimIndent()
        val back = VpnConfig.fromIni(VpnConfig.fromIni(src).toIni())
        assertEquals("debug", back.loggingLevel)
        assertEquals("rfc3339", back.loggingTimeFormat)
    }

    /**
     * Padding / heartbeat / shaping are written by the iOS client; without a matching
     * parser here an iOS-exported profile lost them on import.
     */
    @Test
    fun `ios tuning keys survive a round trip`() {
        val src = """
            [qeli]
            server = h:443
            user = u
            pass = p
            shaping = true
            shaping_gap_mean = 900
            heartbeat_interval = 20000
            padding_max = 128
        """.trimIndent()
        val back = VpnConfig.fromIni(VpnConfig.fromIni(src).toIni())
        assertTrue(back.shapingEnabled)
        assertEquals(900L, back.shapingGapMeanMs)
        assertEquals(20000L, back.heartbeatIntervalMs)
        assertEquals(128, back.paddingMax)
    }

    /**
     * `apps_mode` and `apps` used to be emitted only together, so an "include" mode with an
     * empty list silently reverted to "all apps tunnelled" on the next save.
     */
    @Test
    fun `apps_mode survives without a populated app list`() {
        val cfg = profile().copy(appsMode = "include")
        assertEquals("include", VpnConfig.fromIni(cfg.toIni()).appsMode)
    }

    /** An old passwordless link remains importable as a draft, but cannot be re-shared. */
    @Test
    fun `passwordless link imports but cannot be shared`() {
        val draft = VpnConfig.fromQeliUri("qeli://alice:@vpn.example.com:443")
        assertEquals("", draft.password)
        try {
            draft.toQeliUri()
            fail("expected export without an inline pass to be refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message.orEmpty().contains("inline pass"))
        }
    }

    @Test
    fun `ipv6 endpoint is bracketed in every native config and round trips`() {
        val cfg = profile().copy(serverAddress = "2001:db8::7", port = 8443)
        assertTrue(cfg.toIni().contains("server = [2001:db8::7]:8443"))
        assertTrue(cfg.toTransportProbeIni().contains("server = [2001:db8::7]:8443"))
        val back = VpnConfig.fromIni(cfg.toIni())
        assertEquals("2001:db8::7", back.serverAddress)
        assertEquals(8443, back.port)
        assertEquals("2001:db8::7", VpnConfig.fromQeliUri(cfg.toQeliUri()).serverAddress)
    }

    @Test
    fun `bare or malformed ipv6 endpoint is never reinterpreted as host and port`() {
        for (bad in listOf("2001:db8::443", "[2001:db8:::1]:443", "[vpn.example.com]:443")) {
            try {
                VpnConfig.fromIni("[qeli]\nserver = $bad\n")
                fail("expected malformed endpoint to be refused: $bad")
            } catch (_: IllegalArgumentException) { /* expected */ }
        }
        try {
            VpnConfig.fromQeliUri("qeli://u:p@2001:db8::443?proto=tcp&mode=fake-tls")
            fail("expected bare IPv6 qeli:// authority to be refused")
        } catch (_: IllegalArgumentException) { /* expected */ }
    }

    /** Rust clamps an out-of-range link MTU to auto; iOS used to reject the whole link. */
    @Test
    fun `out of range link mtu falls back to auto`() {
        val uri = "qeli://alice:p@vpn.example.com:443?proto=tcp&mode=fake-tls&mtu=99999"
        assertEquals(0, VpnConfig.fromQeliUri(uri).mtu)
    }

    @Test
    fun `emitting refuses an out of range mtu and an unknown mode`() {
        for (bad in listOf(profile().copy(mtu = 99_999), profile(mode = "nope"))) {
            try {
                bad.toTransportCoreIni()
                fail("expected toIni to refuse $bad")
            } catch (_: IllegalArgumentException) { /* expected */ }
        }
    }

    @Test
    fun `include and exclude require strict CIDR literals`() {
        for (bad in listOf("vpn.example.com/24", "10.0.0.1/33", "2001:db8::/129")) {
            try {
                profile().copy(includeRoutes = listOf(bad)).validate()
                fail("expected invalid include CIDR to be refused: $bad")
            } catch (_: IllegalArgumentException) { /* expected */ }
        }
        profile().copy(
            includeRoutes = listOf("10.0.0.0/8"),
            excludeRoutes = listOf("2001:db8::/32")
        ).validate()
    }
    @Test
    fun `every schema field survives a model copy and edit`() {
        val fields = ConfigCore.call(org.json.JSONObject().put("version",1).put("op","schema")).getJSONArray("fields")
        val entries = (0 until fields.length()).map(fields::getJSONObject)
        val source = buildString {
            for (section in listOf("qeli", "logging")) {
                append("[$section]\n")
                for (field in entries) {
                    val key = field.getString("key")
                    if (key.startsWith("logging.") != (section == "logging")) continue
                    val value = when (key) {
                        "server" -> "vpn.example.com:443"
                        "pass" -> "secret"
                        "tun.tx_queue_len" -> "500"
                        "pull_routes" -> "false"
                        "windows_disable_sharing" -> "true"
                        "windows_persistent_adapter" -> "true"
                        "logging.file" -> "/tmp/coverage.log"
                        "logging.time_format" -> "rfc3339"
                        else -> field.getString("default")
                    }
                    val localKey = if (section == "logging") key.removePrefix("logging.") else key
                    append("$localKey = $value\n")
                }
            }
        }
        val saved = VpnConfig.fromIni(source).copy(password="edited").toIni()
        val raw = ConfigCore.call(org.json.JSONObject().put("version",1).put("op","import").put("source",saved)).getJSONObject("raw")
        assertEquals(88, entries.size)
        for (field in entries) assertTrue(field.getString("key"), raw.has(field.getString("key")))
        assertEquals("edited", raw.getJSONArray("pass").getString(0))
        assertEquals("false", raw.getJSONArray("pull_routes").getString(0))
        assertEquals("true", raw.getJSONArray("windows_disable_sharing").getString(0))
        assertEquals("true", raw.getJSONArray("windows_persistent_adapter").getString(0))
        assertEquals("500", raw.getJSONArray("tun.tx_queue_len").getString(0))
        assertEquals("/tmp/coverage.log", raw.getJSONArray("logging.file").getString(0))
        assertEquals("rfc3339", raw.getJSONArray("logging.time_format").getString(0))
    }

    @Test
    fun `duplicate carried scalars survive model operations and cannot activate`() {
        for ((key, first, second) in listOf(Triple("autostart","true","false"), Triple("recv_buffer_size","4194304","0"))) {
            val config=VpnConfig.fromIni("[qeli]\nserver = vpn.example.com:443\n$key = $first\n$key = $second\n")
            try { config.validate(); fail("accepted duplicate $key") } catch (_: IllegalArgumentException) { }
            val raw=ConfigCore.call(org.json.JSONObject().put("version",1).put("op","import").put("source",config.copy(password="edited").toIni())).getJSONObject("raw")
            assertEquals(2, raw.getJSONArray(key).length())
        }
    }

}
