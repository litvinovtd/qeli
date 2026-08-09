package com.qeli

import com.qeli.model.VpnConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Range checks on IMPORTED numeric config values. (Audit 2026-07-27, C6)
 *
 * The server-PUSHED mtu was already clamped at the handshake (QeliService.parseOk), but the
 * locally imported one was not: a hand-written `mtu = 40`, or a scanned
 * `qeli://…?mtu=99999`, went straight through to VpnService.Builder.setMtu, where establish()
 * fails and the retry loop reconnects forever behind an opaque error. Padding was the same
 * bug one layer down — an oversized `padding_max` makes every data record exceed
 * the shared Rust record-size limit, so the peer drops all of them.
 *
 * The two entry points behave DIFFERENTLY on purpose, mirroring the Rust client
 * (qeli/src/config/client.rs) and the C# port: a config FILE is a thing the user wrote, so a
 * bad value is reported; a `qeli://` LINK is scanned or pasted and its import is infallible,
 * so a bad value degrades to auto. Getting these the same way round on every client is the
 * point — the divergence is what the conformance work keeps finding.
 */
class ConfigImportRangesTest {

    /**
     * A CLI profile opened here and saved must come back with its Rust-only settings intact.
     *
     * These keys are on the allowlist precisely so such a profile OPENS — and then saving it
     * deleted them, because nothing stored them. Hooks (`post_up`/`post_down`), the TOFU
     * setting and the routing policy vanished as a side effect of opening the file, which is
     * worse than refusing it would have been. (Audit 2026-08-02, §7.)
     */
    @Test
    fun `rust-only keys survive an import and re-export`() {
        val source = """
            [qeli]
            server = vpn.example.com:443
            user = alice
            pass = s3cret
            post_up = /etc/qeli/up.sh
            post_down = /etc/qeli/down.sh
            allow_unpinned_tofu = false
            gateway_nat = true
            exit_node = 10.9.0.7
            keepalive = 25
            recv_buffer_size = 8388608
            password_file = /etc/qeli/secret
        """.trimIndent()

        val first = VpnConfig.fromIni(source)
        val reExported = VpnConfig.fromIni(first.toIni())

        for ((key, want) in mapOf(
            "post_up" to "/etc/qeli/up.sh",
            "post_down" to "/etc/qeli/down.sh",
            "gateway_nat" to "true",
            "exit_node" to "10.9.0.7",
            "keepalive" to "25",
            "recv_buffer_size" to "8388608",
            "password_file" to "/etc/qeli/secret",
        )) {
            assertEquals("$key must survive the round trip", want, reExported.carriedKeys[key])
        }
        // This security control is modelled by Android now, not carried as an opaque
        // Rust-only key. Exercise the non-default value so toIni() has to emit it.
        assertFalse(first.allowUnpinnedTofu)
        assertFalse(reExported.allowUnpinnedTofu)

        // And they must not have become "unknown" on the way back in — that would refuse the
        // very profile this port just wrote.
        assertTrue("re-import found: ${reExported.unknownKeys}", reExported.unknownKeys.isEmpty())
    }

    /**
     * A JSON profile is refused BY NAME, not fed to the INI parser.
     *
     * JSON was the original config format and is retired (see `VpnConfig.jsonRetired`). The
     * leading brace is still detected for exactly one reason: without it an old file falls into
     * `fromIni` and comes back "missing [qeli]", which tells the reader nothing about what
     * actually happened or what to do. That message IS the remaining contract, so it is what
     * this pins.
     */
    @Test
    fun `a json profile is refused by name`() {
        val err = runCatching {
            VpnConfig.parse("""{"server":{"address":"vpn.example.com","port":443}}""")
        }.exceptionOrNull()
        assertTrue("must name the format, got $err",
            err?.message?.contains("JSON profile") == true && err.message?.contains("INI") == true)
    }

    /** Malformed IPv6 must be refused at config time, not when the TUN is built. */
    @Test
    fun `dns rejects malformed ipv6 and accepts real addresses`() {
        fun withDns(v: String) = VpnConfig.fromIni(
            "[qeli]\nserver = vpn.example.com:443\nuser = alice\npass = s3cret\ndns = $v\n"
        )
        for (bad in listOf(
            "::::", "1::2::3", "abcd:::", "of", "12345::1", "1:2:3:4:5:6:7",
            // The embedded IPv4 form stands for TWO groups, so this one is over-long. Counting
            // it as a single group accepted it. (Audit 2026-08-02, follow-up.)
            "1:2:3:4:5:6::192.0.2.1",
            // `::` must stand for at least one OMITTED group.
            "1:2:3:4:5:6:7:8::",
        )) {
            val err = runCatching { withDns(bad).validate() }.exceptionOrNull()
            assertTrue("'$bad' must be refused", err?.message?.contains("dns") == true)
        }
        for (ok in listOf(
            "1.1.1.1", "::1", "2001:4860:4860::8888", "fe80::1", "::ffff:1.2.3.4",
            // Eight groups exactly, with the last two written as IPv4 — valid, and the same
            // miscount used to REJECT it.
            "1:2:3:4:5:6:192.0.2.1",
            "1:2:3:4:5:6:7:8",
        )) {
            withDns(ok).validate()
        }
    }

    /**
     * Credentials that do not fit one datagram are refused here, as they are in the CLI.
     *
     * AUTH goes out unfragmented and its size IS the credentials, so a long token used as a
     * password needs IP fragmentation — which mobile and CGNAT paths drop. The Rust client
     * bounded this; without the same bound here the identical profile worked on a laptop and
     * hung on the phone. UTF-8 BYTES, not characters. (Audit 2026-08-02, follow-up.)
     */
    @Test
    fun `credentials too large for one datagram are refused`() {
        fun withPass(p: String) = VpnConfig.fromIni(
            "[qeli]\nserver = vpn.example.com:443\nuser = alice\npass = $p\n"
        )
        // A realistic credential is nowhere near the bound.
        withPass("x".repeat(64)).validate()

        val err = runCatching { withPass("x".repeat(VpnConfig.AUTH_CRED_BUDGET)).validate() }
            .exceptionOrNull()
        assertTrue("must name the fields, got $err", err?.message?.contains("pass") == true)

        // Counted in BYTES: a two-byte character halves how many fit, and a check that counted
        // characters would let this through.
        val cyrillic = "п".repeat(VpnConfig.AUTH_CRED_BUDGET / 2)
        val err2 = runCatching { withPass(cyrillic).validate() }.exceptionOrNull()
        assertTrue("UTF-8 length must be what counts, got $err2", err2 != null)
    }

    /**
     * An unknown `dns` mode must fail, not silently become the widest option.
     *
     * Both readers now fold an unrecognised value back to `tunnel` and treat the text as a
     * server list, so no FILE can put a bad mode in the field any more — but the UI writes it
     * directly, and "tunnel" is precisely the wrong default to land on: it is the opposite of
     * `off` and sends every lookup through the VPN. Checked where the value can still arrive.
     */
    @Test
    fun `validate refuses an unknown dns mode`() {
        val cfg = VpnConfig.fromIni(ini()).copy(dnsMode = "of")
        val err = runCatching { cfg.validate() }.exceptionOrNull()
        assertTrue("validate must name dns, got $err", err?.message?.contains("dns") == true)
        for (ok in listOf("off", "tunnel", "system")) {
            VpnConfig.fromIni(ini()).copy(dnsMode = ok).validate()
        }
    }

    /**
     * A reconnect delay past a day must be RECORDED, not silently swapped for the default.
     *
     * The bound exists because the desktop port's reconnect loop waits through an Int: past
     * ~24.8 days the millisecond cast truncates and can throw, killing the loop that the long
     * delay was configuring. A profile moves between clients, so the bound is shared — and this
     * is the port that has to agree with it rather than quietly accept more.
     */
    @Test
    fun `an out-of-range reconnect delay is recorded`() {
        val cfg = VpnConfig.fromIni(ini(
            "reconnect_base_delay = 999999999", "reconnect_max_delay = 999999999"))
        assertTrue("both must be recorded: ${cfg.unparsedNumericKeys}",
            cfg.unparsedNumericKeys.containsAll(
                listOf("reconnect_base_delay", "reconnect_max_delay")))
        assertNotNull(runCatching { cfg.validate() }.exceptionOrNull())

        // An hour is a long backoff and a legitimate one — the bound must not catch it.
        val patient = VpnConfig.fromIni(ini("reconnect_max_delay = 3600"))
        assertEquals(3600L, patient.reconnectMaxDelaySecs)
        assertTrue(patient.unparsedNumericKeys.isEmpty())
    }

    /**
     * A negative heartbeat interval must be refused, not quietly turn the keepalive off.
     *
     * `heartbeat_interval = -1` parsed cleanly and disabled the heartbeat entirely, while
     * `heartbeat = true` sitting right above it still said it was on. That is worse than either
     * a rejection or an honest `heartbeat = false`: the profile claims a keepalive it does not
     * have, and the connection dies on the first idle NAT timeout with nothing to point at.
     */
    @Test
    fun `a non-positive heartbeat interval is recorded`() {
        val cfg = VpnConfig.fromIni(ini("heartbeat = true", "heartbeat_interval = -1"))
        assertTrue("interval must be recorded: ${cfg.unparsedNumericKeys}",
            cfg.unparsedNumericKeys.contains("heartbeat_interval"))

        // Jitter and size may legitimately be zero — no jitter, empty payload — so the floor
        // there is 0, not 1, and this must NOT be flagged.
        val noJitter = VpnConfig.fromIni(ini("heartbeat_jitter = 0", "heartbeat_size = 0"))
        assertTrue(noJitter.unparsedNumericKeys.isEmpty())
    }

    /** Shaping values are durations and sizes: zero or negative is not a setting. */
    @Test
    fun `a non-positive shaping value is recorded`() {
        val cfg = VpnConfig.fromIni(ini("shaping = true", "shaping_gap_mean = 0",
            "shaping_min_size = -5", "shaping_budget = 0"))
        assertTrue("all three must be recorded: ${cfg.unparsedNumericKeys}",
            cfg.unparsedNumericKeys.containsAll(
                listOf("shaping_gap_mean", "shaping_min_size", "shaping_budget")))
        assertNotNull(runCatching { cfg.validate() }.exceptionOrNull())
    }

    /**
     * A wire mode that needs a STREAM must not validate on a datagram transport.
     *
     * `proto` and `mode` were each checked against their own enum and never against each other,
     * so `udp` + `reality-tls` passed while the server refuses it — the profile could not reach
     * any working server, and failed later and less clearly. `reality-tls` is the dangerous
     * half: nothing in the name says TCP, so the operator believes they have the strongest
     * masking available while the datagram path falls back to fake-tls framing.
     */
    @Test
    fun `stream-only wire modes are refused on udp`() {
        // Each mode carries whatever IT requires, so this fails on the transport pairing only.
        val secrets = arrayOf(
            "reality_sid = 0123456789abcdef",
            "key = 1111111111111111111111111111111111111111111111111111111111111111",
            "obfs_key = deadbeefcafe",
        )
        for (mode in listOf("plain", "reality-tls")) {
            val err = runCatching {
                VpnConfig.fromIni(ini("proto = udp", "mode = $mode", *secrets)).validate()
            }.exceptionOrNull()
            assertTrue("udp + $mode must be refused, got $err",
                err?.message?.contains("TCP-only") == true && err.message?.contains(mode) == true)
            // The same mode over TCP is exactly what it is for.
            VpnConfig.fromIni(ini("proto = tcp", "mode = $mode", *secrets)).validate()
        }
        // ...and the datagram modes are untouched, so this cannot pass by refusing all UDP.
        for (mode in listOf("fake-tls", "obfs")) {
            VpnConfig.fromIni(ini("proto = udp", "mode = $mode", *secrets)).validate()
        }
    }

    /** A mode that needs a secret must not validate without it. Mirrors the Rust client. */
    @Test
    fun `a wire mode without its secret is refused`() {
        val cases = listOf(
            arrayOf("mode = reality-tls") to "requires 'reality_sid'",
            arrayOf("mode = reality-tls", "reality_sid = deadbeeg") to "1..8 bytes of hex",
            arrayOf("mode = reality-tls", "reality_sid = 0123456789abcdef") to "pinned server 'key'",
            arrayOf("mode = obfs") to "requires a non-empty 'obfs_key'",
        )
        for ((extra, want) in cases) {
            val err = runCatching {
                VpnConfig.fromIni(ini(*extra)).validate()
            }.exceptionOrNull()
            assertTrue("${extra.toList()} must be refused with '$want', got $err",
                err?.message?.contains(want) == true)
        }
    }

    /** A profile that never carried them must not grow empty lines for them. */
    @Test
    fun `a profile without rust-only keys stays clean`() {
        val plain = VpnConfig.fromIni(
            "[qeli]\nserver = vpn.example.com:443\nuser = alice\npass = s3cret\n"
        )
        assertTrue(plain.carriedKeys.isEmpty())
        assertFalse(plain.toIni().contains("post_up"))
    }

    private fun ini(vararg extra: String) = buildString {
        append("[qeli]\n")
        append("server = vpn.example.com:443\n")
        append("user = alice\n")
        append("pass = secret\n")
        for (line in extra) append(line).append('\n')
    }

    private fun link(query: String) = "qeli://alice:secret@vpn.example.com:443?proto=tcp&$query"

    /**
     * `front` and `routing_mode` are compared against ONE literal at the use site, so an
     * unknown value silently takes the other branch instead of erroring. (Audit 2026-07-31, §3.)
     */
    @Test
    fun `unknown front and routing mode are refused`() {
        assertNotNull("front = webscoket must be refused",
            runCatching { VpnConfig.fromIni(ini("front = webscoket")).validate() }.exceptionOrNull())
        for (f in listOf("websocket", "none")) {
            VpnConfig.fromIni(ini("front = $f")).validate()
        }

        // routingMode has NO ini key — the flat INI derives it from `gateway`, and the JSON
        // importer that used to carry one is retired, so no file can reach the field any more.
        // The UI still sets it directly, which is the arrival path left to check.
        val base = VpnConfig.fromIni(ini())
        assertNotNull("routing mode full-tunel must be refused",
            runCatching { base.copy(routingMode = "full-tunel").validate() }.exceptionOrNull())
        for (r in listOf("split-tunnel", "full-tunnel", "all")) {
            base.copy(routingMode = r).validate()
        }
    }

    /**
     * A boolean nobody could parse must not read as `false`.
     *
     * Every unknown value used to be falsey, so `kill_switch = ture` silently disabled the kill
     * switch and `bind_static = ture` silently dropped the static-key binding — a security
     * downgrade with no message anywhere, and unrecoverable after parse because the original
     * string is gone. Parsing still succeeds (the editor must be able to open a bad profile to
     * fix it); validate() is what refuses. (Audit 2026-07-31.)
     */
    @Test
    fun `a typo in a boolean is refused, not read as false`() {
        for (key in listOf("gateway", "bind_static", "reconnect", "padding", "heartbeat", "quic")) {
            val cfg = VpnConfig.fromIni(ini("$key = ture"))
            assertTrue("$key: the typo must be recorded", cfg.unparsedBooleanKeys.contains(key))
            val e = runCatching { cfg.validate() }.exceptionOrNull()
            assertNotNull("$key: validate() must refuse the config", e)
            assertTrue("the message must name the key: ${e?.message}",
                e!!.message!!.contains(key))
        }

        // A typo must NOT be resolved to the falsey reading it used to get.
        assertTrue("gateway = ture must not silently become split-tunnel",
            VpnConfig.fromIni(ini("gateway = ture")).isFullTunnel)
        assertTrue("bind_static = ture must not silently disable key binding",
            VpnConfig.fromIni(ini("bind_static = ture")).bindStaticToSession)

        // Every spelling the Rust client accepts must still work, both ways, and leave the
        // config valid.
        for (yes in listOf("true", "1", "yes", "on", "TRUE", "On")) {
            val c = VpnConfig.fromIni(ini("quic = $yes"))
            assertTrue("$yes must be true", c.quicEnabled)
            assertTrue(c.unparsedBooleanKeys.isEmpty())
        }
        for (no in listOf("false", "0", "no", "off", "FALSE", "Off")) {
            val c = VpnConfig.fromIni(ini("quic = $no"))
            assertFalse("$no must be false", c.quicEnabled)
            assertTrue(c.unparsedBooleanKeys.isEmpty())
        }
    }

    @Test
    fun `an INI file with an out-of-range mtu is rejected`() {
        for (bad in listOf("99999", "40", "-1", "575", "16639")) {
            try {
                VpnConfig.fromIni(ini("mtu = $bad"))
                fail("mtu = $bad must be rejected, not imported")
            } catch (e: IllegalArgumentException) {
                assertEquals(true, e.message?.contains("mtu"))
            }
        }
    }

    @Test
    fun `an INI file with a valid mtu keeps it, and 0 stays auto`() {
        assertEquals(1380, VpnConfig.fromIni(ini("mtu = 1380")).mtu)
        assertEquals(576, VpnConfig.fromIni(ini("mtu = 576")).mtu)
        assertEquals(9000, VpnConfig.fromIni(ini("mtu = 9000")).mtu)
        // The real ceiling, derived in Rust from the record format. Pinned so this port cannot
        // silently keep an older, lower bound than the server accepts. (Audit 2026-08-01, §1.)
        assertEquals(16638, VpnConfig.MTU_MAX)
        assertEquals(16638, VpnConfig.fromIni(ini("mtu = 16638")).mtu)
        // 9001 used to be refused; it is inside the range now. Kept as a case so the old
        // ceiling cannot creep back in unnoticed.
        assertEquals(9001, VpnConfig.fromIni(ini("mtu = 9001")).mtu)
        assertEquals(0, VpnConfig.fromIni(ini("mtu = 0")).mtu)
        assertEquals(0, VpnConfig.fromIni(ini()).mtu)   // absent = auto
    }

    /** A link must stay importable: the mtu falls back to auto, everything else survives. */
    @Test
    fun `a qeli link with an out-of-range mtu falls back to auto`() {
        val cfg = VpnConfig.fromQeliUri(link("mode=fake-tls&mtu=99999"))
        assertEquals(0, cfg.mtu)
        assertEquals("vpn.example.com", cfg.serverAddress)
        assertEquals("alice", cfg.username)
        assertEquals(0, VpnConfig.fromQeliUri(link("mode=fake-tls&mtu=-5")).mtu)
        // In range → carried through untouched.
        assertEquals(1380, VpnConfig.fromQeliUri(link("mode=fake-tls&mtu=1380")).mtu)
    }

    /**
     * Padding is CLAMPED rather than rejected: unlike mtu these are pure obfuscation knobs,
     * so narrowing them costs the user nothing while an oversized max breaks every packet.
     */
    @Test
    fun `imported padding bounds are clamped to the wire ceiling`() {
        val c = VpnConfig.fromIni(ini("padding_min = -5", "padding_max = 60000"))
        assertEquals(0, c.paddingMin)
        assertEquals(1400, c.paddingMax)
        // min above max must not survive as an inverted range (nextInt would throw).
        val inverted = VpnConfig.fromIni(ini("padding_min = 900", "padding_max = 100"))
        assertEquals(900, inverted.paddingMin)
        assertEquals(900, inverted.paddingMax)
    }

    /** A clamped/accepted profile must still round-trip through the emit-side validator. */
    @Test
    fun `a clamped profile still passes validate on re-save`() {
        VpnConfig.fromIni(ini("padding_min = -5", "padding_max = 60000", "mtu = 1380")).validate()
    }

    /**
     * `dns` is a MODE in the Rust client and a resolver LIST here — the same key, two meanings.
     *
     * Recognising the mode words was only half the job: they mapped to "no explicit resolvers",
     * and the connect path treats that as "nothing chosen" and installs 1.1.1.1/8.8.8.8 on a
     * full tunnel. So `dns = off` — which means LEAVE MY RESOLVER ALONE — sent every lookup to
     * Cloudflare and Google, the exact opposite of the request. The mode has to be kept, and it
     * has to survive a save/load round-trip. (Audit 2026-08-02, §3.)
     */
    @Test
    fun `dns mode survives import and round-trip`() {
        for (mode in listOf("off", "system")) {
            val c = VpnConfig.fromIni(ini("dns = $mode"))
            assertEquals(mode, c.dnsMode)
            assertTrue("a mode is not a resolver list", c.dnsServers.isEmpty())
            // Re-saving must not turn "leave my resolver alone" back into the fallback.
            assertEquals(mode, VpnConfig.fromIni(c.toIni()).dnsMode)
        }

        // The list form is unchanged, and defaults to the tunnel mode.
        val list = VpnConfig.fromIni(ini("dns = 10.0.0.1, 10.0.0.2"))
        assertEquals("tunnel", list.dnsMode)
        assertEquals(listOf("10.0.0.1", "10.0.0.2"), list.dnsServers)
        assertEquals(listOf("10.0.0.1", "10.0.0.2"), VpnConfig.fromIni(list.toIni()).dnsServers)
        val coreIni = list.toTransportCoreIni()
        assertTrue(coreIni.contains("dns_servers = 10.0.0.1, 10.0.0.2"))
        assertFalse(coreIni.lineSequence().any { it.startsWith("dns = 10.0.0.1") })

        // Absent: the tunnel mode with no explicit servers, i.e. today's behaviour.
        val none = VpnConfig.fromIni(ini())
        assertEquals("tunnel", none.dnsMode)
        assertTrue(none.dnsServers.isEmpty())
    }

    @Test
    fun `transport core INI makes the Android gateway default explicit`() {
        val fullTunnel = VpnConfig.fromIni(ini())
        assertTrue(fullTunnel.isFullTunnel)
        assertTrue(fullTunnel.toTransportCoreIni().lineSequence().any { it == "gateway = true" })

        val splitTunnel = VpnConfig.fromIni(ini("gateway = false"))
        assertFalse(splitTunnel.isFullTunnel)
        assertTrue(splitTunnel.toTransportCoreIni().lineSequence().any { it == "gateway = false" })
    }

    /**
     * A misspelled key name must be refused — but a key another PORT owns must not be.
     *
     * Nothing reads a typo, so the setting it was meant to change silently keeps its default:
     * `gatway = true` left the tunnel split with nothing said. The Rust client has always
     * refused these. The trap is over-correcting: `keepalive`, `post_up`, `exit_node` and
     * friends are real Rust-client file-only keys (docs/ru/CONFIG.md, "Что пушем НЕ
     * передаётся"), and refusing a CLI profile that carries them would be a worse regression
     * than the typo it catches. (Audit 2026-08-01, §14.)
     */
    @Test
    fun `a misspelled key is refused, a key another port owns is not`() {
        val typo = VpnConfig.fromIni(ini("gatway = true"))
        assertTrue("the typo must be recorded", typo.unknownKeys.contains("gatway"))
        val e = runCatching { typo.validate() }.exceptionOrNull()
        assertNotNull("validate() must refuse it", e)
        assertTrue("the message must name the key: ${e?.message}", e!!.message!!.contains("gatway"))

        // Keys this port does not read but the Rust client does — must open cleanly.
        for (k in listOf("keepalive = 25", "post_up = /bin/true", "exit_node = true",
                         "lan_subnet = 10.0.0.0/24", "tcp_nodelay = true", "autostart = true")) {
            val c = VpnConfig.fromIni(ini(k))
            assertTrue("$k must not be treated as a typo: ${c.unknownKeys}", c.unknownKeys.isEmpty())
            c.validate()
        }

        // `kill_switch` is not a harmless Rust-only knob on Android: accepting it would tell
        // the user traffic is blocked while the app cannot implement that guarantee. Refuse
        // it explicitly and point at the OS lockdown that can enforce it.
        val unsupported = VpnConfig.fromIni(ini("kill_switch = true"))
        val unsupportedError = runCatching { unsupported.validate() }.exceptionOrNull()
        assertNotNull("kill_switch must be refused on Android", unsupportedError)
        assertTrue(
            "the message must name the key: ${unsupportedError?.message}",
            unsupportedError!!.message!!.contains("kill_switch")
        )
        assertTrue(
            "the message must explain the system control: ${unsupportedError.message}",
            unsupportedError.message!!.contains("Always-on VPN")
        )

        // The strongest guard against a wrong list: everything this port WRITES must be
        // something it accepts back, or the client would refuse its own saved profile.
        //
        // Built with the OPTIONAL keys turned ON. A round-trip from a default config emits
        // only the unconditional lines, so `allow_lan` — written under `if (allowLan)` — never
        // appeared and its absence from the known-key list went unnoticed until a user with
        // LAN bypass could not re-import their own profile. Anything emitted conditionally
        // has to be exercised here or this guard is weaker than it looks.
        // (Audit 2026-08-02, §2.)
        val full = VpnConfig.fromIni(
            // `apps` is ONE comma-separated line, which is what `toIni` writes — repeating the
            // key would be a genuine ambiguity and `validate()` is right to refuse it.
            ini("mtu = 1400", "quic = true", "front = none", "allow_lan = true",
                "apps_mode = include", "apps = com.example.one, com.example.two",
                "route_local = true", "shaping = true")
        )
        val reimported = VpnConfig.fromIni(full.toIni())
        assertTrue("round-trip must not produce unknown keys: ${reimported.unknownKeys}",
            reimported.unknownKeys.isEmpty())
        // ...and the values must survive, or the guard would pass on a lossy writer.
        assertTrue(reimported.allowLan)
        assertEquals("include", reimported.appsMode)
        assertEquals(listOf("com.example.one", "com.example.two"), reimported.apps)
    }

    /**
     * A number that is present but unreadable must be refused, not replaced by the default.
     *
     * `server`'s port has always thrown here, which is why the worst case never bit this port —
     * but every other numeric key fell back in silence, so `padding_min = abc` quietly became
     * 0. The C# port had it worse (`server = host:notnum` became `host:443`, a different
     * server), and all four must now agree. (Audit 2026-08-01, §P2.)
     */
    @Test
    fun `an unreadable number is refused, not replaced by the default`() {
        val cfg = VpnConfig.fromIni(ini("padding_min = abc"))
        assertTrue("the bad number must be recorded", cfg.unparsedNumericKeys.contains("padding_min"))
        val e = runCatching { cfg.validate() }.exceptionOrNull()
        assertNotNull("validate() must refuse it", e)
        assertTrue("the message must name the key: ${e?.message}",
            e!!.message!!.contains("padding_min"))

        // EVERY numeric field, not just padding: `mtu = abc` used to become auto-MTU, a
        // mistyped timeout became 30 s, a mistyped AWG knob became its default — each one a
        // setting the operator chose and did not get. (Audit 2026-08-01, §8.)
        for (key in listOf("mtu", "timeout", "jc", "jmin", "jmax", "reconnect_retries",
                           "reconnect_base_delay", "reconnect_max_delay", "heartbeat_interval",
                           "heartbeat_size", "heartbeat_jitter", "shaping_gap_mean",
                           "shaping_budget", "shaping_min_size", "shaping_max_size",
                           "shaping_stealth_mbps")) {
            val c = VpnConfig.fromIni(ini("$key = abc"))
            assertTrue("$key: an unreadable value must be recorded",
                c.unparsedNumericKeys.contains(key))
        }

        // ...and so is a value that is merely OUT OF RANGE. This used to assert the opposite,
        // on the grounds that the silent fallback was "a documented clamp, not a mistake". It
        // is not a clamp: a clamp pins the value to the nearest bound, whereas this jumps to
        // the DEFAULT, which is somewhere else entirely — `heartbeat_interval = -5` became
        // 15 s, i.e. a setting the author never wrote. The C# reader was corrected on the same
        // reasoning; this test was pinning the behaviour the fix removes.
        val ranged = VpnConfig.fromIni(ini("heartbeat_interval = -5"))
        assertTrue("out of range must be recorded: ${ranged.unparsedNumericKeys}",
            ranged.unparsedNumericKeys.contains("heartbeat_interval"))

        // An ABSENT key keeps its default silently — that is what a default is for.
        assertTrue(VpnConfig.fromIni(ini()).unparsedNumericKeys.isEmpty())
        // ...and a readable one records nothing, so the check above cannot pass vacuously.
        val good = VpnConfig.fromIni(ini("padding_min = 10", "padding_max = 200"))
        assertTrue(good.unparsedNumericKeys.isEmpty())
        good.validate()

        // The port was already strict and must stay that way — an outright throw, not a record.
        assertNotNull("a non-numeric port must be rejected outright",
            runCatching { VpnConfig.fromIni("[qeli]\nserver = 1.2.3.4:notnum\n") }.exceptionOrNull())
    }

    /**
     * A key written twice must be refused, not silently resolved.
     *
     * The ports disagreed on which line wins: this parser folds entries into a map and keeps
     * the LAST, while the Rust client (config/format.rs `Section::get`) takes the FIRST. Two
     * `server` lines therefore sent the Rust client to one host and every GUI client to
     * another, out of one file, with nothing reported anywhere. Parsing still succeeds — the
     * editor must be able to open the file to fix it; validate() is what refuses.
     * (Audit 2026-08-01, §7.)
     */
    @Test
    fun `a key written twice is refused, not silently resolved`() {
        val cfg = VpnConfig.fromIni(ini("server = other.example.com:8443"))
        assertTrue("the duplicate must be recorded",
            cfg.duplicateKeys.contains("qeli.server"))
        val e = runCatching { cfg.validate() }.exceptionOrNull()
        assertNotNull("validate() must refuse an ambiguous config", e)
        assertTrue("the message must name the key: ${e?.message}",
            e!!.message!!.contains("qeli.server"))

        // Duplicates are found per SECTION — the same key name in two different sections is
        // not a duplicate, and a clean file must stay clean.
        val clean = VpnConfig.fromIni(ini("mtu = 1400") + "[logging]\nlevel = debug\n")
        assertTrue("a clean config must record nothing: ${clean.duplicateKeys}",
            clean.duplicateKeys.isEmpty())
        clean.validate()

        // Recorded ONCE however many times the key repeats, and the last value still wins, so
        // a file that already had a duplicate parses as it always did.
        val thrice = VpnConfig.fromIni(ini("mtu = 1400", "mtu = 1300", "mtu = 1200"))
        assertEquals(listOf("qeli.mtu"), thrice.duplicateKeys)
        assertEquals(1200, thrice.mtu)
    }
}

/**
 * A profile must survive a save/load round-trip intact. (Audit 2026-07-29, #6)
 *
 * The importer used to stop filling fields at heartbeat, so shaping, an explicit
 * `mtu_probe = false` and the whole `[logging]` block were dropped: the reopened profile
 * silently came back with defaults, and re-saving it wrote that loss back to disk. Every value
 * below is non-default on purpose — a writer or reader that skips one fails an assertion here.
 *
 * Originally written against the JSON importer, which is retired; the loss it guards against is
 * a property of the WRITER/READER PAIR, not of either format, so it moved to INI unchanged.
 */
class ConfigRoundTripCompletenessTest {
    private val ini = """
        [qeli]
        server = example.com:8443
        proto = tcp
        user = u
        pass = p
        mode = fake-tls
        mtu = 1280
        mtu_probe = false
        shaping = true
        shaping_gap_mean = 800
        shaping_gap_min = 50
        shaping_gap_max = 7000
        shaping_budget = 4096
        shaping_min_size = 128
        shaping_max_size = 900
        shaping_stealth = true
        shaping_stealth_mbps = 5

        [logging]
        level = debug
        time_format = rfc3339
    """.trimIndent()

    @Test
    fun importKeepsShapingMtuProbeAndLogging() {
        val c = VpnConfig.fromIni(ini)
        assertEquals(false, c.mtuProbe)
        assertEquals(true, c.shapingEnabled)
        assertEquals(800L, c.shapingGapMeanMs)
        assertEquals(50L, c.shapingGapMinMs)
        assertEquals(7000L, c.shapingGapMaxMs)
        assertEquals(4096, c.shapingBudgetBytesPerSec)
        assertEquals(128, c.shapingMinSize)
        assertEquals(900, c.shapingMaxSize)
        assertEquals(true, c.shapingStealth)
        assertEquals(5, c.shapingStealthRateMbps)
        assertEquals("debug", c.loggingLevel)
        assertEquals("rfc3339", c.loggingTimeFormat)
    }

    /** And the values must still be there after the profile is written back out and reread. */
    @Test
    fun theValuesSurviveAnIniRoundTrip() {
        val back = VpnConfig.fromIni(VpnConfig.fromIni(ini).toIni())
        assertEquals(false, back.mtuProbe)
        assertEquals(true, back.shapingEnabled)
        assertEquals(800L, back.shapingGapMeanMs)
        assertEquals(900, back.shapingMaxSize)
        assertEquals("debug", back.loggingLevel)
    }
}
