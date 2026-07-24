package com.qeli

import com.qeli.model.VpnConfig
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * Cross-implementation conformance for the `qeli://` link.
 *
 * Reads the SAME fixtures as the Rust, C# and Swift test suites
 * (`conformance/qeli-links.json` at the repo root). The link format is implemented four
 * separate times in four languages, so each field is four chances to disagree — and the
 * failure mode is silent: the link "imports fine" with a field dropped or re-defaulted,
 * and the user gets a profile that will not connect.
 *
 * Two real divergences were found the moment these fixtures were written: Android emitted
 * `mtu` into a link but had no branch to parse it back, and the port was accepted with no
 * range check at all (`0`, `99999` and negatives all produced a profile) while Swift and C#
 * rejected them.
 */
class QeliLinkConformanceTest {

    /**
     * The fixture lives outside the Gradle module, so resolve it by walking up from the
     * working directory instead of hardcoding a depth — the test must fail loudly if the
     * file moves, never silently pass by testing nothing.
     */
    private fun fixtures(): JSONObject {
        var dir: File? = File("").absoluteFile
        while (dir != null) {
            val f = File(dir, "conformance/qeli-links.json")
            if (f.isFile) return JSONObject(f.readText())
            dir = dir.parentFile
        }
        fail("conformance/qeli-links.json not found walking up from ${File("").absolutePath}")
        error("unreachable")
    }

    @Test
    fun `accepts every valid fixture with the expected fields`() {
        val cases = fixtures().getJSONArray("cases")
        assertTrue("fixture file has no cases", cases.length() > 0)
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val name = c.getString("name")
            val cfg = try {
                VpnConfig.fromQeliUri(c.getString("uri"))
            } catch (e: Exception) {
                fail("case '$name': expected the link to parse, got ${e.javaClass.simpleName}: ${e.message}")
                continue
            }
            val e = c.getJSONObject("expect")
            if (e.has("host")) assertEquals("case '$name': host", e.getString("host"), cfg.serverAddress)
            if (e.has("port")) assertEquals("case '$name': port", e.getInt("port"), cfg.port)
            if (e.has("user")) assertEquals("case '$name': user", e.getString("user"), cfg.username)
            if (e.has("pass")) assertEquals("case '$name': pass", e.getString("pass"), cfg.password)
            if (e.has("proto")) assertEquals("case '$name': proto", e.getString("proto"), cfg.protocol)
            if (e.has("mode")) assertEquals("case '$name': mode", e.getString("mode"), cfg.wireMode)
            if (e.has("server_key")) {
                // "" in the fixture means "unpinned"; Kotlin models that as null.
                val want = e.getString("server_key")
                val got = cfg.serverPublicKeyHex ?: ""
                assertEquals("case '$name': server_key", want, got)
            }
            if (e.has("sni")) assertEquals("case '$name': sni", nullable(e, "sni"), cfg.sni)
            if (e.has("reality_sid")) {
                assertEquals("case '$name': reality_sid", nullable(e, "reality_sid"), cfg.realityShortId)
            }
            if (e.has("obfs_key")) {
                // Kotlin models an absent obfs key as "" rather than null.
                assertEquals("case '$name': obfs_key", nullable(e, "obfs_key") ?: "", cfg.obfsKey)
            }
            if (e.has("quic")) assertEquals("case '$name': quic", e.getBoolean("quic"), cfg.quicEnabled)
            if (e.has("awg")) assertEquals("case '$name': awg", e.getBoolean("awg"), cfg.awgEnabled)
            if (e.has("jc")) assertEquals("case '$name': jc", e.getInt("jc"), cfg.awgJc)
            if (e.has("jmin")) assertEquals("case '$name': jmin", e.getInt("jmin"), cfg.awgJmin)
            if (e.has("jmax")) assertEquals("case '$name': jmax", e.getInt("jmax"), cfg.awgJmax)
        }
    }

    @Test
    fun `rejects every invalid fixture`() {
        val reject = fixtures().getJSONArray("reject")
        for (i in 0 until reject.length()) {
            val c = reject.getJSONObject(i)
            val name = c.getString("name")
            val uri = c.getString("uri")
            var parsed = false
            try {
                VpnConfig.fromQeliUri(uri)
                parsed = true
            } catch (_: Exception) {
                // expected
            }
            assertTrue("case '$name': this link MUST be rejected, but it parsed: $uri", !parsed)
        }
    }

    @Test
    fun `every valid fixture survives a round trip`() {
        // Emit and re-import: this is the check that catches a field being written into the
        // link with no branch to read it back (exactly what happened with `mtu`).
        val cases = fixtures().getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val name = c.getString("name")
            val first = VpnConfig.fromQeliUri(c.getString("uri"))
            val again = try {
                VpnConfig.fromQeliUri(first.toQeliUri())
            } catch (e: Exception) {
                fail("case '$name': re-emitted link does not parse: ${e.message}")
                continue
            }
            assertEquals("case '$name': host round-trip", first.serverAddress, again.serverAddress)
            assertEquals("case '$name': port round-trip", first.port, again.port)
            assertEquals("case '$name': user round-trip", first.username, again.username)
            assertEquals("case '$name': pass round-trip", first.password, again.password)
            assertEquals("case '$name': proto round-trip", first.protocol, again.protocol)
            assertEquals("case '$name': mode round-trip", first.wireMode, again.wireMode)
            assertEquals("case '$name': key round-trip", first.serverPublicKeyHex, again.serverPublicKeyHex)
            assertEquals("case '$name': sni round-trip", first.sni, again.sni)
            assertEquals("case '$name': rsid round-trip", first.realityShortId, again.realityShortId)
            assertEquals("case '$name': obfs round-trip", first.obfsKey, again.obfsKey)
            assertEquals("case '$name': quic round-trip", first.quicEnabled, again.quicEnabled)
            assertEquals("case '$name': awg round-trip", first.awgEnabled, again.awgEnabled)
            assertEquals("case '$name': mtu round-trip", first.mtu, again.mtu)
            assertEquals("case '$name': bind_static round-trip", first.bindStaticToSession, again.bindStaticToSession)
            if (first.awgEnabled) {
                assertEquals("case '$name': jc round-trip", first.awgJc, again.awgJc)
                assertEquals("case '$name': jmin round-trip", first.awgJmin, again.awgJmin)
                assertEquals("case '$name': jmax round-trip", first.awgJmax, again.awgJmax)
            }
        }
    }

    /** Fixture value that may be JSON `null`, meaning "absent". */
    private fun nullable(o: JSONObject, key: String): String? =
        if (o.isNull(key)) null else o.getString(key)
}
