package com.qeli
import org.json.JSONObject
import org.json.JSONArray

/** Thin adapter; CIDR parsing, subtraction and route budgets are owned by Rust. */
internal object RouteComplements {
    private fun call(op: String, data: JSONObject) = ConfigCore.policy(op,data)
    internal fun hostPrefix(address: String): Int = call("host_prefix",JSONObject().put("value",address.substringBefore('/'))).getInt("value")
    internal fun needsSyntheticSink(fullTunnel: Boolean, hasAddress: Boolean, allowLeak: Boolean): Boolean =
        call("sink",JSONObject().put("full",fullTunnel).put("address",hasAddress).put("leak",allowLeak)).getBoolean("value")
    fun ipv4(excludes: List<String>): List<String>? = subtract("0.0.0.0/0",excludes)
    fun ipv6(excludes: List<String>): List<String>? = subtract("::/0",excludes)
    fun subtract(cidr: String, excludes: List<String>): List<String>? = try {
        val a=call("subtract",JSONObject().put("cidr",cidr).put("excludes",JSONArray(excludes))).getJSONArray("value")
        (0 until a.length()).map(a::getString)
    } catch (_: IllegalArgumentException) { null }
    fun overlaps(a: String, b: String): Boolean = try {
        call("overlaps",JSONObject().put("a",a).put("b",b)).getBoolean("value")
    } catch (_: IllegalArgumentException) { false }
    fun overridesOnLinkGateway(cidr: String, gateway: String, onLinkPrefix: Int): Boolean? = try {
        call("on_link",JSONObject().put("cidr",cidr).put("gateway",gateway).put("prefix",onLinkPrefix)).getBoolean("value")
    } catch (_: IllegalArgumentException) { null }
    fun countInstalledOriginals(originals: Set<String>, installedFragments: Set<String>, excludes: List<String>, protectedCidrs: Set<String>): Int =
        call("installed",JSONObject().put("originals",JSONArray(originals)).put("installed",JSONArray(installedFragments))
            .put("excludes",JSONArray(excludes)).put("protected",JSONArray(protectedCidrs))).getInt("value")
}
