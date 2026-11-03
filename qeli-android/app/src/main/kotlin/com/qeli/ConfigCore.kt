package com.qeli

import org.json.JSONObject

/** ABI 1.16 pure document/policy service. No local parser or fallback. */
object ConfigCore {
    private val loadFailure: LinkageError? = try {
        val hostLibrary = System.getProperty("qeli.config.nativeLibrary")
        if (hostLibrary.isNullOrBlank()) System.loadLibrary("qeli") else System.load(hostLibrary)
        null
    } catch (error: LinkageError) { error }
    @JvmStatic private external fun nativeRequest(input: ByteArray): ByteArray
    fun call(request: JSONObject): JSONObject {
        loadFailure?.let { throw IllegalStateException("Qeli native configuration core is unavailable; rebuild/package ABI 1.16 or newer", it) }
        val input = request.toString().toByteArray(Charsets.UTF_8)
        val output = try {
            require(input.size <= 2 * 1024 * 1024) { "Configuration request too large" }
            nativeRequest(input)
        } catch (error: LinkageError) {
            throw IllegalStateException("Configuration editor requires Qeli native ABI 1.16 or newer", error)
        } finally { input.fill(0) }
        try {
            require(output.size <= 4 * 1024 * 1024) { "Configuration response too large" }
            val result = JSONObject(String(output, Charsets.UTF_8))
            require(result.getBoolean("ok")) { result.getString("error") }
            return result.getJSONObject("result")
        } finally { output.fill(0) }
    }
    fun policy(operation: String, data: JSONObject = JSONObject()): JSONObject =
        call(JSONObject().put("version",1).put("op","policy").put("operation",operation).put("data",data))
}
