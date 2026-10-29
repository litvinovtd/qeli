package com.qeli

/** Local trust names. Carrier namespaces are independent; legacy trust is never reset. */
internal object ServerIdentityPolicy {
    fun isKeyMismatch(message: String): Boolean = message.contains("SERVER KEY MISMATCH")

    fun endpointId(protocol: String, host: String, port: Int): String {
        val address = host.trim().let { if (':' in it && !it.startsWith('[')) "[$it]" else it }
        require(protocol.lowercase() in setOf("tcp", "udp")) { "invalid server transport" }
        return "${protocol.lowercase()}://$address:$port"
    }

    fun storageId(eventId: String, protocol: String, host: String, port: Int): String {
        val scoped = endpointId(protocol, host, port)
        // Older bundled cores emit the legacy identifier. Scope it from this session's
        // validated configuration rather than mixing it with another transport's pin.
        if (eventId != scoped && eventId != "$host:$port" && eventId != legacyId(scoped))
            throw SecurityException("native server identity endpoint does not match the profile")
        return scoped
    }

    fun verifyExplicit(received: String, expected: String?): Boolean {
        if (expected.isNullOrBlank()) return false
        val normalized = expected.replace(":", "").replace("-", "").replace(" ", "")
        if (normalized.length == 64 && normalized.all { it == '0' }) return false
        verify("configured key", received, normalized)
        return true
    }

    fun checkKnownHost(serverId: String, received: String, lookup: (String) -> String?): Boolean {
        lookup(serverId)?.let { verify(serverId, received, it); return true }
        legacyId(serverId)?.let { legacy -> lookup(legacy)?.let { verify(legacy, received, it) } }
        // Matching legacy entries must be copied, not removed or overwritten.
        return false
    }

    private fun legacyId(serverId: String): String? {
        val endpoint = when {
            serverId.startsWith("tcp://") -> serverId.removePrefix("tcp://")
            serverId.startsWith("udp://") -> serverId.removePrefix("udp://")
            else -> return null
        }
        return if (endpoint.startsWith('[')) endpoint.removePrefix("[").replace("]:", ":") else endpoint
    }

    private fun verify(serverId: String, received: String, pinned: String) {
        if (!pinned.equals(received, ignoreCase = true)) throw SecurityException(
            "SERVER KEY MISMATCH for $serverId - possible MITM. Pinned $pinned, got $received. " +
                "Verify the correct profile key before replacing any saved pin."
        )
    }
}
