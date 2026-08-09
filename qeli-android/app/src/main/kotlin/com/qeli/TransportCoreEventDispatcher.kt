package com.qeli

internal data class TransportCoreSocketProtectOutcome(
    val sequence: Long,
    val protected: Boolean,
    val reason: String?,
)

internal data class TransportCoreServerIdentityOutcome(
    val sequence: Long,
    val trusted: Boolean,
    val reason: String?,
)

/** Pure platform-event policy kept outside VpnService so retry and ACK decisions are JVM-tested. */
internal object TransportCoreEventDispatcher {
    const val PROTECT_ATTEMPTS = 5

    fun protectSocket(
        event: TransportCoreEvent,
        attempt: (Int) -> Boolean,
        beforeRetry: () -> Unit = {},
    ): TransportCoreSocketProtectOutcome {
        val request = TransportCoreEventCodec.decodeSocketProtect(event)
        var lastError: Exception? = null
        repeat(PROTECT_ATTEMPTS) { index ->
            val protected = try {
                attempt(request.fd)
            } catch (error: Exception) {
                lastError = error
                false
            }
            if (protected) {
                return TransportCoreSocketProtectOutcome(
                    sequence = request.sequence,
                    protected = true,
                    reason = null,
                )
            }
            if (index + 1 < PROTECT_ATTEMPTS) beforeRetry()
        }
        val detail = lastError?.message?.takeIf(String::isNotBlank)
        val reason = buildString {
            append("protect() failed after $PROTECT_ATTEMPTS attempts")
            if (detail != null) append(": ").append(detail)
        }
        return TransportCoreSocketProtectOutcome(
            sequence = request.sequence,
            protected = false,
            reason = reason,
        )
    }

    /** Apply Android known-host policy to a key whose possession Rust already proved. */
    fun verifyServerIdentity(
        event: TransportCoreEvent,
        verify: (serverId: String, publicKey: String) -> Unit,
    ): TransportCoreServerIdentityOutcome {
        val request = TransportCoreEventCodec.decodeServerIdentity(event)
        return try {
            verify(request.serverId, request.publicKey)
            TransportCoreServerIdentityOutcome(request.sequence, trusted = true, reason = null)
        } catch (error: Exception) {
            TransportCoreServerIdentityOutcome(
                request.sequence,
                trusted = false,
                reason = (error.message ?: "platform rejected the server identity").take(512),
            )
        }
    }
}
