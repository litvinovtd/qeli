package com.qeli

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportCoreEventDispatcherTest {
    private fun socketProtectEvent(sequence: Long = 23, fd: Int = 42): TransportCoreEvent {
        val payload = "{\"fd\":$fd}".toByteArray()
        val frame = ByteBuffer.allocate(TransportCoreEventCodec.HEADER_SIZE + payload.size)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(TransportCoreEventCodec.HEADER_SIZE)
            .putInt(0x00010002)
            .putInt(TransportCoreEventCodec.KIND_SOCKET_PROTECT)
            .putInt(1) // Connecting; keep this pure JVM test independent of native loading.
            .putInt(TransportCoreEventCodec.PAYLOAD_JSON)
            .putInt(0)
            .putLong(sequence)
            .putLong(0)
            .putInt(0)
            .putInt(payload.size)
            .put(payload)
            .array()
        return TransportCoreEventCodec.decode(frame)
    }

    private fun serverIdentityEvent(sequence: Long = 31): TransportCoreEvent {
        val payload = (
            "{\"server_id\":\"vpn.example:443\",\"public_key\":\"${"11".repeat(32)}\"}"
        ).toByteArray()
        val frame = ByteBuffer.allocate(TransportCoreEventCodec.HEADER_SIZE + payload.size)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(TransportCoreEventCodec.HEADER_SIZE)
            .putInt(0x00010004)
            .putInt(TransportCoreEventCodec.KIND_SERVER_IDENTITY)
            .putInt(1)
            .putInt(TransportCoreEventCodec.PAYLOAD_JSON)
            .putInt(0)
            .putLong(sequence)
            .putLong(0)
            .putInt(0)
            .putInt(payload.size)
            .put(payload)
            .array()
        return TransportCoreEventCodec.decode(frame)
    }

    @Test
    fun retriesTheSameFdAndAcknowledgesTheFirstSuccess() {
        var attempts = 0
        var pauses = 0
        val outcome = TransportCoreEventDispatcher.protectSocket(
            socketProtectEvent(),
            attempt = { fd ->
                assertEquals(42, fd)
                ++attempts == 3
            },
            beforeRetry = { ++pauses },
        )

        assertTrue(outcome.protected)
        assertEquals(23, outcome.sequence)
        assertNull(outcome.reason)
        assertEquals(3, attempts)
        assertEquals(2, pauses)
    }

    @Test
    fun failsClosedAfterFiveFalseOrThrowingAttempts() {
        var attempts = 0
        val outcome = TransportCoreEventDispatcher.protectSocket(
            socketProtectEvent(),
            attempt = {
                ++attempts
                if (attempts == 2) throw IllegalStateException("platform unavailable")
                false
            },
        )

        assertFalse(outcome.protected)
        assertEquals(TransportCoreEventDispatcher.PROTECT_ATTEMPTS, attempts)
        assertTrue(outcome.reason!!.contains("5 attempts"))
        assertTrue(outcome.reason.contains("platform unavailable"))
    }

    @Test
    fun acknowledgesServerIdentityOnlyAfterKnownHostPolicyAcceptsIt() {
        var observedServer = ""
        var observedKey = ""
        val outcome = TransportCoreEventDispatcher.verifyServerIdentity(serverIdentityEvent()) {
                serverId, publicKey ->
            observedServer = serverId
            observedKey = publicKey
        }

        assertTrue(outcome.trusted)
        assertEquals(31, outcome.sequence)
        assertNull(outcome.reason)
        assertEquals("vpn.example:443", observedServer)
        assertEquals("11".repeat(32), observedKey)
    }

    @Test
    fun rejectsServerIdentityWhenKnownHostPolicyDetectsMismatch() {
        val outcome = TransportCoreEventDispatcher.verifyServerIdentity(serverIdentityEvent()) {
                _, _ ->
            throw SecurityException("SERVER KEY MISMATCH")
        }

        assertFalse(outcome.trusted)
        assertEquals(31, outcome.sequence)
        assertTrue(outcome.reason!!.contains("MISMATCH"))
    }
}
