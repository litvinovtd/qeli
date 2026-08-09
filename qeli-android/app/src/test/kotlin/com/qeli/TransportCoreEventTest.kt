package com.qeli

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TransportCoreEventTest {
    private fun frame(
        payload: ByteArray = ByteArray(0),
        declaredLength: Int = payload.size,
        kind: Int = 2,
        sequence: Long = 17,
        planGeneration: Long = 9,
    ): ByteArray {
        return ByteBuffer.allocate(TransportCoreEventCodec.HEADER_SIZE + payload.size)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(TransportCoreEventCodec.HEADER_SIZE)
            .putInt(0x00010002)
            .putInt(kind)
            .putInt(2)
            .putInt(1)
            .putInt(0)
            .putLong(sequence)
            .putLong(planGeneration)
            .putInt(0)
            .putInt(declaredLength)
            .put(payload)
            .array()
    }

    @Test
    fun decodesTheStableLittleEndianHeaderAndPayload() {
        val payload = "{\"generation\":9}".toByteArray()
        val event = TransportCoreEventCodec.decode(frame(payload))

        assertEquals(0x00010002, event.abiVersion)
        assertEquals(2, event.kind)
        assertEquals(2, event.state)
        assertEquals(17L, event.sequence)
        assertEquals(9L, event.planGeneration)
        assertArrayEquals(payload, event.payload)
    }

    @Test
    fun rejectsTruncatedAndLengthMismatchedFrames() {
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decode(ByteArray(47))
        }
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decode(frame(byteArrayOf(1, 2), declaredLength = 3))
        }
    }

    @Test
    fun decodesSocketProtectRequestUsingEventSequenceAsRequestId() {
        val event = TransportCoreEventCodec.decode(
            frame(
                payload = "{\"fd\":42}".toByteArray(),
                kind = TransportCoreEventCodec.KIND_SOCKET_PROTECT,
                sequence = 23,
                planGeneration = 0,
            )
        )

        assertEquals(
            TransportCoreSocketProtectRequest(sequence = 23, fd = 42),
            TransportCoreEventCodec.decodeSocketProtect(event),
        )
    }

    @Test
    fun rejectsSocketProtectRequestWithInvalidCorrelationOrFd() {
        val stale = TransportCoreEventCodec.decode(
            frame(
                payload = "{\"fd\":42}".toByteArray(),
                kind = TransportCoreEventCodec.KIND_SOCKET_PROTECT,
                sequence = 0,
                planGeneration = 0,
            )
        )
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decodeSocketProtect(stale)
        }

        val invalidFd = TransportCoreEventCodec.decode(
            frame(
                payload = "{\"fd\":-1}".toByteArray(),
                kind = TransportCoreEventCodec.KIND_SOCKET_PROTECT,
                sequence = 23,
                planGeneration = 0,
            )
        )
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decodeSocketProtect(invalidFd)
        }
    }

    @Test
    fun decodesProvenServerIdentityUsingEventSequenceAsRequestId() {
        val key = "11".repeat(32)
        val event = TransportCoreEventCodec.decode(
            frame(
                payload = "{\"server_id\":\"vpn.example:443\",\"public_key\":\"$key\"}"
                    .toByteArray(),
                kind = TransportCoreEventCodec.KIND_SERVER_IDENTITY,
                sequence = 31,
                planGeneration = 0,
            )
        )

        assertEquals(
            TransportCoreServerIdentityRequest(31, "vpn.example:443", key),
            TransportCoreEventCodec.decodeServerIdentity(event),
        )
    }

    @Test
    fun rejectsMalformedServerIdentityKey() {
        val event = TransportCoreEventCodec.decode(
            frame(
                payload = "{\"server_id\":\"vpn.example:443\",\"public_key\":\"xyz\"}"
                    .toByteArray(),
                kind = TransportCoreEventCodec.KIND_SERVER_IDENTITY,
                sequence = 31,
                planGeneration = 0,
            )
        )
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decodeServerIdentity(event)
        }
    }
}
