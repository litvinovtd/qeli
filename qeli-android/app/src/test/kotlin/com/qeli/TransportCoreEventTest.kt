package com.qeli

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TransportCoreEventTest {
    private fun frame(payload: ByteArray = ByteArray(0), declaredLength: Int = payload.size): ByteArray {
        return ByteBuffer.allocate(TransportCoreEventCodec.HEADER_SIZE + payload.size)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(TransportCoreEventCodec.HEADER_SIZE)
            .putInt(0x00010001)
            .putInt(2)
            .putInt(2)
            .putInt(1)
            .putInt(0)
            .putLong(17)
            .putLong(9)
            .putInt(0)
            .putInt(declaredLength)
            .put(payload)
            .array()
    }

    @Test
    fun decodesTheStableLittleEndianHeaderAndPayload() {
        val payload = "{\"generation\":9}".toByteArray()
        val event = TransportCoreEventCodec.decode(frame(payload))

        assertEquals(0x00010001, event.abiVersion)
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
}
