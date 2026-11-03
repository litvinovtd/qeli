package com.qeli

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import org.junit.Assert.*
import org.junit.Test

class BoundedInputTest {
    @Test fun exactLimitPreservesBytesAcrossChunks() {
        val bytes = ByteArray(40_000) { (it % 251).toByte() }
        assertArrayEquals(bytes, BoundedInput.read(ByteArrayInputStream(bytes), bytes.size))
    }
    @Test fun oversizedStreamStopsAfterOneExtraByte() {
        var consumed = 0
        val input = object : InputStream() { override fun read(): Int { consumed++; return 42 } }
        assertThrows(IllegalArgumentException::class.java) { BoundedInput.read(input, 31) }
        assertEquals(32, consumed)
    }
    @Test fun zeroBulkReadDoesNotSpinOrLoseAByte() {
        val input = object : ByteArrayInputStream(byteArrayOf(1, 2, 3)) {
            override fun read(buffer: ByteArray, offset: Int, count: Int): Int = 0
        }
        assertArrayEquals(byteArrayOf(1, 2, 3), BoundedInput.read(input, 3))
    }
    @Test fun ioFailurePropagatesAndClearsReadBuffer() {
        var seen: ByteArray? = null
        val input = object : InputStream() {
            override fun read(): Int = throw IOException("fixture refusal")
            override fun read(buffer: ByteArray, offset: Int, count: Int): Int {
                seen = buffer; buffer[0] = 99; throw IOException("fixture refusal")
            }
        }
        assertThrows(IOException::class.java) { BoundedInput.read(input, 100) }
        assertTrue(requireNotNull(seen).all { it == 0.toByte() })
    }
    @Test fun invalidBudgetIsRejectedBeforeReading() {
        var read = false
        val input = object : InputStream() { override fun read(): Int { read = true; return -1 } }
        assertThrows(IllegalArgumentException::class.java) { BoundedInput.read(input, -1) }
        assertThrows(IllegalArgumentException::class.java) { BoundedInput.read(input, Int.MAX_VALUE) }
        assertFalse(read)
    }
    @Test fun emptyStreamAndZeroBudgetAreDistinguishedFromOverflow() {
        assertArrayEquals(byteArrayOf(), BoundedInput.read(ByteArrayInputStream(byteArrayOf()), 0))
        assertThrows(IllegalArgumentException::class.java) { BoundedInput.read(ByteArrayInputStream(byteArrayOf(1)), 0) }
    }
    @Test fun callerOwnsTheStreamAndItsFailureMessage() {
        var closed = false
        val input = object : ByteArrayInputStream(byteArrayOf(1, 2)) { override fun close() { closed = true } }
        val error = assertThrows(IllegalArgumentException::class.java) { BoundedInput.read(input, 1, "import budget") }
        assertEquals("import budget", error.message); assertFalse(closed)
    }
}
