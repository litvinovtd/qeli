package com.qeli

import java.io.ByteArrayOutputStream
import java.io.InputStream

/** Bound allocation and consumed bytes without trusting content length or stream availability. */
internal object BoundedInput {
    fun read(input: InputStream, maxBytes: Int, exceeded: String = "input exceeds $maxBytes bytes"): ByteArray {
        require(maxBytes in 0 until Int.MAX_VALUE) { "invalid input byte limit" }
        val output = object : ByteArrayOutputStream(minOf(maxBytes, 16 * 1024)) {
            fun wipe() { buf.fill(0); reset() }
        }
        val buffer = ByteArray(16 * 1024)
        try {
            while (true) {
                val count = input.read(buffer, 0, minOf(buffer.size, maxBytes - output.size() + 1))
                if (count < 0) break
                if (count == 0) {
                    // A provider returning zero must not spin forever or masquerade as EOF.
                    val value = input.read()
                    if (value < 0) break
                    require(output.size() < maxBytes) { exceeded }
                    output.write(value)
                } else {
                    require(count <= maxBytes - output.size()) { exceeded }
                    output.write(buffer, 0, count)
                }
            }
            return output.toByteArray()
        } finally {
            buffer.fill(0)
            output.wipe()
        }
    }
}
