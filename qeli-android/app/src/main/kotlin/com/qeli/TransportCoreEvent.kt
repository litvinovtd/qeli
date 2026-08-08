package com.qeli

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.json.JSONObject

/** Stable Android view of one shared-core control-plane event. */
internal data class TransportCoreEvent(
    val abiVersion: Int,
    val kind: Int,
    val state: Int,
    val payloadFormat: Int,
    val sequence: Long,
    val planGeneration: Long,
    val errorCode: Int,
    val payload: ByteArray,
)

internal data class TransportCoreSocketProtectRequest(
    val sequence: Long,
    val fd: Int,
)

/** Decoder for the JNI event frame. Kept separate from [TransportCore] so JVM tests do not
 * load the Android native library merely to validate framing. */
internal object TransportCoreEventCodec {
    const val HEADER_SIZE = 48
    const val KIND_STATE_CHANGED = 1
    const val KIND_NETWORK_PLAN = 2
    const val KIND_ERROR = 3
    const val KIND_SOCKET_PROTECT = 4
    const val PAYLOAD_JSON = 1
    const val PAYLOAD_UTF8 = 2

    fun decode(frame: ByteArray): TransportCoreEvent {
        require(frame.size >= HEADER_SIZE) { "transport core event header is truncated" }
        val input = ByteBuffer.wrap(frame).order(ByteOrder.LITTLE_ENDIAN)
        val structSize = input.int
        require(structSize == HEADER_SIZE) { "unsupported transport core event header $structSize" }
        val abiVersion = input.int
        require(abiVersion ushr 16 == 1) { "unsupported transport core ABI 0x${abiVersion.toUInt().toString(16)}" }
        val kind = input.int
        val state = input.int
        val payloadFormat = input.int
        val reserved = input.int
        require(reserved == 0) { "transport core event reserved field is non-zero" }
        val sequence = input.long
        val planGeneration = input.long
        val errorCode = input.int
        val payloadLength = Integer.toUnsignedLong(input.int)
        require(payloadLength == input.remaining().toLong()) {
            "transport core event payload length mismatch"
        }
        val payload = ByteArray(payloadLength.toInt())
        input.get(payload)
        return TransportCoreEvent(
            abiVersion = abiVersion,
            kind = kind,
            state = state,
            payloadFormat = payloadFormat,
            sequence = sequence,
            planGeneration = planGeneration,
            errorCode = errorCode,
            payload = payload,
        )
    }

    fun decodeSocketProtect(event: TransportCoreEvent): TransportCoreSocketProtectRequest {
        require(event.kind == KIND_SOCKET_PROTECT) { "event is not a socket protect request" }
        require(event.payloadFormat == PAYLOAD_JSON) { "socket protect payload is not JSON" }
        require(event.sequence > 0) { "socket protect request sequence must be positive" }
        require(event.planGeneration == 0L) { "socket protect request has a plan generation" }
        require(event.errorCode == 0) { "socket protect request has an error code" }
        val fd = JSONObject(event.payload.toString(Charsets.UTF_8)).getLong("fd")
        require(fd in 0..Int.MAX_VALUE.toLong()) { "socket protect fd is outside Int range" }
        return TransportCoreSocketProtectRequest(event.sequence, fd.toInt())
    }
}
