package com.qeli

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

/** Reject malformed bytes instead of silently changing credentials or INI text. */
internal fun decodeUtf8Strict(bytes: ByteArray): String =
    Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
