package com.qeli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.charset.CharacterCodingException

class ProfileStoreUtf8Test {
    @Test fun malformedBytesCannotChangeStoredCredentials() {
        assertThrows(CharacterCodingException::class.java) {
            decodeUtf8Strict(byteArrayOf(0x70, 0x61, 0x73, 0x73, 0x3d, 0xC3.toByte()))
        }
    }

    @Test fun validUnicodeStoredTextIsPreserved() {
        val text = "pass=пароль\n"
        assertEquals(text, decodeUtf8Strict(text.toByteArray(Charsets.UTF_8)))
    }
}
