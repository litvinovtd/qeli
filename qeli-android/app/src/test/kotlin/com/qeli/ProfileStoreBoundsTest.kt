package com.qeli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ProfileStoreBoundsTest {
    @Test fun plaintextAndEnvelopeAcceptExactMaximum() {
        ProfileStore.requirePlaintextSize(ProfileStore.MAX_PROFILE_SET_BYTES)
        ProfileStore.requireEnvelopeSize(ProfileStore.MAX_ENVELOPE_BYTES)
        ProfileStore.requireBase64Size(ProfileStore.MAX_BASE64_CHARS)
        assertEquals(
            ((ProfileStore.MAX_ENVELOPE_BYTES + 2) / 3) * 4,
            ProfileStore.MAX_BASE64_CHARS,
        )
    }

    @Test fun eachLayerRejectsOversizedInputBeforeFurtherAllocation() {
        assertThrows(IllegalArgumentException::class.java) {
            ProfileStore.requirePlaintextSize(ProfileStore.MAX_PROFILE_SET_BYTES + 1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProfileStore.requireEnvelopeSize(ProfileStore.MAX_ENVELOPE_BYTES + 1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProfileStore.requireBase64Size(ProfileStore.MAX_BASE64_CHARS + 1)
        }
    }
}
