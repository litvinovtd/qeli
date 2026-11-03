package com.qeli

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ProfileStoreActiveIndexTest {
    @Test fun absentIndexKeepsLegacyFirstProfile() {
        assertEquals(0, ProfileStore.readActiveProfileIndex(JSONObject("{}"), 2))
    }

    @Test fun integralIndexSelectsRequestedProfile() {
        for (value in listOf("1", "1.0", "1e0")) {
            assertEquals(1, ProfileStore.readActiveProfileIndex(JSONObject("""{"active":$value}"""), 2))
        }
    }

    @Test fun malformedIndexCannotSilentlySelectFirstProfile() {
        for (value in listOf("null", "true", "\"1\"", "1.5", "2147483648", "-1", "2")) {
            assertThrows("active=$value", IllegalArgumentException::class.java) {
                ProfileStore.readActiveProfileIndex(JSONObject("""{"active":$value}"""), 2)
            }
        }
    }

    @Test fun profileCountMustBeBounded() {
        assertThrows(IllegalArgumentException::class.java) {
            ProfileStore.readActiveProfileIndex(JSONObject("{}"), 0)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProfileStore.readActiveProfileIndex(JSONObject("{}"), ProfileStore.MAX_PROFILES + 1)
        }
    }
}
