package com.qeli

import com.qeli.model.VpnConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class ProfileAppsEditorTest {
    private val profile = """[qeli]
server = vpn.example:443
apps_mode = include
apps = com.old
# apps_mode comment remains

[logging]
level = debug
"""

    @Test fun selectionStaysInQeliBeforeLogging() {
        val edited = ProfileAppsEditor.replace(profile, "exclude", listOf("com.example"))
        val qeli = edited.substringBefore("[logging]")
        val logging = edited.substringAfter("[logging]")
        assertTrue(qeli.contains("apps_mode = exclude"))
        assertTrue(qeli.contains("apps = com.example"))
        assertFalse(qeli.contains("com.old"))
        assertTrue(qeli.contains("# apps_mode comment remains"))
        assertFalse(logging.contains("apps_mode ="))
        assertEquals("exclude", VpnConfig.fromIni(edited).appsMode)
        assertEquals(listOf("com.example"), VpnConfig.fromIni(edited).apps)
    }

    @Test fun exactKeysAreRemovedWithoutDamagingOtherText() {
        val input = """[QELI]
APPS_MODE = include
Apps = com.old
apps_mode_extra = keep
# apps = comment
[logging]
level = info
"""
        val edited = ProfileAppsEditor.replace(input, "all", emptyList())
        assertFalse(edited.contains("APPS_MODE ="))
        assertFalse(edited.contains("Apps = com.old"))
        assertTrue(edited.contains("apps_mode_extra = keep"))
        assertTrue(edited.contains("# apps = comment"))
        assertTrue(edited.contains("[logging]\nlevel = info"))
    }

    @Test fun malformedSectionCannotReceiveAppKeys() {
        assertThrows(IllegalArgumentException::class.java) {
            ProfileAppsEditor.replace("[logging]\nlevel = debug", "include", listOf("com.example"))
        }
    }
}
