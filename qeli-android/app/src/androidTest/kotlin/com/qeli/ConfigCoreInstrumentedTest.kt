package com.qeli

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.qeli.model.VpnConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

/** Execute the packaged Android JNI parser, not the host JNI library used by JVM tests. */
@RunWith(AndroidJUnit4::class)
class ConfigCoreInstrumentedTest {
    @Test
    fun packagedCoreParsesAndRoundTripsIni() {
        val ini = "[qeli]\nserver = vpn.example:443\nuser = selftest\npass = selftest\nmtu_probe = off\n"
        val config = VpnConfig.fromIni(ini)
        assertEquals("vpn.example", config.serverAddress)
        assertFalse(config.mtuProbe)
        val canonical = config.toIni()
        val restored = VpnConfig.fromIni(canonical)
        assertEquals(canonical, restored.toIni())
        assertFalse(restored.mtuProbe)
    }

    @Test
    fun packagedCoreRejectsJsonConfigAndForgedLink() {
        assertThrows(IllegalArgumentException::class.java) {
            VpnConfig.fromIni("{\"server\":{\"address\":\"vpn.example\",\"port\":443}}")
        }
        assertThrows(IllegalArgumentException::class.java) {
            VpnConfig.fromQeliUri("qeli://selftest:p%0Abind_static%20%3D%20false@vpn.example:443?proto=tcp&mode=fake-tls")
        }
    }
}
