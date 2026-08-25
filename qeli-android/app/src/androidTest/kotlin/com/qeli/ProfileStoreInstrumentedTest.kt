package com.qeli

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ProfileStoreInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val prefsName = "profile_store_instrumented_test"
    private val keyAlias = "qeli_profile_store_instrumented_test"

    @After
    fun cleanUp() {
        context.getSharedPreferences(prefsName, Context.MODE_PRIVATE).edit().clear().commit()
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            if (containsAlias(keyAlias)) deleteEntry(keyAlias)
        }
    }

    @Test
    fun profileRoundTripsWithoutPlaintextAtRest() {
        val secret = "[server]\naddress = vpn.example\npassword = never-store-this-clear"
        val store = ProfileStore.SecureStore(context, prefsName, keyAlias)

        assertEquals(true, store.edit().putString("profile", secret).commit())
        assertEquals(secret, store.getString("profile", null))

        val encoded = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
            .getString("profile", null)!!
        assertNotEquals(secret, encoded)
        assertFalse(encoded.contains("never-store-this-clear"))
        assertEquals(
            secret,
            ProfileStore.SecureStore(context, prefsName, keyAlias)
                .getString("profile", null),
        )
    }

    @Test
    fun tamperAndCiphertextRelocationAreRejected() {
        val store = ProfileStore.SecureStore(context, prefsName, keyAlias)
        assertEquals(true, store.edit().putString("profile", "secret").commit())
        val raw = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
        val encoded = raw.getString("profile", null)!!

        raw.edit().putString("other", encoded).commit()
        assertThrows(SecurityException::class.java) { store.getString("other", null) }

        val bytes = Base64.decode(encoded, Base64.NO_WRAP)
        bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
        raw.edit().putString("profile", Base64.encodeToString(bytes, Base64.NO_WRAP)).commit()
        assertThrows(SecurityException::class.java) { store.getString("profile", null) }
    }
}
