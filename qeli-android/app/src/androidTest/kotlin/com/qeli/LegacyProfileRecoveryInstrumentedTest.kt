package com.qeli

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Before
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

/** Run only in a disposable, initially empty test installation. */
@RunWith(AndroidJUnit4::class)
class LegacyProfileRecoveryInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val legacy by lazy { context.getSharedPreferences("vpn_secure", Context.MODE_PRIVATE) }
    private val current by lazy { context.getSharedPreferences("vpn_secure_v2", Context.MODE_PRIVATE) }
    private fun resetCache() {
        ProfileStore::class.java.getDeclaredField("singleton").apply { isAccessible = true }.set(null, null)
    }
    @After fun cleanup() {
        legacy.edit().clear().commit(); current.edit().clear().commit(); resetCache()
    }
    @Before fun prepare() {
        // Other instrumentation classes may have cached an empty production store.
        // Both migration cases need a cold open of their own legacy preferences.
        cleanup()
    }
    @Test fun unreadableLegacyStillExposesVersionAndBlocksOrdinaryWrites() {
        legacy.edit()
            .putString("__androidx_security_crypto_encrypted_prefs_key_keyset__", "not-a-hex-keyset")
            .putString("__androidx_security_crypto_encrypted_prefs_value_keyset__", "not-a-hex-keyset")
            .putString("legacy-encrypted-profile", "unreadable-ciphertext")
            .commit()
        val before = legacy.all.toMap()
        val store = ProfileStore.open(context)
        val revision = store.version(ProfileStore.KEY_PROFILES)
        assertFalse(revision.present)
        assertThrows(SecurityException::class.java) { store.getString(ProfileStore.KEY_PROFILES, null) }
        assertThrows(IllegalStateException::class.java) {
            store.putStringIfVersion(ProfileStore.KEY_PROFILES, revision, "ordinary write")
        }
        assertFalse(current.contains(ProfileStore.KEY_PROFILES))
        assertEquals(before, legacy.all)
        assertThrows(IllegalStateException::class.java) {
            store.edit().putString(ProfileStore.KEY_PROFILES, "ordinary editor").commit()
        }
        val backup = "{\"profiles\":[{\"name\":\"restored\",\"cfg\":\"[qeli]\\nserver = vpn.example:443\\nuser = fixture\\npass = secret\\n\"}],\"active\":0}"
        store.putStringIfVersion(ProfileStore.KEY_PROFILES, revision, backup, allowUnreadableLegacyRecovery = true)
        assertEquals(backup, store.getString(ProfileStore.KEY_PROFILES, null))
        assertEquals(before, legacy.all) // Keep the old recovery copy even after explicit restore.
        assertThrows(ProfileStore.SecureStore.StaleVersionException::class.java) {
            store.putStringIfVersion(ProfileStore.KEY_PROFILES, revision, "stale backup", allowUnreadableLegacyRecovery = true)
        }
        resetCache()
        assertEquals(backup, ProfileStore.open(context).getString(ProfileStore.KEY_PROFILES, null))
    }
    @Test fun partialLegacyKeysetsAreNotAnEmptyProfileStore() {
        legacy.edit().putString("legacy-encrypted-profile", "unreadable-ciphertext").commit()
        val before = legacy.all.toMap()
        val store = ProfileStore.open(context)
        val revision = store.version(ProfileStore.KEY_PROFILES)
        assertFalse(revision.present)
        assertThrows(SecurityException::class.java) { store.getString(ProfileStore.KEY_PROFILES, null) }
        assertThrows(IllegalStateException::class.java) {
            store.putStringIfVersion(ProfileStore.KEY_PROFILES, revision, "default profile")
        }
        assertEquals(before, legacy.all)
        assertFalse(current.contains(ProfileStore.KEY_PROFILES))
        store.putStringIfVersion(ProfileStore.KEY_PROFILES, revision, "explicit recovery", allowUnreadableLegacyRecovery = true)
        assertEquals("explicit recovery", store.getString(ProfileStore.KEY_PROFILES, null))
        assertEquals(before, legacy.all)
    }
}
