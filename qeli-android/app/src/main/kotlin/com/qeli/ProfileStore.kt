package com.qeli

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.google.crypto.tink.Aead
import com.google.crypto.tink.DeterministicAead
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.daead.DeterministicAeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

/**
 * Single source of truth for profile secrets shared by the Activity, VPN service and tile.
 * Values are encrypted with AES-256-GCM; the non-exportable key lives in Android Keystore.
 * The preference key is authenticated as AAD so ciphertext cannot be moved between entries.
 *
 * security-crypto 1.1 deprecated every public API. [LegacyEncryptedPreferences] is a read-only,
 * one-shot compatibility bridge for existing installs: it reads the old Tink keysets directly,
 * writes and verifies the new envelope, then removes the obsolete preference file. New writes do
 * not use androidx.security.crypto.
 */
object ProfileStore {
    const val KEY_PROFILES = "profiles_json"

    private const val PREFS_SECURE = "vpn_secure_v2"
    private const val KEY_ALIAS = "qeli_profile_store_v2_aes"
    private const val ENVELOPE_VERSION: Byte = 1
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_BYTES = 12
    private const val AAD_PREFIX = "qeli.profile-store.v2:"

    @Volatile
    private var singleton: SecureStore? = null

    @Synchronized
    fun open(context: Context): SecureStore {
        singleton?.let { return it }
        val app = context.applicationContext
        val store = SecureStore(app, PREFS_SECURE, KEY_ALIAS)
        if (!store.contains(KEY_PROFILES)) {
            LegacyEncryptedPreferences.readProfiles(app)?.let { legacy ->
                check(store.edit().putString(KEY_PROFILES, legacy).commit()) {
                    "Could not commit migrated profile store"
                }
                check(store.getString(KEY_PROFILES, null) == legacy) {
                    "Migrated profile store did not pass read-back verification"
                }
                LegacyEncryptedPreferences.erase(app)
            }
        }
        return store.also { singleton = it }
    }

    /** Minimal encrypted preference surface. Profiles are the only secret value stored here. */
    class SecureStore internal constructor(
        context: Context,
        private val preferenceName: String,
        keyAlias: String,
    ) {
        private val backing = context.getSharedPreferences(preferenceName, Context.MODE_PRIVATE)
        private val key = loadOrCreateKey(keyAlias)

        fun contains(key: String): Boolean = backing.contains(key)

        fun getString(key: String, defaultValue: String?): String? {
            val envelope = backing.getString(key, null) ?: return defaultValue
            return decrypt(key, envelope)
        }

        fun edit(): Editor = Editor(this)

        private fun encrypt(preferenceKey: String, value: String): String {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(aad(preferenceKey))
            val iv = cipher.iv
            check(iv.size == GCM_IV_BYTES) { "Android Keystore returned a non-standard GCM IV" }
            val ciphertext = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
            val envelope = ByteBuffer.allocate(1 + iv.size + ciphertext.size)
                .put(ENVELOPE_VERSION)
                .put(iv)
                .put(ciphertext)
                .array()
            return Base64.encodeToString(envelope, Base64.NO_WRAP)
        }

        private fun decrypt(preferenceKey: String, encoded: String): String {
            try {
                val envelope = Base64.decode(encoded, Base64.NO_WRAP)
                require(envelope.size >= 1 + GCM_IV_BYTES + GCM_TAG_BITS / 8) {
                    "encrypted profile envelope is truncated"
                }
                val buffer = ByteBuffer.wrap(envelope)
                require(buffer.get() == ENVELOPE_VERSION) {
                    "unsupported encrypted profile envelope version"
                }
                val iv = ByteArray(GCM_IV_BYTES).also(buffer::get)
                val ciphertext = ByteArray(buffer.remaining()).also(buffer::get)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
                cipher.updateAAD(aad(preferenceKey))
                return cipher.doFinal(ciphertext).toString(Charsets.UTF_8)
            } catch (error: SecurityException) {
                throw error
            } catch (error: Exception) {
                throw SecurityException("Could not decrypt profile store", error)
            }
        }

        private fun aad(key: String): ByteArray = (AAD_PREFIX + preferenceName + ":" + key)
            .toByteArray(Charsets.UTF_8)

        class Editor internal constructor(private val store: SecureStore) {
            private val values = LinkedHashMap<String, String?>()

            fun putString(key: String, value: String?): Editor = apply { values[key] = value }
            fun remove(key: String): Editor = apply { values[key] = null }

            fun commit(): Boolean {
                val editor = store.backing.edit()
                values.forEach { (key, value) ->
                    if (value == null) editor.remove(key)
                    else editor.putString(key, store.encrypt(key, value))
                }
                return editor.commit()
            }

            fun apply() {
                val editor = store.backing.edit()
                values.forEach { (key, value) ->
                    if (value == null) editor.remove(key)
                    else editor.putString(key, store.encrypt(key, value))
                }
                editor.apply()
            }
        }
    }

    /**
     * Stored config text of the active profile. Current entries are flat INI. The legacy `json`
     * field is accepted only so old app-owned storage can reach the existing migration path;
     * VpnConfig continues to reject JSON as a config/import format.
     */
    fun activeProfileConfigText(context: Context): String? {
        val raw = try {
            open(context).getString(KEY_PROFILES, null)
        } catch (_: Exception) {
            null
        } ?: return null
        return try {
            val root = JSONObject(raw)
            val arr = root.optJSONArray("profiles") ?: return null
            if (arr.length() == 0) return null
            var idx = root.optInt("active", 0)
            if (idx !in 0 until arr.length()) idx = 0
            val profile = arr.getJSONObject(idx)
            profile.optString("cfg", "").ifBlank {
                profile.optString("json", "").ifBlank { null }
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun loadOrCreateKey(alias: String): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build(),
            )
            generateKey()
        }
    }

    private object LegacyEncryptedPreferences {
        private const val FILE = "vpn_secure"
        private const val MASTER_URI = "android-keystore://_androidx_security_master_key_"
        private const val KEY_KEYSET = "__androidx_security_crypto_encrypted_prefs_key_keyset__"
        private const val VALUE_KEYSET = "__androidx_security_crypto_encrypted_prefs_value_keyset__"
        private const val STRING_TYPE = 0

        fun readProfiles(context: Context): String? {
            val raw = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            if (!raw.contains(KEY_KEYSET) || !raw.contains(VALUE_KEYSET)) return null
            if (raw.all.keys.none { it != KEY_KEYSET && it != VALUE_KEYSET }) return null

            DeterministicAeadConfig.register()
            AeadConfig.register()
            val keyAead: DeterministicAead = AndroidKeysetManager.Builder()
                .withSharedPref(context, KEY_KEYSET, FILE)
                .withMasterKeyUri(MASTER_URI)
                .build()
                .keysetHandle
                .getPrimitive(RegistryConfiguration.get(), DeterministicAead::class.java)
            val valueAead: Aead = AndroidKeysetManager.Builder()
                .withSharedPref(context, VALUE_KEYSET, FILE)
                .withMasterKeyUri(MASTER_URI)
                .build()
                .keysetHandle
                .getPrimitive(RegistryConfiguration.get(), Aead::class.java)

            val encryptedKey = Base64.encodeToString(
                keyAead.encryptDeterministically(
                    KEY_PROFILES.toByteArray(Charsets.UTF_8),
                    FILE.toByteArray(Charsets.UTF_8),
                ),
                Base64.NO_WRAP,
            )
            val encodedValue = raw.getString(encryptedKey, null) ?: return null
            val clear = valueAead.decrypt(
                Base64.decode(encodedValue, Base64.DEFAULT),
                encryptedKey.toByteArray(Charsets.UTF_8),
            )
            val buffer = ByteBuffer.wrap(clear)
            require(buffer.remaining() >= Int.SIZE_BYTES * 2 && buffer.int == STRING_TYPE) {
                "legacy profile entry has an invalid type"
            }
            val length = buffer.int
            require(length >= 0 && length == buffer.remaining()) {
                "legacy profile entry has an invalid length"
            }
            return ByteArray(length).also(buffer::get).toString(Charsets.UTF_8)
        }

        fun erase(context: Context) {
            check(context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().clear().commit()) {
                "Migrated legacy profile store could not be erased"
            }
        }
    }
}
