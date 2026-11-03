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
import java.math.BigDecimal
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
    internal const val KEY_CONNECTION_INI = "connection_recovery_ini"
    const val MAX_PROFILE_SET_BYTES = ProfileLimits.MAX_ARCHIVE_BYTES
    const val MAX_PROFILES = ProfileLimits.MAX_PROFILES
    private const val PREFS_SECURE = "vpn_secure_v2"
    private const val KEY_ALIAS = "qeli_profile_store_v2_aes"
    private const val ENVELOPE_VERSION: Byte = 1
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_BYTES = 12
    // Version byte, IV and GCM tag around bounded plaintext.
    internal const val MAX_ENVELOPE_BYTES = MAX_PROFILE_SET_BYTES + 1 + GCM_IV_BYTES + GCM_TAG_BITS / 8
    internal const val MAX_BASE64_CHARS = ((MAX_ENVELOPE_BYTES + 2) / 3) * 4
    private const val AAD_PREFIX = "qeli.profile-store.v2:"

    @Volatile
    private var singleton: SecureStore? = null

    @Synchronized
    fun open(context: Context): SecureStore {
        singleton?.let { return it }
        val app = context.applicationContext
        val store = SecureStore(app, PREFS_SECURE, KEY_ALIAS)
        if (!store.contains(KEY_PROFILES)) {
            var verified = false
            try {
                LegacyEncryptedPreferences.readProfiles(app)?.let { legacy ->
                    check(store.edit().putString(KEY_PROFILES, legacy).commit()) {
                        "Could not commit migrated profile store"
                    }
                    check(store.getString(KEY_PROFILES, null) == legacy) {
                        "Migrated profile store did not pass read-back verification"
                    }
                    verified = true
                    LegacyEncryptedPreferences.erase(app)
                }
            } catch (error: Exception) {
                if (verified) {
                    // The new entry is authoritative; preserve the old ciphertext for
                    // manual cleanup without making usable profiles inaccessible.
                    android.util.Log.w("ProfileStore", "Legacy encrypted profile cleanup failed")
                } else {
                    // Keep a versionable store so the UI can explicitly restore a backup.
                    // Ordinary reads/writes must not mistake failed migration for empty.
                    store.legacyMigrationFailure = error
                }
            }
        }
        return store.also { singleton = it }
    }

    /** Minimal encrypted preference surface for profiles and the active connection snapshot. */
    class SecureStore internal constructor(
        context: Context,
        private val preferenceName: String,
        keyAlias: String,
    ) {
        private val backing = context.getSharedPreferences(preferenceName, Context.MODE_PRIVATE)
        private val key = loadOrCreateKey(keyAlias)
        @Volatile internal var legacyMigrationFailure: Exception? = null

        fun contains(key: String): Boolean = backing.contains(key)

        fun getString(key: String, defaultValue: String?): String? {
            if (key == KEY_PROFILES) legacyMigrationFailure?.let {
                throw SecurityException("Legacy profile migration failed; explicitly restore a backup", it)
            }
            val envelope = backing.getString(key, null) ?: return defaultValue
            return decrypt(key, envelope)
        }

        fun edit(): Editor = Editor(this)

        /** Opaque encrypted value observed by an Activity, including a malformed entry. */
        data class Version(val present: Boolean, val encrypted: Any?)

        class StaleVersionException : IllegalStateException("Profile store changed in another app instance")

        fun version(key: String): Version = Version(backing.contains(key), backing.all[key])

        /** Serializes competing Activities in this process and refuses stale writes. */
        fun putStringIfVersion(
            key: String, expected: Version, value: String,
            allowUnreadableLegacyRecovery: Boolean = false,
        ): Version = synchronized(backing) {
                check(legacyMigrationFailure == null || allowUnreadableLegacyRecovery) {
                    "Legacy profile migration failed; ordinary profile writes are blocked"
                }
                if (version(key) != expected) throw StaleVersionException()
                check(backing.edit().putString(key, encrypt(key, value)).commit()) {
                    "Could not commit profile store"
                }
                if (key == KEY_PROFILES) legacyMigrationFailure = null
                version(key)
            }

        private fun encrypt(preferenceKey: String, value: String): String {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(aad(preferenceKey))
            val iv = cipher.iv
            check(iv.size == GCM_IV_BYTES) { "Android Keystore returned a non-standard GCM IV" }
            val plaintext = value.toByteArray(Charsets.UTF_8)
            val ciphertext = try {
                requirePlaintextSize(plaintext.size)
                cipher.doFinal(plaintext)
            } finally {
                plaintext.fill(0)
            }
            val envelope = ByteBuffer.allocate(1 + iv.size + ciphertext.size)
                .put(ENVELOPE_VERSION)
                .put(iv)
                .put(ciphertext)
                .array()
            return Base64.encodeToString(envelope, Base64.NO_WRAP)
        }

        private fun decrypt(preferenceKey: String, encoded: String): String {
            try {
                requireBase64Size(encoded.length)
                val envelope = Base64.decode(encoded, Base64.NO_WRAP)
                requireEnvelopeSize(envelope.size)
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
                val plaintext = cipher.doFinal(ciphertext)
                try {
                    requirePlaintextSize(plaintext.size)
                    return decodeUtf8Strict(plaintext)
                } finally {
                    plaintext.fill(0)
                }
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
                check(store.legacyMigrationFailure == null) {
                    "Legacy profile migration failed; ordinary profile writes are blocked"
                }
                val editor = store.backing.edit()
                values.forEach { (key, value) ->
                    if (value == null) editor.remove(key)
                    else editor.putString(key, store.encrypt(key, value))
                }
                return editor.commit()
            }

        }
    }

    /** The requested connection is independent of subsequent edits/selection in the UI. */
    fun saveConnectionConfig(context: Context, ini: String) {
        val store = open(context)
        check(store.edit().putString(KEY_CONNECTION_INI, ini).commit()) {
            "Could not persist connection recovery configuration"
        }
        check(store.getString(KEY_CONNECTION_INI, null) == ini) {
            "Connection recovery configuration failed read-back verification"
        }
    }

    fun connectionConfigText(context: Context): String? =
        open(context).getString(KEY_CONNECTION_INI, null)

    fun clearConnectionConfig(context: Context) {
        check(open(context).edit().remove(KEY_CONNECTION_INI).commit()) {
            "Could not remove connection recovery configuration"
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
            if (raw.toByteArray(Charsets.UTF_8).size > MAX_PROFILE_SET_BYTES) return null
            val root = JSONObject(raw)
            val arr = root.optJSONArray("profiles") ?: return null
            if (arr.length() !in 1..MAX_PROFILES) return null
            val profile = arr.getJSONObject(readActiveProfileIndex(root, arr.length()))
            profile.optString("cfg", "").ifBlank {
                profile.optString("json", "").ifBlank { null }
            }
        } catch (_: Exception) {
            null
        }
    }

    /** Missing active is a legacy default; malformed or out-of-range values cannot select another profile. */
    internal fun readActiveProfileIndex(root: JSONObject, count: Int): Int {
        require(count in 1..MAX_PROFILES) { "profile count is out of range" }
        val raw = root.opt("active")
        val index = when (raw) {
            null -> 0
            is Number -> try {
                BigDecimal(raw.toString()).intValueExact()
            } catch (_: ArithmeticException) {
                null
            } catch (_: NumberFormatException) {
                null
            }
            else -> null
        } ?: throw IllegalArgumentException("active profile index must be an integer")
        require(index in 0 until count) { "active profile index is out of range" }
        return index
    }

    internal fun requirePlaintextSize(size: Int) {
        require(size in 0..MAX_PROFILE_SET_BYTES) { "profile store plaintext exceeds 8 MiB" }
    }

    internal fun requireEnvelopeSize(size: Int) {
        require(size in 0..MAX_ENVELOPE_BYTES) { "encrypted profile envelope exceeds the safety limit" }
    }

    internal fun requireBase64Size(size: Int) {
        require(size in 0..MAX_BASE64_CHARS) { "encoded profile envelope exceeds the safety limit" }
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
            if (raw.all.keys.none { it != KEY_KEYSET && it != VALUE_KEYSET }) return null
            check(raw.contains(KEY_KEYSET) && raw.contains(VALUE_KEYSET)) {
                "Legacy encrypted profiles have missing keysets"
            }

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
            val plaintext = ByteArray(length).also(buffer::get)
            try { return decodeUtf8Strict(plaintext) }
            finally { plaintext.fill(0) }
        }

        fun erase(context: Context) {
            check(context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().clear().commit()) {
                "Migrated legacy profile store could not be erased"
            }
        }
    }
}
