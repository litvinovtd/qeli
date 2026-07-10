package com.qeli

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject

/**
 * Single source of truth for the encrypted profile store, shared by [MainActivity] and the
 * Quick Settings tile ([QeliTileService]) so both open the SAME `EncryptedSharedPreferences`
 * with identical parameters (name, master-key scheme, encryption schemes). Profiles carry the
 * server password + obfs_key, so the store is encrypted at rest — the master key lives in the
 * Android Keystore (TEE/StrongBox where available).
 *
 * The stored blob (key [KEY_PROFILES]) is `{"active": <int>, "profiles": [{"name","cfg"}, …]}`,
 * where `cfg` is flat-INI. [MainActivity] owns writes + legacy migration; this object only reads.
 */
object ProfileStore {
    const val PREFS_SECURE = "vpn_secure"
    const val KEY_PROFILES = "profiles_json"

    /** Open the encrypted profile store. Callers within the same process get an instance
     *  backed by the same file, so [MainActivity] and the tile stay in sync. */
    fun open(context: Context): SharedPreferences = EncryptedSharedPreferences.create(
        context,
        PREFS_SECURE,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    /**
     * The config text (flat-INI, or legacy JSON — both accepted by `VpnConfig.parse`) of the
     * active/default profile: the one the app's "Connect" button uses. Returns null when the
     * store is empty/unreadable or the active entry has no config, in which case the tile falls
     * back to launching the app. Mirrors `MainActivity.loadProfiles`' `active` index + `cfg`/`json`.
     */
    fun activeProfileConfigText(context: Context): String? {
        val raw = try { open(context).getString(KEY_PROFILES, null) } catch (_: Exception) { null } ?: return null
        return try {
            val root = JSONObject(raw)
            val arr = root.optJSONArray("profiles") ?: return null
            if (arr.length() == 0) return null
            var idx = root.optInt("active", 0)
            if (idx !in 0 until arr.length()) idx = 0
            val p = arr.getJSONObject(idx)
            // New format stores `cfg` (INI); legacy stored `json` (JSON). Very old
            // {address,port,…} entries aren't handled here — the tile falls back to the app,
            // which normalizes them on load.
            p.optString("cfg", "").ifBlank { p.optString("json", "").ifBlank { null } }
        } catch (_: Exception) { null }
    }
}
