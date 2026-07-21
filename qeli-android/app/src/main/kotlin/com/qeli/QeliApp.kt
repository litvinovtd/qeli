package com.qeli

import android.app.Application
import android.content.Context
import android.content.res.Configuration
import android.util.Log
import androidx.appcompat.app.AppCompatDelegate
import java.util.Locale

class QeliApp : Application() {

    override fun onCreate() {
        super.onCreate()

        // Apply the persisted theme as early as possible so the very first frame
        // already uses the right palette (no flash on launch).
        applyStoredTheme(this)
        // Log uncaught exceptions for diagnostics, then DELEGATE to the previous
        // handler so the process still crashes normally (produces an ANR/crash
        // report and lets Android restart cleanly). Swallowing them here left the
        // faulting thread dead and the app in a half-broken, silent state.
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            Log.e("QeliApp", "Uncaught exception in thread ${thread.name}", throwable)
            previous?.uncaughtException(thread, throwable)
        }
    }

    companion object {
        const val PREFS = "app_state"
        const val KEY_DARK = "dark_mode"
        const val KEY_CHECK_UPDATES = "check_updates"
        const val KEY_LANG = "lang"

        /** Supported UI languages, in the order the settings dialog lists them. */
        val LANGUAGES = listOf("en", "ru")
        const val DEFAULT_LANG = "en"

        /** Whether the user picked the dark theme (default: light). */
        fun isDark(ctx: Context): Boolean =
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_DARK, false)

        /** Opt-in: check GitHub for a newer version on connect (default OFF). Privacy:
         *  the check only runs while the tunnel is up (so it travels inside the tunnel). */
        fun isCheckUpdates(ctx: Context): Boolean =
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_CHECK_UPDATES, false)

        fun setCheckUpdates(ctx: Context, on: Boolean) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY_CHECK_UPDATES, on).apply()
        }

        /** Persist the choice and apply it (AppCompat recreates open activities). */
        fun setDark(ctx: Context, dark: Boolean) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY_DARK, dark).apply()
            AppCompatDelegate.setDefaultNightMode(
                if (dark) AppCompatDelegate.MODE_NIGHT_YES else AppCompatDelegate.MODE_NIGHT_NO
            )
        }

        /** The picked UI language ("en" | "ru"); unknown/absent falls back to English —
         *  so the app defaults to English regardless of the device locale. */
        fun language(ctx: Context): String =
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getString(KEY_LANG, DEFAULT_LANG)
                ?.takeIf { it in LANGUAGES } ?: DEFAULT_LANG

        /** Persist the chosen UI language. The Activity applies it by calling recreate(),
         *  which re-runs attachBaseContext and re-wraps with the new locale. */
        fun setLanguage(ctx: Context, lang: String) {
            val value = lang.takeIf { it in LANGUAGES } ?: DEFAULT_LANG
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY_LANG, value).apply()
        }

        /**
         * Wrap a base context so its resources resolve in the chosen UI language (default
         * English). Applied from Activity.attachBaseContext — the earliest point, before any
         * view or string is loaded — so it deterministically overrides the device locale.
         *
         * This deliberately does NOT use AppCompatDelegate.setApplicationLocales: that needs
         * an AppLocalesMetadataHolderService in the manifest to work at all on API < 33, and
         * even where it works, calling it from Application.onCreate doesn't reliably beat the
         * device locale for the first Activity — which is exactly why a Russian phone opened
         * the app in Russian instead of the intended English default.
         */
        fun wrap(base: Context): Context {
            val config = Configuration(base.resources.configuration)
            config.setLocale(Locale.forLanguageTag(language(base)))
            return base.createConfigurationContext(config)
        }

        fun applyStoredTheme(ctx: Context) {
            AppCompatDelegate.setDefaultNightMode(
                if (isDark(ctx)) AppCompatDelegate.MODE_NIGHT_YES else AppCompatDelegate.MODE_NIGHT_NO
            )
        }
    }
}
