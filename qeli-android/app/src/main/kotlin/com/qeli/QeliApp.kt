package com.qeli

import android.app.Application
import android.content.Context
import android.util.Log
import androidx.appcompat.app.AppCompatDelegate

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

        fun applyStoredTheme(ctx: Context) {
            AppCompatDelegate.setDefaultNightMode(
                if (isDark(ctx)) AppCompatDelegate.MODE_NIGHT_YES else AppCompatDelegate.MODE_NIGHT_NO
            )
        }
    }
}
