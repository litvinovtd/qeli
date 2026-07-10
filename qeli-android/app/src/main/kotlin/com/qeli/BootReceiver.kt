package com.qeli

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import com.qeli.model.VpnConfig

/**
 * Auto-connect the active profile on device boot when the user opted in
 * ([MainActivity.PREF_AUTO_CONNECT_BOOT]). Requires the OS VPN consent to have already been
 * granted — we can't show the consent dialog from a boot receiver; if it isn't, we skip (the
 * user can also enable Android's system-level Always-on VPN for a guaranteed boot start).
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != "android.intent.action.QUICKBOOT_POWERON") return

        val prefs = context.getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(MainActivity.PREF_AUTO_CONNECT_BOOT, false)) return

        val cfg = ProfileStore.activeProfileConfigText(context)
            ?.let { runCatching { VpnConfig.parse(it) }.getOrNull() } ?: return
        if (cfg.serverAddress.isBlank() || cfg.serverAddress == "SERVER_IP_OR_HOST") return

        // No UI on boot → consent must already exist (prepare == null). Otherwise skip.
        if (runCatching { VpnService.prepare(context) != null }.getOrDefault(true)) return

        val svc = Intent(context, VpnServiceImpl::class.java).apply {
            action = VpnServiceImpl.ACTION_CONNECT
            putExtra(VpnServiceImpl.EXTRA_CONFIG, cfg)
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(svc)
            else context.startService(svc)
        }
    }
}
