package com.qeli

import android.Manifest
import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.widget.RemoteViews
import androidx.core.content.ContextCompat
import com.qeli.model.VpnConfig

/**
 * Home-screen widget — a 1-tap connect/disconnect button for the DEFAULT (active) profile,
 * the same shortcut as [QeliTileService] but on the launcher. State mirrors
 * [VpnServiceImpl.liveStatus]; the widget refreshes on the service's package-targeted
 * status broadcast (received here because the manifest filter lists com.qeli.STATUS and the
 * broadcast is package-scoped, so it survives the background implicit-broadcast restriction).
 */
class QeliWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, mgr: AppWidgetManager, ids: IntArray) {
        for (id in ids) render(context, mgr, id)
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)   // dispatches onUpdate/onEnabled/etc.
        when (intent.action) {
            ACTION_TOGGLE -> toggle(context)
            VpnServiceImpl.BROADCAST_STATUS -> refreshAll(context)
        }
    }

    /** Toggle: tear down a live/connecting tunnel, else connect the active profile. */
    private fun toggle(context: Context) {
        val busy = VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_CONNECTED ||
            VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_CONNECTING
        if (busy) {
            runCatching {
                context.startService(Intent(context, VpnServiceImpl::class.java)
                    .apply { action = VpnServiceImpl.ACTION_DISCONNECT })
            }
            return
        }
        connectDefault(context)
    }

    private fun connectDefault(context: Context) {
        val cfg = ProfileStore.activeProfileConfigText(context)
            ?.let { runCatching { VpnConfig.parse(it) }.getOrNull() }
        val needsConsent = runCatching { VpnService.prepare(context) != null }.getOrDefault(true)
        val needsNotif = Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED

        // Anything we can't do headless (OS consent, notif prompt, blank server) → open the app,
        // which owns those flows and connects on arrival (EXTRA_AUTO_CONNECT).
        if (cfg == null || cfg.serverAddress.isBlank() || cfg.serverAddress == "SERVER_IP_OR_HOST" ||
            needsConsent || needsNotif) {
            launchApp(context); return
        }
        try {
            val i = Intent(context, VpnServiceImpl::class.java).apply {
                action = VpnServiceImpl.ACTION_CONNECT
                putExtra(VpnServiceImpl.EXTRA_CONFIG, cfg)
            }
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(i) else context.startService(i)
        } catch (_: Exception) {
            // Background foreground-service start refused (API 31+) → fall back to the app.
            launchApp(context)
        }
    }

    private fun launchApp(context: Context) {
        val i = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra(MainActivity.EXTRA_AUTO_CONNECT, true)
        }
        runCatching { context.startActivity(i) }
    }

    private fun refreshAll(context: Context) {
        val mgr = AppWidgetManager.getInstance(context) ?: return
        val ids = mgr.getAppWidgetIds(ComponentName(context, QeliWidgetProvider::class.java))
        for (id in ids) render(context, mgr, id)
    }

    private fun render(context: Context, mgr: AppWidgetManager, id: Int) {
        val views = RemoteViews(context.packageName, R.layout.widget_qeli)
        val (labelRes, colorRes) = when (VpnServiceImpl.liveStatus) {
            VpnServiceImpl.STATUS_CONNECTED -> R.string.connected to R.color.status_connected
            VpnServiceImpl.STATUS_CONNECTING -> R.string.connecting to R.color.status_connecting
            else -> R.string.widget_tap_connect to R.color.text_hint
        }
        views.setTextViewText(R.id.widgetStatus, context.getString(labelRes))
        views.setInt(R.id.widgetIcon, "setColorFilter", ContextCompat.getColor(context, colorRes))
        views.setOnClickPendingIntent(R.id.widgetRoot, togglePendingIntent(context))
        mgr.updateAppWidget(id, views)
    }

    private fun togglePendingIntent(context: Context): PendingIntent {
        val i = Intent(context, QeliWidgetProvider::class.java).apply { action = ACTION_TOGGLE }
        return PendingIntent.getBroadcast(
            context, 0, i,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    companion object {
        private const val ACTION_TOGGLE = "com.qeli.widget.TOGGLE"
    }
}
