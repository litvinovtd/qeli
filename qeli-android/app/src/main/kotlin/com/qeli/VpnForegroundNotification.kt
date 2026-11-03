package com.qeli

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.res.Configuration

/** Both foreground records share the existing VPN notification and Disconnect action. */
internal object VpnForegroundNotification {
    const val ID = 1001
    private const val CHANNEL = "vpn_obfuscated_channel"

    fun text(context: Context, resource: Int): String {
        val configuration = Configuration(context.resources.configuration)
        configuration.setLocale(java.util.Locale.forLanguageTag(QeliApp.language(context)))
        return context.createConfigurationContext(configuration).getString(resource)
    }

    fun createChannel(context: Context) {
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, text(context, R.string.notif_channel_name), NotificationManager.IMPORTANCE_LOW),
        )
    }

    fun build(context: Context, message: String): Notification {
        val tap = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            }, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val disconnect = PendingIntent.getService(
            context, 1, Intent(context, VpnServiceImpl::class.java).setAction(VpnServiceImpl.ACTION_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(context, CHANNEL)
            .setContentTitle("Qeli").setContentText(message)
            .setSmallIcon(android.R.drawable.ic_lock_lock).setContentIntent(tap)
            .setOngoing(true).setVisibility(Notification.VISIBILITY_SECRET)
            .addAction(Notification.Action.Builder(
                android.graphics.drawable.Icon.createWithResource(context, android.R.drawable.ic_menu_close_clear_cancel),
                text(context, R.string.disconnect), disconnect,
            ).build()).build()
    }
}
