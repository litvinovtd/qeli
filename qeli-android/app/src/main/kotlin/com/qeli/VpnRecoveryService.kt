package com.qeli

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.util.Log

/**
 * A same-process foreground record lets Android restart a killed VPN process even when it
 * discards the VpnService's redelivery record. A sticky null intent requests one guarded
 * recovery; it never contains credentials, creates a TUN, or changes the system VPN policy.
 */
class VpnRecoveryService : Service() {
    private var recoveryRequested = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val desired = getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
            .getBoolean(MainActivity.PREF_CONNECTION_DESIRED, false)
        if (!desired || VpnService.prepare(this) != null) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        try {
            VpnForegroundNotification.createChannel(this)
            val notification = getSystemService(android.app.NotificationManager::class.java)
                .activeNotifications.firstOrNull { it.id == VpnForegroundNotification.ID }?.notification
                ?: VpnForegroundNotification.build(this, VpnForegroundNotification.text(this, R.string.notif_connecting))
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(VpnForegroundNotification.ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(VpnForegroundNotification.ID, notification)
            }
            if (intent == null && !recoveryRequested) {
                recoveryRequested = true
                Log.i("VpnRecovery", "Android restarted the recovery record; requesting desired VPN recovery")
                startForegroundService(Intent(this, VpnServiceImpl::class.java).setAction(VpnServiceImpl.ACTION_RECOVER_DESIRED))
            }
            return START_STICKY
        } catch (error: Exception) {
            Log.e("VpnRecovery", "VPN recovery record unavailable", error)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
    }
}
