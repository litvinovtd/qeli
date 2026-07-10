package com.qeli

import android.Manifest
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import com.qeli.model.VpnConfig

/**
 * Quick Settings tile — one tap connects the DEFAULT (active) profile, one tap disconnects.
 * The QoL shortcut so a user doesn't have to open the app to toggle the VPN.
 *
 * State mirrors [VpnServiceImpl.liveStatus]; a receiver keeps the tile live while the QS panel
 * is open (onStartListening/onStopListening bracket its visibility). Connect path: if the OS
 * VPN consent ([VpnService.prepare]) or the POST_NOTIFICATIONS grant (API 33+) is missing, the
 * default profile is unreadable/blank, or a background foreground-service start is refused
 * (API 31+), we bounce through [MainActivity] (which owns those flows) via
 * startActivityAndCollapse; otherwise we start [VpnServiceImpl] directly with no UI.
 */
class QeliTileService : TileService() {

    private var receiver: BroadcastReceiver? = null

    override fun onStartListening() {
        super.onStartListening()
        // Stay live while the panel is open so a connect/disconnect in progress is reflected.
        if (receiver == null) {
            val r = object : BroadcastReceiver() {
                override fun onReceive(c: Context, i: Intent) = updateTile()
            }
            ContextCompat.registerReceiver(
                this, r, IntentFilter(VpnServiceImpl.BROADCAST_STATUS),
                ContextCompat.RECEIVER_NOT_EXPORTED,
            )
            receiver = r
        }
        updateTile()
    }

    override fun onStopListening() {
        receiver?.let { runCatching { unregisterReceiver(it) } }
        receiver = null
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        val busy = VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_CONNECTED ||
            VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_CONNECTING
        if (busy) {
            // Deliver a command to the already-running foreground service (allowed from bg).
            runCatching {
                startService(Intent(this, VpnServiceImpl::class.java)
                    .apply { action = VpnServiceImpl.ACTION_DISCONNECT })
            }
            reflect(VpnServiceImpl.STATUS_DISCONNECTED)   // optimistic; the broadcast corrects it
            return
        }
        connectDefault()
    }

    private fun connectDefault() {
        val cfg = ProfileStore.activeProfileConfigText(this)
            ?.let { runCatching { VpnConfig.parse(it) }.getOrNull() }
        val needsConsent = runCatching { VpnService.prepare(this) != null }.getOrDefault(true)
        val needsNotif = Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED

        // Anything the tile can't safely do headless → let the app handle it: the OS consent
        // dialog, the notification-permission prompt, or the profile editor for a blank server.
        if (cfg == null || cfg.serverAddress.isBlank() || cfg.serverAddress == "SERVER_IP_OR_HOST" ||
            needsConsent || needsNotif) {
            launchAppToConnect()
            return
        }

        // Consent + notifications OK: start the service directly. If the OS refuses a background
        // foreground-service start (API 31+), fall back to bringing the app forward.
        try {
            val intent = Intent(this, VpnServiceImpl::class.java).apply {
                action = VpnServiceImpl.ACTION_CONNECT
                putExtra(VpnServiceImpl.EXTRA_CONFIG, cfg)
            }
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
            reflect(VpnServiceImpl.STATUS_CONNECTING)   // optimistic; the broadcast corrects it
        } catch (_: Exception) {
            launchAppToConnect()
        }
    }

    /** Bring the app forward with a request to connect — it owns the consent / permission /
     *  editor flows. startActivityAndCollapse closes the QS panel first. */
    private fun launchAppToConnect() {
        val intent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra(MainActivity.EXTRA_AUTO_CONNECT, true)
        }
        if (Build.VERSION.SDK_INT >= 34) {
            val pi = PendingIntent.getActivity(
                this, 0, intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun updateTile() = reflect(VpnServiceImpl.liveStatus)

    private fun reflect(status: String) {
        val tile = qsTile ?: return
        val (state, sub) = when (status) {
            // Android has no dedicated "busy" tile state; connecting shows ACTIVE too.
            VpnServiceImpl.STATUS_CONNECTED -> Tile.STATE_ACTIVE to R.string.connected
            VpnServiceImpl.STATUS_CONNECTING -> Tile.STATE_ACTIVE to R.string.connecting
            else -> Tile.STATE_INACTIVE to R.string.disconnected
        }
        tile.state = state
        tile.label = getString(R.string.app_name)
        if (Build.VERSION.SDK_INT >= 29) tile.subtitle = getString(sub)
        tile.updateTile()
    }
}
