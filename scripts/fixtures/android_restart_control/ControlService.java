package com.qeli.audit.restartcontrol;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.util.Log;
import java.io.IOException;

/** Platform-only control: foreground + optional TUN + REDELIVER, no networking/native core. */
public final class ControlService extends VpnService {
    private ParcelFileDescriptor tun;
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        getSystemService(NotificationManager.class).createNotificationChannel(
            new NotificationChannel("q29-control", "Q29 audit", NotificationManager.IMPORTANCE_LOW));
        Notification notice = new Notification.Builder(this, "q29-control")
            .setContentTitle("Q29 restart control").setContentText("Disposable audit fixture")
            .setSmallIcon(android.R.drawable.ic_lock_lock).setOngoing(true).build();
        if (Build.VERSION.SDK_INT >= 34) startForeground(29, notice, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(29, notice);
        boolean withTun = getSharedPreferences("control", MODE_PRIVATE).getBoolean("with_tun", true);
        if (withTun && tun == null) {
            tun = new Builder().setSession("Q29 restart control").addAddress("10.88.29.2", 24)
                .addRoute("198.19.0.1", 32).setMtu(1400).establish();
            if (tun == null) throw new IllegalStateException("control TUN establish refused");
        }
        Log.i("Q29Control", "READY mode=" + (withTun ? "vpn" : "plain") + " pid=" + Process.myPid() +
            " flags=" + flags + " startId=" + startId + " action=" + (intent == null ? "null" : intent.getAction()) +
            " result=" + START_REDELIVER_INTENT);
        return START_REDELIVER_INTENT;
    }
    private void closeTun() {
        if (tun != null) {
            try { tun.close(); } catch (IOException error) { Log.e("Q29Control", "TUN close failed", error); }
            tun = null;
        }
    }
    @Override public void onRevoke() {
        Log.i("Q29Control", "REVOKED"); closeTun(); stopSelf();
    }
    @Override public void onDestroy() {
        closeTun(); super.onDestroy();
    }
}
