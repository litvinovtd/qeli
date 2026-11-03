package com.qeli.audit.restartcontrol;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/** Fixture-only mode setter; it does not start the service or implement a watchdog. */
public final class ModeReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (!"com.qeli.audit.CONTROL_MODE".equals(intent.getAction())) return;
        boolean withTun = intent.getBooleanExtra("with_tun", true);
        boolean committed = context.getSharedPreferences("control", Context.MODE_PRIVATE)
            .edit().putBoolean("with_tun", withTun).commit();
        Log.i("Q29Control", "MODE with_tun=" + withTun + " committed=" + committed);
    }
}
