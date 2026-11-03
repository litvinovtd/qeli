package com.qeli

import androidx.lifecycle.ViewModel
import com.qeli.model.VpnConfig

/** Retain only in memory across configuration changes; never persist profile secrets in Bundle. */
class VpnConnectViewModel : ViewModel() {
    internal val request = VpnConnectRequest()
}

/** Main-thread ownership of an Activity's permission flow and its validated profile snapshot. */
internal class VpnConnectRequest {
    enum class Permission { NOTIFICATION, VPN }
    private var configuration: VpnConfig? = null
    private var awaiting: Permission? = null
    val isActive: Boolean get() = configuration != null
    val hasOutstandingResult: Boolean get() = awaiting != null

    var reconfigure: Boolean = false
        private set

    fun begin(config: VpnConfig): Boolean = begin(config, false)

    fun begin(config: VpnConfig, reconfigure: Boolean): Boolean {
        if (isActive || hasOutstandingResult) return false
        configuration = config
        this.reconfigure = reconfigure
        return true
    }
    fun awaitPermission(permission: Permission) {
        check(isActive && awaiting == null)
        awaiting = permission
    }
    /** Cancellation drains the old callback before another request can own that launcher. */
    fun finishPermission(permission: Permission, granted: Boolean): Boolean {
        if (awaiting != permission) return false
        awaiting = null
        val owned = isActive
        if (!granted) configuration = null
        return owned
    }
    fun takeConfiguration(): VpnConfig? {
        if (hasOutstandingResult) return null
        return configuration.also { configuration = null }
    }
    fun cancel() { configuration = null }
    fun launchFailed(permission: Permission) {
        if (awaiting == permission) awaiting = null
        cancel()
    }
}
