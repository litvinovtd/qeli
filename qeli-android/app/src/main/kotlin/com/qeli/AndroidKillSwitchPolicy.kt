package com.qeli

/**
 * Result of binding the portable `kill_switch` setting to Android's OS-owned lockdown.
 *
 * A regular VPN app cannot enable "Block connections without VPN". It can, however, verify
 * Android's system-owned policy and refuse to establish an unprotected full tunnel. Keeping
 * this final decision pure makes the fail-closed cases unit testable without constructing an
 * Android service.
 */
internal enum class AndroidKillSwitchReadiness {
    NOT_REQUESTED,
    SPLIT_TUNNEL_IGNORED,
    LOCKDOWN_NOT_OBSERVABLE,
    ALWAYS_ON_DISABLED,
    LOCKDOWN_DISABLED,
    READY,
}

internal object AndroidKillSwitchPolicy {
    const val LOCKDOWN_STATUS_API = 29

    fun evaluate(
        requested: Boolean,
        fullTunnel: Boolean,
        apiLevel: Int,
        alwaysOn: Boolean,
        lockdown: Boolean,
    ): AndroidKillSwitchReadiness = when {
        !requested -> AndroidKillSwitchReadiness.NOT_REQUESTED
        !fullTunnel -> AndroidKillSwitchReadiness.SPLIT_TUNNEL_IGNORED
        apiLevel < LOCKDOWN_STATUS_API -> AndroidKillSwitchReadiness.LOCKDOWN_NOT_OBSERVABLE
        !alwaysOn -> AndroidKillSwitchReadiness.ALWAYS_ON_DISABLED
        !lockdown -> AndroidKillSwitchReadiness.LOCKDOWN_DISABLED
        else -> AndroidKillSwitchReadiness.READY
    }
}
