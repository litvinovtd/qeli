package com.qeli

/**
 * Side-effect-free trusted Wi-Fi policy shared by the Activity, foreground service and tests.
 * SSIDs remain device-local and are never imported from a qeli:// profile.
 */
object TrustedWifiPolicy {
    enum class NetworkKind { TRUSTED_WIFI, OTHER_NETWORK, UNKNOWN_WIFI, NO_NETWORK }

    enum class PauseCompletionAction {
        STOP,
        WAIT,
        RESUME,
        RESUME_AFTER_REDACTION,
    }

    /** A deliberately absent TUN is incompatible with either form of lockdown. */
    fun canPause(configKillSwitch: Boolean, systemLockdown: Boolean): Boolean =
        !configKillSwitch && !systemLockdown

    /**
     * Decide what to do after the live TUN has finished shutting down for a trusted network.
     * Keeping this transition side-effect free makes the two teardown races testable without an
     * Android service: Disconnect wins, a newly-enabled lockdown restores the VPN, and a network
     * change that happened while teardown was running cannot leave the controller stuck waiting.
     */
    fun pauseCompletionAction(
        connectionDesired: Boolean,
        pauseAllowed: Boolean,
        networkKind: NetworkKind,
    ): PauseCompletionAction = when {
        !connectionDesired -> PauseCompletionAction.STOP
        !pauseAllowed -> PauseCompletionAction.RESUME
        networkKind == NetworkKind.OTHER_NETWORK -> PauseCompletionAction.RESUME
        networkKind == NetworkKind.UNKNOWN_WIFI -> PauseCompletionAction.RESUME_AFTER_REDACTION
        else -> PauseCompletionAction.WAIT
    }

    /** Pre-Android 12 callbacks include secondary networks; only the selected carrier may act. */
    fun shouldEvaluateCallback(isCurrentUnderlyingNetwork: Boolean): Boolean =
        isCurrentUnderlyingNetwork

    fun parse(raw: String?): List<String> {
        if (raw.isNullOrBlank()) return emptyList()
        return raw.lineSequence()
            .map(String::trim)
            .filter(String::isNotEmpty)
            .distinct()
            .toList()
    }

    fun serialize(ssids: Iterable<String>): String = ssids
        .map(String::trim)
        .filter(String::isNotEmpty)
        .distinct()
        .joinToString("\n")

    fun normalizeObservedSsid(raw: String?): String? {
        val value = raw?.trim()?.takeIf(String::isNotEmpty) ?: return null
        if (value.equals("<unknown ssid>", ignoreCase = true) ||
            value.equals("unknown ssid", ignoreCase = true)) return null
        return if (value.length >= 2 && value.first() == '"' && value.last() == '"') {
            value.substring(1, value.length - 1)
        } else {
            value
        }.takeIf(String::isNotEmpty)
    }

    fun classify(
        enabled: Boolean,
        configuredSsids: Collection<String>,
        hasNetwork: Boolean,
        isWifi: Boolean,
        observedSsid: String?,
    ): NetworkKind {
        if (!hasNetwork) return NetworkKind.NO_NETWORK
        if (!enabled || configuredSsids.isEmpty() || !isWifi) return NetworkKind.OTHER_NETWORK
        val ssid = normalizeObservedSsid(observedSsid) ?: return NetworkKind.UNKNOWN_WIFI
        return if (ssid in configuredSsids) NetworkKind.TRUSTED_WIFI else NetworkKind.OTHER_NETWORK
    }
}
