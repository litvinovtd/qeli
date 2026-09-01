package com.qeli

/** Pure feature policy for the Android path adapter.
 *
 * Keeping transport eligibility outside [QeliService] makes the fail-closed rule JVM-testable:
 * every transport exposes the same exact-network transaction whenever the loaded core supports
 * it. The authenticated Rust negotiation remains the sole owner of whether the server and this
 * exact session enable TCP resume or the post-auth UDP CID envelope.
 */
internal object AndroidRoamingPolicy {
    enum class AvailableNetworkAction {
        KEEP,
        ROAM,
    }

    const val PLATFORM_PATH_TRANSACTIONS = 1L shl 12
    const val PLATFORM_PATH_SOCKET_BINDING = 1L shl 13
    const val PLATFORM_PATH_REFRESH = 1L shl 14
    const val PLATFORM_ROAMING_PATH =
        PLATFORM_PATH_TRANSACTIONS or PLATFORM_PATH_SOCKET_BINDING
    private const val MAKE_BEFORE_BREAK_SETTLE_MS = 350L

    fun pathPreparationDelayMs(carrierWasLost: Boolean): Long =
        if (carrierWasLost) 0L else MAKE_BEFORE_BREAK_SETTLE_MS

    fun platformCapabilities(
        pathAllowedByConfig: Boolean,
        coreSupportsPathTransactions: Boolean,
        coreSupportsPathRefreshRequests: Boolean,
    ): Long {
        if (!pathAllowedByConfig || !coreSupportsPathTransactions) return 0L
        return PLATFORM_ROAMING_PATH or
            (if (coreSupportsPathRefreshRequests) PLATFORM_PATH_REFRESH else 0L)
    }

    fun canSchedulePathUpdate(pathTransactionsEnabled: Boolean, generation: Long): Boolean =
        pathTransactionsEnabled && generation > 0

    /** Android may report Wi-Fi loss before the cellular replacement becomes available.
     * In that break-before-make ordering, the first later onAvailable is a handover even though
     * there is no longer a previous Network object to compare with. */
    fun availableNetworkAction(
        hadCurrentNetwork: Boolean,
        waitingForReplacement: Boolean,
        networkChanged: Boolean,
        enteringTrustedWifi: Boolean,
    ): AvailableNetworkAction = when {
        enteringTrustedWifi -> AvailableNetworkAction.KEEP
        waitingForReplacement -> AvailableNetworkAction.ROAM
        hadCurrentNetwork && networkChanged -> AvailableNetworkAction.ROAM
        else -> AvailableNetworkAction.KEEP
    }

    fun shouldWaitForReplacement(
        connected: Boolean,
        generation: Long,
        hasServiceScope: Boolean,
        replacementAvailable: Boolean,
    ): Boolean = connected && generation > 0 && hasServiceScope && !replacementAvailable
}
