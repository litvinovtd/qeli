package com.qeli

/** Pure feature policy for the Android path adapter.
 *
 * Keeping transport eligibility outside [QeliService] makes the fail-closed rule JVM-testable:
 * every transport exposes the same exact-network transaction whenever the loaded core supports
 * it. The authenticated Rust negotiation remains the sole owner of whether the server and this
 * exact session enable TCP resume or the post-auth UDP CID envelope.
 */
internal object AndroidRoamingPolicy {
    const val PLATFORM_PATH_TRANSACTIONS = 1L shl 12
    const val PLATFORM_PATH_SOCKET_BINDING = 1L shl 13
    const val PLATFORM_PATH_REFRESH = 1L shl 14
    const val PLATFORM_ROAMING_PATH =
        PLATFORM_PATH_TRANSACTIONS or PLATFORM_PATH_SOCKET_BINDING

    fun platformCapabilities(
        coreSupportsPathTransactions: Boolean,
        coreSupportsPathRefreshRequests: Boolean,
    ): Long {
        if (!coreSupportsPathTransactions) return 0L
        return PLATFORM_ROAMING_PATH or
            (if (coreSupportsPathRefreshRequests) PLATFORM_PATH_REFRESH else 0L)
    }

    fun canSchedulePathUpdate(pathTransactionsEnabled: Boolean, generation: Long): Boolean =
        pathTransactionsEnabled && generation > 0
}
