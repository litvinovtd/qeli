package com.qeli

/**
 * Generation-safe JNI owner for the shared Rust transport control plane.
 *
 * The Android service initially runs this in shadow mode: configuration and lifecycle pass
 * through the common core, while the established Kotlin packet loop remains the sole TUN
 * reader. [setTunFd] exists for the later network-plan handoff and must not be called before
 * the Rust core itself publishes that generation.
 */
internal class TransportCore private constructor(private var handle: Long) : AutoCloseable {
    @Synchronized
    fun start() = requireSuccess(nativeStart(requireHandle()), "start")

    @Synchronized
    fun stop() {
        val current = handle
        if (current != 0L) requireSuccess(nativeStop(current), "stop")
    }

    @Synchronized
    fun state(): Int {
        val value = nativeState(requireHandle())
        check(value >= 0) { "transport core state failed (rc=$value)" }
        return value
    }

    @Synchronized
    fun setTunFd(generation: Long, fd: Int) =
        requireSuccess(nativeSetTunFd(requireHandle(), generation, fd), "setTunFd")

    @Synchronized
    override fun close() {
        val current = handle
        if (current == 0L) return
        // Stop is best-effort during teardown: free is the ownership boundary and closes
        // every native resource even if the event queue cannot accept stop notifications.
        nativeStop(current)
        handle = 0
        requireSuccess(nativeFree(current), "free")
    }

    private fun requireHandle(): Long {
        check(handle != 0L) { "transport core is closed" }
        return handle
    }

    companion object {
        const val PLATFORM_ROUTES = 1L shl 0
        const val PLATFORM_DNS = 1L shl 1
        const val PLATFORM_KILL_SWITCH = 1L shl 2
        const val PLATFORM_TUN_FD = 1L shl 3
        const val PLATFORM_SOCKET_PROTECT = 1L shl 5
        const val PLATFORM_SYSTEM_PLAN =
            PLATFORM_ROUTES or PLATFORM_DNS or PLATFORM_KILL_SWITCH

        init {
            System.loadLibrary("qeli")
        }

        fun create(
            configText: String,
            platformCapabilities: Long = PLATFORM_SYSTEM_PLAN,
            eventCapacity: Int = 0,
        ): TransportCore {
            val bytes = configText.toByteArray(Charsets.UTF_8)
            val nativeHandle = try {
                nativeNew(bytes, platformCapabilities, eventCapacity)
            } finally {
                bytes.fill(0)
            }
            check(nativeHandle != 0L) { "transport core rejected the configuration" }
            return TransportCore(nativeHandle)
        }

        fun abiVersion(): Int = nativeAbiVersion()

        fun coreCapabilities(): Long = nativeCoreCapabilities()

        private fun requireSuccess(result: Int, operation: String) {
            check(result == 0) { "transport core $operation failed (rc=$result)" }
        }

        @JvmStatic private external fun nativeAbiVersion(): Int
        @JvmStatic private external fun nativeCoreCapabilities(): Long
        @JvmStatic private external fun nativeNew(
            config: ByteArray,
            platformCapabilities: Long,
            eventCapacity: Int,
        ): Long
        @JvmStatic private external fun nativeStart(handle: Long): Int
        @JvmStatic private external fun nativeStop(handle: Long): Int
        @JvmStatic private external fun nativeState(handle: Long): Int
        @JvmStatic private external fun nativeSetTunFd(handle: Long, generation: Long, fd: Int): Int
        @JvmStatic private external fun nativeFree(handle: Long): Int
    }
}
