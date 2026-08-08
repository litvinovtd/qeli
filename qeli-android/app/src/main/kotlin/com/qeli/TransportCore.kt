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
    fun pollEvent(): TransportCoreEvent? =
        nativePollEvent(requireHandle())?.let(TransportCoreEventCodec::decode)

    @Synchronized
    fun drainEvents(limit: Int = 64): List<TransportCoreEvent> {
        require(limit in 1..256) { "event drain limit must be 1..256" }
        val events = ArrayList<TransportCoreEvent>()
        repeat(limit) {
            val event = nativePollEvent(requireHandle()) ?: return events
            events += TransportCoreEventCodec.decode(event)
        }
        error("transport core emitted more than $limit events without quiescing")
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

        const val STATE_CREATED = 0
        const val STATE_CONNECTING = 1

        private const val ABI_VERSION = 0x00010001
        private const val CORE_STRICT_CONFIG = 1L shl 0
        private const val CORE_LIFECYCLE_EVENTS = 1L shl 1
        private const val CORE_NETWORK_PLAN_ACK = 1L shl 2
        private const val REQUIRED_CORE_CAPABILITIES =
            CORE_STRICT_CONFIG or CORE_LIFECYCLE_EVENTS or CORE_NETWORK_PLAN_ACK

        init {
            System.loadLibrary("qeli")
        }

        fun create(
            configText: String,
            platformCapabilities: Long = PLATFORM_SYSTEM_PLAN,
            eventCapacity: Int = 0,
        ): TransportCore {
            val libraryVersion = nativeAbiVersion()
            check(
                libraryVersion ushr 16 == ABI_VERSION ushr 16 &&
                    (libraryVersion and 0xffff) >= (ABI_VERSION and 0xffff)
            ) { "incompatible transport core ABI 0x${libraryVersion.toUInt().toString(16)}" }
            val capabilities = nativeCoreCapabilities()
            check(capabilities and REQUIRED_CORE_CAPABILITIES == REQUIRED_CORE_CAPABILITIES) {
                "transport core is missing required lifecycle capabilities"
            }
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
        @JvmStatic private external fun nativePollEvent(handle: Long): ByteArray?
        @JvmStatic private external fun nativeSetTunFd(handle: Long, generation: Long, fd: Int): Int
        @JvmStatic private external fun nativeFree(handle: Long): Int
    }
}
