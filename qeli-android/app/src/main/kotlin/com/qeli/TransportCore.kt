package com.qeli

/**
 * Generation-safe JNI owner for the shared Rust transport control plane.
 *
 * Kotlin services platform-only requests (VpnService.protect, trust and NetworkPlan/TUN).
 * The blocking [runTransport] entry point owns every handshake and payload byte in Rust.
 */
internal class TransportCore private constructor(private var handle: Long) : AutoCloseable {
    @Synchronized
    fun start() = requireSuccess(nativeStart(requireHandle()), "start")

    @Synchronized
    fun stop() {
        val current = handle
        if (current != 0L) requireSuccess(nativeStop(current), "stop")
    }

    /** Run one complete transport generation without holding this object's monitor. */
    fun runTransport(fallbackDnsServers: List<String> = emptyList()): Int {
        val current = synchronized(this) { requireHandle() }
        val envelope = org.json.JSONObject()
            .put("fallback_dns_servers", org.json.JSONArray(fallbackDnsServers))
        val bytes = envelope.toString().toByteArray(Charsets.UTF_8)
        return try {
            nativeRunTransport(current, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    @Synchronized
    fun stats(): TransportCoreStats {
        val values = nativeStats(requireHandle())
        check(values.size == 4) { "transport core returned malformed stats" }
        return TransportCoreStats(
            txBytes = values[0],
            rxBytes = values[1],
            txPackets = values[2],
            rxPackets = values[3],
        )
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

    /**
     * Re-parse one authenticated `OK:` response in Rust and synchronously take the emitted
     * generation plan. Holding this monitor across publish+poll prevents the background event
     * pump from consuming the NetworkPlan between those two native calls.
     */
    @Synchronized
    fun publishHandshakeNetwork(
        authOk: String,
        effectiveMtu: Int,
        fallbackDnsServers: List<String> = emptyList(),
    ): TransportCoreNetworkPlan {
        require(authOk.startsWith("OK:")) { "authenticated network input must start with OK:" }
        require(effectiveMtu in 576..65535) { "effective MTU is outside the ABI range" }
        val envelope = org.json.JSONObject()
            .put("auth_ok", authOk)
            .put("effective_mtu", effectiveMtu)
            .put("fallback_dns_servers", org.json.JSONArray(fallbackDnsServers))
        val bytes = envelope.toString().toByteArray(Charsets.UTF_8)
        val generation = try {
            nativePublishHandshakeNetwork(requireHandle(), bytes)
        } finally {
            bytes.fill(0)
        }
        check(generation > 0) {
            "transport core publishHandshakeNetwork failed (rc=$generation)"
        }
        repeat(4) {
            val frame = nativePollEvent(requireHandle())
                ?: error("transport core omitted NetworkPlan generation $generation")
            val event = TransportCoreEventCodec.decode(frame)
            when (event.kind) {
                TransportCoreEventCodec.KIND_STATE_CHANGED -> Unit
                TransportCoreEventCodec.KIND_NETWORK_PLAN -> {
                    val plan = TransportCoreEventCodec.decodeNetworkPlan(event)
                    check(plan.generation == generation) {
                        "transport core emitted generation ${plan.generation}, expected $generation"
                    }
                    return plan
                }
                TransportCoreEventCodec.KIND_ERROR -> error(
                    "transport core rejected NetworkPlan generation $generation"
                )
                else -> error(
                    "unexpected transport core event ${event.kind} while awaiting NetworkPlan"
                )
            }
        }
        error("transport core did not emit NetworkPlan generation $generation")
    }

    @Synchronized
    fun networkPlanResult(generation: Long, applied: Boolean, reason: String? = null) {
        require(generation > 0) { "network plan generation must be positive" }
        val bytes = if (applied) {
            ByteArray(0)
        } else {
            (reason ?: "platform rejected the network plan").take(512).toByteArray(Charsets.UTF_8)
        }
        try {
            requireSuccess(
                nativeNetworkPlanResult(
                    requireHandle(),
                    generation,
                    if (applied) 0 else 1,
                    bytes,
                ),
                "networkPlanResult",
            )
        } finally {
            bytes.fill(0)
        }
    }

    @Synchronized
    fun socketProtectResult(requestSequence: Long, protected: Boolean, reason: String? = null) {
        require(requestSequence > 0) { "socket protect request sequence must be positive" }
        val bytes = if (protected) {
            ByteArray(0)
        } else {
            (reason ?: "platform rejected socket protection")
                .take(512)
                .toByteArray(Charsets.UTF_8)
        }
        try {
            requireSuccess(
                nativeSocketProtectResult(
                    requireHandle(),
                    requestSequence,
                    if (protected) 0 else 1,
                    bytes,
                ),
                "socketProtectResult",
            )
        } finally {
            bytes.fill(0)
        }
    }

    @Synchronized
    fun serverIdentityResult(requestSequence: Long, trusted: Boolean, reason: String? = null) {
        require(requestSequence > 0) { "server identity request sequence must be positive" }
        val bytes = if (trusted) {
            ByteArray(0)
        } else {
            (reason ?: "platform rejected the server identity")
                .take(512)
                .toByteArray(Charsets.UTF_8)
        }
        try {
            requireSuccess(
                nativeServerIdentityResult(
                    requireHandle(),
                    requestSequence,
                    if (trusted) 0 else 1,
                    bytes,
                ),
                "serverIdentityResult",
            )
        } finally {
            bytes.fill(0)
        }
    }

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
        const val PLATFORM_SERVER_IDENTITY = 1L shl 6
        const val PLATFORM_SYSTEM_PLAN =
            PLATFORM_ROUTES or PLATFORM_DNS or PLATFORM_KILL_SWITCH

        const val STATE_CREATED = 0
        const val STATE_CONNECTING = 1

        private const val ABI_VERSION = 0x00010006
        private const val CORE_STRICT_CONFIG = 1L shl 0
        private const val CORE_LIFECYCLE_EVENTS = 1L shl 1
        private const val CORE_NETWORK_PLAN_ACK = 1L shl 2
        private const val CORE_TUN_FD_OWNERSHIP = 1L shl 3
        private const val CORE_SOCKET_PROTECT_ACK = 1L shl 4
        private const val CORE_DEVICE_ID_INPUT = 1L shl 5
        private const val CORE_SERVER_IDENTITY_ACK = 1L shl 6
        private const val CORE_HANDSHAKE_NETWORK_INPUT = 1L shl 7
        private const val CORE_NATIVE_DATA_PLANE = 1L shl 8
        private const val REQUIRED_CORE_CAPABILITIES =
            CORE_STRICT_CONFIG or CORE_LIFECYCLE_EVENTS or CORE_NETWORK_PLAN_ACK or
                CORE_TUN_FD_OWNERSHIP or CORE_SOCKET_PROTECT_ACK or CORE_DEVICE_ID_INPUT or
                CORE_SERVER_IDENTITY_ACK or CORE_HANDSHAKE_NETWORK_INPUT or
                CORE_NATIVE_DATA_PLANE

        init {
            System.loadLibrary("qeli")
        }

        fun create(
            configText: String,
            deviceId: ByteArray,
            platformCapabilities: Long = PLATFORM_SYSTEM_PLAN,
            eventCapacity: Int = 0,
        ): TransportCore {
            require(deviceId.size == 16 && deviceId.any { it != 0.toByte() }) {
                "device id must be 16 non-zero bytes"
            }
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
            try {
                requireSuccess(nativeSetDeviceId(nativeHandle, deviceId), "setDeviceId")
                return TransportCore(nativeHandle)
            } catch (error: Throwable) {
                nativeFree(nativeHandle)
                throw error
            }
        }

        fun abiVersion(): Int = nativeAbiVersion()

        fun coreCapabilities(): Long = nativeCoreCapabilities()

        /**
         * Send the shared Rust UDP ClientHello first flight and return milliseconds to any
         * server reply. This diagnostic does not authenticate, create a core handle or touch
         * TUN. [configText] must be the credential-free probe profile produced by VpnConfig.
         */
        fun udpReachability(configText: String, host: String, timeoutMs: Int = 1500): Long {
            require(timeoutMs in 100..5000) { "UDP probe timeout must be 100..5000 ms" }
            require(host.isNotEmpty() && host.length <= 253 && host.none(Char::isISOControl)) {
                "invalid UDP probe host"
            }
            val config = configText.toByteArray(Charsets.UTF_8)
            val target = host.toByteArray(Charsets.UTF_8)
            return try {
                nativeUdpReachability(config, target, timeoutMs)
            } finally {
                config.fill(0)
                target.fill(0)
            }
        }

        private fun requireSuccess(result: Int, operation: String) {
            check(result == 0) { "transport core $operation failed (rc=$result)" }
        }

        @JvmStatic private external fun nativeAbiVersion(): Int
        @JvmStatic private external fun nativeCoreCapabilities(): Long
        @JvmStatic private external fun nativeUdpReachability(
            config: ByteArray,
            host: ByteArray,
            timeoutMs: Int,
        ): Long
        @JvmStatic private external fun nativeNew(
            config: ByteArray,
            platformCapabilities: Long,
            eventCapacity: Int,
        ): Long
        @JvmStatic private external fun nativeStart(handle: Long): Int
        @JvmStatic private external fun nativeRunTransport(handle: Long, input: ByteArray): Int
        @JvmStatic private external fun nativeStop(handle: Long): Int
        @JvmStatic private external fun nativeSetDeviceId(handle: Long, deviceId: ByteArray): Int
        @JvmStatic private external fun nativeState(handle: Long): Int
        @JvmStatic private external fun nativeStats(handle: Long): LongArray
        @JvmStatic private external fun nativePollEvent(handle: Long): ByteArray?
        @JvmStatic private external fun nativeSetTunFd(handle: Long, generation: Long, fd: Int): Int
        @JvmStatic private external fun nativePublishHandshakeNetwork(
            handle: Long,
            input: ByteArray,
        ): Long
        @JvmStatic private external fun nativeNetworkPlanResult(
            handle: Long,
            generation: Long,
            resultCode: Int,
            reason: ByteArray,
        ): Int
        @JvmStatic private external fun nativeSocketProtectResult(
            handle: Long,
            requestSequence: Long,
            resultCode: Int,
            reason: ByteArray,
        ): Int
        @JvmStatic private external fun nativeServerIdentityResult(
            handle: Long,
            requestSequence: Long,
            resultCode: Int,
            reason: ByteArray,
        ): Int
        @JvmStatic private external fun nativeFree(handle: Long): Int
    }
}

internal data class TransportCoreStats(
    val txBytes: Long,
    val rxBytes: Long,
    val txPackets: Long,
    val rxPackets: Long,
)
