package com.qeli

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.json.JSONObject

/** Stable Android view of one shared-core control-plane event. */
internal data class TransportCoreEvent(
    val abiVersion: Int,
    val kind: Int,
    val state: Int,
    val payloadFormat: Int,
    val sequence: Long,
    val planGeneration: Long,
    val errorCode: Int,
    val payload: ByteArray,
)

internal data class TransportCoreSocketProtectRequest(
    val sequence: Long,
    val fd: Int,
)

internal data class TransportCoreServerIdentityRequest(
    val sequence: Long,
    val serverId: String,
    val publicKey: String,
)

internal data class TransportCoreNetworkRoute(
    val cidr: String,
    val gateway: String,
    val metric: Long,
)

internal data class TransportCoreNetworkDns(
    val address: String,
    val port: Int,
)

internal data class TransportCoreNetworkPlan(
    val generation: Long,
    val tunnelAddress: String,
    val prefixLength: Int,
    val mtu: Int,
    val tunnelGateway: String,
    val routes: List<TransportCoreNetworkRoute>,
    val dnsServers: List<TransportCoreNetworkDns>,
    val fullTunnel: Boolean,
    val killSwitch: Boolean,
    val maxStreams: Int,
    val adaptive: Boolean,
)

/** Decoder for the JNI event frame. Kept separate from [TransportCore] so JVM tests do not
 * load the Android native library merely to validate framing. */
internal object TransportCoreEventCodec {
    const val HEADER_SIZE = 48
    const val KIND_STATE_CHANGED = 1
    const val KIND_NETWORK_PLAN = 2
    const val KIND_ERROR = 3
    const val KIND_SOCKET_PROTECT = 4
    const val KIND_SERVER_IDENTITY = 5
    const val PAYLOAD_JSON = 1
    const val PAYLOAD_UTF8 = 2

    fun decode(frame: ByteArray): TransportCoreEvent {
        require(frame.size >= HEADER_SIZE) { "transport core event header is truncated" }
        val input = ByteBuffer.wrap(frame).order(ByteOrder.LITTLE_ENDIAN)
        val structSize = input.int
        require(structSize == HEADER_SIZE) { "unsupported transport core event header $structSize" }
        val abiVersion = input.int
        require(abiVersion ushr 16 == 1) { "unsupported transport core ABI 0x${abiVersion.toUInt().toString(16)}" }
        val kind = input.int
        val state = input.int
        val payloadFormat = input.int
        val reserved = input.int
        require(reserved == 0) { "transport core event reserved field is non-zero" }
        val sequence = input.long
        val planGeneration = input.long
        val errorCode = input.int
        val payloadLength = Integer.toUnsignedLong(input.int)
        require(payloadLength == input.remaining().toLong()) {
            "transport core event payload length mismatch"
        }
        val payload = ByteArray(payloadLength.toInt())
        input.get(payload)
        return TransportCoreEvent(
            abiVersion = abiVersion,
            kind = kind,
            state = state,
            payloadFormat = payloadFormat,
            sequence = sequence,
            planGeneration = planGeneration,
            errorCode = errorCode,
            payload = payload,
        )
    }

    fun decodeSocketProtect(event: TransportCoreEvent): TransportCoreSocketProtectRequest {
        require(event.kind == KIND_SOCKET_PROTECT) { "event is not a socket protect request" }
        require(event.payloadFormat == PAYLOAD_JSON) { "socket protect payload is not JSON" }
        require(event.sequence > 0) { "socket protect request sequence must be positive" }
        require(event.planGeneration == 0L) { "socket protect request has a plan generation" }
        require(event.errorCode == 0) { "socket protect request has an error code" }
        val fd = JSONObject(event.payload.toString(Charsets.UTF_8)).getLong("fd")
        require(fd in 0..Int.MAX_VALUE.toLong()) { "socket protect fd is outside Int range" }
        return TransportCoreSocketProtectRequest(event.sequence, fd.toInt())
    }

    fun decodeServerIdentity(event: TransportCoreEvent): TransportCoreServerIdentityRequest {
        require(event.kind == KIND_SERVER_IDENTITY) { "event is not a server identity request" }
        require(event.payloadFormat == PAYLOAD_JSON) { "server identity payload is not JSON" }
        require(event.sequence > 0) { "server identity request sequence must be positive" }
        require(event.planGeneration == 0L) { "server identity request has a plan generation" }
        require(event.errorCode == 0) { "server identity request has an error code" }
        val payload = JSONObject(event.payload.toString(Charsets.UTF_8))
        val serverId = payload.getString("server_id")
        val publicKey = payload.getString("public_key").lowercase()
        require(serverId.isNotBlank() && serverId.length <= 320) { "invalid server identity id" }
        require(publicKey.matches(Regex("[0-9a-f]{64}"))) { "invalid server identity public key" }
        return TransportCoreServerIdentityRequest(event.sequence, serverId, publicKey)
    }

    fun decodeNetworkPlan(event: TransportCoreEvent): TransportCoreNetworkPlan {
        require(event.kind == KIND_NETWORK_PLAN) { "event is not a network plan" }
        require(event.payloadFormat == PAYLOAD_JSON) { "network plan payload is not JSON" }
        require(event.sequence > 0) { "network plan event sequence must be positive" }
        require(event.planGeneration > 0) { "network plan generation must be positive" }
        require(event.errorCode == 0) { "network plan has an error code" }
        val payload = JSONObject(event.payload.toString(Charsets.UTF_8))
        val generation = payload.getLong("generation")
        require(generation == event.planGeneration) { "network plan generation mismatch" }
        val tunnelAddress = payload.getString("tunnel_address")
        val prefixLength = payload.getInt("prefix_len")
        val mtu = payload.getInt("mtu")
        val tunnelGateway = payload.getString("tunnel_gateway")
        require(tunnelAddress.isNotBlank() && tunnelAddress.length <= 128) {
            "invalid network plan tunnel address"
        }
        require(prefixLength in 0..128) { "invalid network plan prefix" }
        require(mtu in 576..65535) { "invalid network plan MTU" }
        require(tunnelGateway.isNotBlank() && tunnelGateway.length <= 128) {
            "invalid network plan gateway"
        }

        val routeJson = payload.getJSONArray("routes")
        require(routeJson.length() <= 256) { "network plan contains too many routes" }
        val routes = ArrayList<TransportCoreNetworkRoute>(routeJson.length())
        for (index in 0 until routeJson.length()) {
            val route = routeJson.getJSONObject(index)
            val cidr = route.getString("cidr")
            val gateway = route.getString("gateway")
            val metric = route.getLong("metric")
            require(cidr.isNotBlank() && cidr.length <= 128) { "invalid network plan route" }
            require(gateway.isNotBlank() && gateway.length <= 128) {
                "invalid network plan route gateway"
            }
            require(metric in 0..0xffff_ffffL) { "invalid network plan route metric" }
            routes += TransportCoreNetworkRoute(cidr, gateway, metric)
        }

        val dnsJson = payload.getJSONArray("dns_servers")
        require(dnsJson.length() <= 8) { "network plan contains too many DNS servers" }
        val dnsServers = ArrayList<TransportCoreNetworkDns>(dnsJson.length())
        for (index in 0 until dnsJson.length()) {
            val dns = dnsJson.getJSONObject(index)
            val address = dns.getString("address")
            val port = dns.getInt("port")
            require(address.isNotBlank() && address.length <= 128) {
                "invalid network plan DNS address"
            }
            require(port in 1..65535) { "invalid network plan DNS port" }
            dnsServers += TransportCoreNetworkDns(address, port)
        }

        return TransportCoreNetworkPlan(
            generation = generation,
            tunnelAddress = tunnelAddress,
            prefixLength = prefixLength,
            mtu = mtu,
            tunnelGateway = tunnelGateway,
            routes = routes,
            dnsServers = dnsServers,
            fullTunnel = payload.getBoolean("full_tunnel"),
            killSwitch = payload.getBoolean("kill_switch"),
            maxStreams = payload.optInt("max_streams", 1).coerceIn(1, 64),
            adaptive = payload.optBoolean("adaptive", false),
        )
    }
}
