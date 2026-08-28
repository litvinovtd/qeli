package com.qeli

import com.qeli.model.VpnConfig
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import org.json.JSONArray
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

internal data class TransportCorePathRef(
    val platformPathId: String,
    val networkToken: String,
    val interfaceIndex: Int?,
)

internal data class TransportCorePathCommand(
    val sequence: Long,
    val generation: Long,
    val candidateId: Long,
    val action: String,
    val socketFd: Int?,
    val path: TransportCorePathRef,
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

internal data class TransportCoreNetworkAddress(
    val family: String,
    val address: String,
    val prefixLength: Int,
    val onLinkPrefixLength: Int,
    val gateway: String?,
)

internal data class TransportCoreDataPlaneFacts(
    val paddingEnabled: Boolean = false,
    val paddingMin: Int = 0,
    val paddingMax: Int = 0,
    val heartbeatEnabled: Boolean = false,
    val heartbeatIntervalMs: Long = 0,
    val shapingEnabled: Boolean = false,
)

internal data class TransportCoreNetworkPlan(
    val generation: Long,
    val familyMode: String,
    val addresses: List<TransportCoreNetworkAddress>,
    val tunnelAddress: String,
    val prefixLength: Int,
    val mtu: Int,
    val tunnelGateway: String,
    val routes: List<TransportCoreNetworkRoute>,
    val pushedRoutes: List<String>,
    val dnsServers: List<TransportCoreNetworkDns>,
    val fullTunnel: Boolean,
    val killSwitch: Boolean,
    val allowIpv4Leak: Boolean,
    val allowIpv6Leak: Boolean,
    val maxStreams: Int,
    val adaptive: Boolean,
    val dataPlane: TransportCoreDataPlaneFacts,
    val connectionLog: List<String>,
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
    const val KIND_PATH_COMMAND = 6
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

    fun decodePathCommand(event: TransportCoreEvent): TransportCorePathCommand {
        require(event.kind == KIND_PATH_COMMAND) { "event is not a path command" }
        require(event.payloadFormat == PAYLOAD_JSON) { "path command payload is not JSON" }
        require(event.sequence > 0 && event.planGeneration > 0) {
            "path command correlation values must be positive"
        }
        require(event.errorCode == 0) { "path command has an error code" }
        val payload = JSONObject(event.payload.toString(Charsets.UTF_8))
        val generation = payload.getLong("generation")
        val candidateId = payload.getLong("candidate_id")
        require(generation == event.planGeneration && candidateId > 0) {
            "path command correlation mismatch"
        }
        val action = payload.getString("action")
        require(action in setOf("prepare_path", "bind_socket", "commit_path", "abort_path")) {
            "invalid path command action"
        }
        val socketFd = if (payload.isNull("socket_fd")) null else {
            payload.getLong("socket_fd").also { fd ->
                require(fd in 0..Int.MAX_VALUE.toLong()) { "path command fd is outside Int range" }
            }.toInt()
        }
        require((action == "bind_socket") == (socketFd != null)) {
            "only BIND_SOCKET may carry a socket fd"
        }
        val path = payload.getJSONObject("path")
        require(path.getLong("generation") == generation) {
            "path command embeds a different generation"
        }
        val platformPathId = path.getString("platform_path_id")
        require(!path.isNull("network_token")) { "Android path has no network token" }
        val networkToken = path.getString("network_token")
        require(platformPathId.isNotBlank() && platformPathId.length <= 256 &&
            platformPathId.none(Char::isISOControl)) { "invalid platform path id" }
        require(networkToken.isNotBlank() && networkToken.length <= 256 &&
            networkToken.none(Char::isISOControl)) { "Android path has no network token" }
        val interfaceIndex = if (path.isNull("interface_index")) null else {
            path.getLong("interface_index").also { index ->
                require(index in 1..Int.MAX_VALUE.toLong()) { "invalid path interface index" }
            }.toInt()
        }
        return TransportCorePathCommand(
            sequence = event.sequence,
            generation = generation,
            candidateId = candidateId,
            action = action,
            socketFd = socketFd,
            path = TransportCorePathRef(platformPathId, networkToken, interfaceIndex),
        )
    }

    fun encodePathUpdate(
        generation: Long,
        updateId: Long,
        platformPathId: String,
        reason: String,
        networkToken: String,
        interfaceIndex: Int?,
        localAddresses: List<String>,
        resolvedAddresses: List<String>,
    ): String {
        require(generation > 0 && updateId > 0) { "path update ids must be positive" }
        require(reason in setOf("network_changed", "wake")) { "unsupported path reason" }
        require(platformPathId.isNotBlank() && platformPathId.length <= 256 &&
            platformPathId.none(Char::isISOControl)) { "invalid platform path id" }
        require(networkToken.isNotBlank() && networkToken.length <= 256 &&
            networkToken.none(Char::isISOControl)) { "invalid Android network token" }
        require(interfaceIndex == null || interfaceIndex > 0) { "invalid interface index" }
        require(localAddresses.isNotEmpty() && localAddresses.size <= 16) {
            "path update requires 1..16 local addresses"
        }
        require(resolvedAddresses.isNotEmpty() && resolvedAddresses.size <= 16) {
            "path update requires 1..16 resolved addresses"
        }
        localAddresses.forEach(::parseIpLiteral)
        resolvedAddresses.forEach(::parseIpLiteral)
        val flags = JSONObject()
            .put("default_route_changed", reason == "network_changed")
            .put("wake", reason == "wake")
            .put("same_network_nat_failure", false)
        val payload = JSONObject()
            .put("generation", generation)
            .put("update_id", updateId)
            .put("platform_path_id", platformPathId)
            .put("reason", reason)
            .put("network_token", networkToken)
            .put("local_addresses", JSONArray(localAddresses))
            .put("resolved_addresses", JSONArray().apply {
                resolvedAddresses.forEach { address ->
                    put(JSONObject().put("address", address).put("ttl_secs", 0))
                }
            })
            .put("flags", flags)
        if (interfaceIndex != null) payload.put("interface_index", interfaceIndex)
        return payload.toString()
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
        val familyMode = payload.getString("family_mode")
        require(familyMode in setOf("ipv4", "dual", "ipv6")) {
            "invalid network plan family mode"
        }
        val addressJson = payload.getJSONArray("addresses")
        require(addressJson.length() in 1..2) {
            "network plan must contain one address per active family"
        }
        val addresses = ArrayList<TransportCoreNetworkAddress>(addressJson.length())
        val addressFamilies = HashSet<String>()
        for (index in 0 until addressJson.length()) {
            val item = addressJson.getJSONObject(index)
            val family = item.getString("family")
            require(family == "ipv4" || family == "ipv6") {
                "invalid network plan address family"
            }
            require(addressFamilies.add(family)) {
                "network plan contains duplicate address family"
            }
            val address = item.getString("address")
            val parsed = parseIpLiteral(address)
            require((family == "ipv4" && parsed is Inet4Address) ||
                (family == "ipv6" && parsed is Inet6Address)) {
                "network plan address does not match its family"
            }
            require(parsed !is Inet6Address || isUsableTunnelIpv6(parsed)) {
                "network plan contains an unusable IPv6 tunnel address"
            }
            val prefix = item.getInt("prefix_len")
            val onLinkPrefix = item.getInt("on_link_prefix_len")
            val maxPrefix = if (family == "ipv4") 32 else 128
            require(prefix in 1..maxPrefix && onLinkPrefix in 1..prefix) {
                "invalid network plan address prefix"
            }
            val gateway = if (item.isNull("gateway")) null else item.getString("gateway")
            if (gateway != null) {
                val parsedGateway = parseIpLiteral(gateway)
                require((family == "ipv4" && parsedGateway is Inet4Address) ||
                    (family == "ipv6" && parsedGateway is Inet6Address &&
                        isUsableTunnelIpv6(parsedGateway))) {
                    "network plan gateway does not match its family"
                }
            }
            addresses += TransportCoreNetworkAddress(
                family, address, prefix, onLinkPrefix, gateway,
            )
        }
        require(
            when (familyMode) {
                "ipv4" -> addressFamilies == setOf("ipv4")
                "ipv6" -> addressFamilies == setOf("ipv6")
                else -> addressFamilies == setOf("ipv4", "ipv6")
            }
        ) { "network plan addresses do not match its family mode" }
        val tunnelAddress = payload.getString("tunnel_address")
        val prefixLength = payload.getInt("prefix_len")
        val mtu = payload.getInt("mtu")
        val tunnelGateway = payload.getString("tunnel_gateway")
        require(tunnelAddress.isNotBlank() && tunnelAddress.length <= 128) {
            "invalid network plan tunnel address"
        }
        val projectedAddress = addresses.singleOrNull { it.address == tunnelAddress }
            ?: throw IllegalArgumentException(
                "legacy network plan address is not present in typed addresses")
        val parsedTunnelGateway = parseIpLiteral(tunnelGateway)
        require(prefixLength == projectedAddress.onLinkPrefixLength &&
            tunnelGateway == projectedAddress.gateway &&
            ((projectedAddress.family == "ipv4" && parsedTunnelGateway is Inet4Address) ||
                (projectedAddress.family == "ipv6" && parsedTunnelGateway is Inet6Address &&
                    isUsableTunnelIpv6(parsedTunnelGateway)))) {
            "legacy network plan projection does not match typed address"
        }
        require(mtu in VpnConfig.MTU_MIN..VpnConfig.MTU_MAX) { "invalid network plan MTU" }
        require("ipv6" !in addressFamilies || mtu >= 1280) {
            "IPv6 network plan MTU is below 1280"
        }
        payload.optString("carrier_address").takeIf { it.isNotBlank() }?.let(::parseIpLiteral)

        val routeJson = payload.getJSONArray("routes")
        require(routeJson.length() <= 256) { "network plan contains too many routes" }
        val routes = ArrayList<TransportCoreNetworkRoute>(routeJson.length())
        for (index in 0 until routeJson.length()) {
            val route = routeJson.getJSONObject(index)
            val cidr = route.getString("cidr")
            val gateway = route.getString("gateway")
            val metric = route.getLong("metric")
            val (destination, _) = parseCidr(cidr)
            val parsedGateway = parseIpLiteral(gateway)
            require((destination is Inet4Address) == (parsedGateway is Inet4Address) &&
                (parsedGateway !is Inet6Address || isUsableTunnelIpv6(parsedGateway)) &&
                (destination is Inet4Address && "ipv4" in addressFamilies ||
                    destination is Inet6Address && "ipv6" in addressFamilies)) {
                "network plan route/gateway uses an invalid or inactive family"
            }
            require(metric in 0..0xffff_ffffL) { "invalid network plan route metric" }
            routes += TransportCoreNetworkRoute(cidr, gateway, metric)
        }

        val pushedRouteJson = payload.optJSONArray("pushed_routes")
        require(pushedRouteJson == null || pushedRouteJson.length() <= 256) {
            "network plan contains too many pushed routes"
        }
        val pushedRoutes = ArrayList<String>(pushedRouteJson?.length() ?: 0)
        if (pushedRouteJson != null) {
            for (index in 0 until pushedRouteJson.length()) {
                val cidr = pushedRouteJson.getString(index)
                parseCidr(cidr)
                pushedRoutes += cidr
            }
        }

        val dnsJson = payload.getJSONArray("dns_servers")
        require(dnsJson.length() <= 8) { "network plan contains too many DNS servers" }
        val dnsServers = ArrayList<TransportCoreNetworkDns>(dnsJson.length())
        for (index in 0 until dnsJson.length()) {
            val dns = dnsJson.getJSONObject(index)
            val address = dns.getString("address")
            val port = dns.getInt("port")
            val parsedAddress = parseIpLiteral(address)
            require(parsedAddress is Inet4Address && "ipv4" in addressFamilies ||
                parsedAddress is Inet6Address && "ipv6" in addressFamilies) {
                "network plan DNS uses an inactive family"
            }
            require(port in 1..65535) { "invalid network plan DNS port" }
            dnsServers += TransportCoreNetworkDns(address, port)
        }

        val dataPlaneJson = payload.optJSONObject("data_plane")
        val dataPlane = TransportCoreDataPlaneFacts(
            paddingEnabled = dataPlaneJson?.optBoolean("padding_enabled", false) ?: false,
            paddingMin = dataPlaneJson?.optInt("padding_min", 0) ?: 0,
            paddingMax = dataPlaneJson?.optInt("padding_max", 0) ?: 0,
            heartbeatEnabled = dataPlaneJson?.optBoolean("heartbeat_enabled", false) ?: false,
            heartbeatIntervalMs = dataPlaneJson?.optLong("heartbeat_interval_ms", 0) ?: 0,
            shapingEnabled = dataPlaneJson?.optBoolean("shaping_enabled", false) ?: false,
        )

        val connectionLogJson = payload.optJSONArray("connection_log")
        require(connectionLogJson == null || connectionLogJson.length() <= 280) {
            "network plan connection log is too large"
        }
        val connectionLog = ArrayList<String>(connectionLogJson?.length() ?: 0)
        if (connectionLogJson != null) {
            for (index in 0 until connectionLogJson.length()) {
                val line = connectionLogJson.getString(index)
                require(line.length <= 1024 && line.none { it.isISOControl() }) {
                    "invalid network plan connection log line"
                }
                connectionLog += line
            }
        }

        return TransportCoreNetworkPlan(
            generation = generation,
            familyMode = familyMode,
            addresses = addresses,
            tunnelAddress = tunnelAddress,
            prefixLength = prefixLength,
            mtu = mtu,
            tunnelGateway = tunnelGateway,
            routes = routes,
            pushedRoutes = pushedRoutes,
            dnsServers = dnsServers,
            fullTunnel = payload.getBoolean("full_tunnel"),
            killSwitch = payload.getBoolean("kill_switch"),
            allowIpv4Leak = payload.optBoolean("allow_ipv4_leak", false),
            allowIpv6Leak = payload.optBoolean("allow_ipv6_leak", false),
            maxStreams = payload.optInt("max_streams", 1).coerceIn(1, 64),
            adaptive = payload.optBoolean("adaptive", false),
            dataPlane = dataPlane,
            connectionLog = connectionLog,
        )
    }

    private fun parseIpLiteral(value: String): InetAddress {
        require(value.isNotBlank() && value.length <= 128 && '%' !in value) {
            "invalid IP literal"
        }
        val looksIpv4 = '.' in value && ':' !in value && value.all { it.isDigit() || it == '.' }
        val looksIpv6 = ':' in value
        require(looksIpv4 || looksIpv6) { "address is not an IP literal" }
        if (looksIpv4) {
            val octets = value.split('.')
            require(octets.size == 4 && octets.all { octet ->
                val parsed = octet.toIntOrNull()
                parsed != null && parsed in 0..255 && parsed.toString() == octet
            }) { "address is not a canonical IPv4 literal" }
        }
        val parsed = InetAddress.getByName(value)
        require((looksIpv4 && parsed is Inet4Address) || (looksIpv6 && parsed is Inet6Address)) {
            "address is not an IP literal"
        }
        return parsed
    }

    private fun parseCidr(value: String): Pair<InetAddress, Int> {
        require(value.isNotBlank() && value.length <= 128) { "invalid IP CIDR" }
        val separator = value.indexOf('/')
        require(separator > 0 && separator == value.lastIndexOf('/') && separator < value.lastIndex) {
            "invalid IP CIDR"
        }
        val address = parseIpLiteral(value.substring(0, separator))
        val prefix = value.substring(separator + 1).toIntOrNull()
            ?: throw IllegalArgumentException("invalid IP CIDR")
        require(prefix in 0..if (address is Inet4Address) 32 else 128) { "invalid IP CIDR" }
        return address to prefix
    }

    private fun isUsableTunnelIpv6(address: Inet6Address): Boolean =
        !address.isAnyLocalAddress && !address.isLoopbackAddress &&
            !address.isMulticastAddress && !address.isLinkLocalAddress
}
