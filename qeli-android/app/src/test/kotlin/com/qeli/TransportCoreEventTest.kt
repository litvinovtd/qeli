package com.qeli

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TransportCoreEventTest {
    private fun frame(
        payload: ByteArray = ByteArray(0),
        declaredLength: Int = payload.size,
        kind: Int = 2,
        sequence: Long = 17,
        planGeneration: Long = 9,
    ): ByteArray {
        return ByteBuffer.allocate(TransportCoreEventCodec.HEADER_SIZE + payload.size)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(TransportCoreEventCodec.HEADER_SIZE)
            .putInt(0x00010002)
            .putInt(kind)
            .putInt(2)
            .putInt(1)
            .putInt(0)
            .putLong(sequence)
            .putLong(planGeneration)
            .putInt(0)
            .putInt(declaredLength)
            .put(payload)
            .array()
    }

    @Test
    fun decodesTheStableLittleEndianHeaderAndPayload() {
        val payload = "{\"generation\":9}".toByteArray()
        val event = TransportCoreEventCodec.decode(frame(payload))

        assertEquals(0x00010002, event.abiVersion)
        assertEquals(2, event.kind)
        assertEquals(2, event.state)
        assertEquals(17L, event.sequence)
        assertEquals(9L, event.planGeneration)
        assertArrayEquals(payload, event.payload)
    }

    @Test
    fun rejectsTruncatedAndLengthMismatchedFrames() {
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decode(ByteArray(47))
        }
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decode(frame(byteArrayOf(1, 2), declaredLength = 3))
        }
    }

    @Test
    fun decodesSocketProtectRequestUsingEventSequenceAsRequestId() {
        val event = TransportCoreEventCodec.decode(
            frame(
                payload = "{\"fd\":42}".toByteArray(),
                kind = TransportCoreEventCodec.KIND_SOCKET_PROTECT,
                sequence = 23,
                planGeneration = 0,
            )
        )

        assertEquals(
            TransportCoreSocketProtectRequest(sequence = 23, fd = 42),
            TransportCoreEventCodec.decodeSocketProtect(event),
        )
    }

    @Test
    fun rejectsSocketProtectRequestWithInvalidCorrelationOrFd() {
        val stale = TransportCoreEventCodec.decode(
            frame(
                payload = "{\"fd\":42}".toByteArray(),
                kind = TransportCoreEventCodec.KIND_SOCKET_PROTECT,
                sequence = 0,
                planGeneration = 0,
            )
        )
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decodeSocketProtect(stale)
        }

        val invalidFd = TransportCoreEventCodec.decode(
            frame(
                payload = "{\"fd\":-1}".toByteArray(),
                kind = TransportCoreEventCodec.KIND_SOCKET_PROTECT,
                sequence = 23,
                planGeneration = 0,
            )
        )
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decodeSocketProtect(invalidFd)
        }
    }

    @Test
    fun decodesProvenServerIdentityUsingEventSequenceAsRequestId() {
        val key = "11".repeat(32)
        val event = TransportCoreEventCodec.decode(
            frame(
                payload = "{\"server_id\":\"vpn.example:443\",\"public_key\":\"$key\"}"
                    .toByteArray(),
                kind = TransportCoreEventCodec.KIND_SERVER_IDENTITY,
                sequence = 31,
                planGeneration = 0,
            )
        )

        assertEquals(
            TransportCoreServerIdentityRequest(31, "vpn.example:443", key),
            TransportCoreEventCodec.decodeServerIdentity(event),
        )
    }

    @Test
    fun rejectsMalformedServerIdentityKey() {
        val event = TransportCoreEventCodec.decode(
            frame(
                payload = "{\"server_id\":\"vpn.example:443\",\"public_key\":\"xyz\"}"
                    .toByteArray(),
                kind = TransportCoreEventCodec.KIND_SERVER_IDENTITY,
                sequence = 31,
                planGeneration = 0,
            )
        )
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decodeServerIdentity(event)
        }
    }

    @Test
    fun decodesCanonicalNetworkPlanAndCorrelatesGeneration() {
        val payload = """{
            "generation":9,
            "family_mode":"ipv4",
            "addresses":[{
                "family":"ipv4","address":"10.8.0.2","prefix_len":24,
                "on_link_prefix_len":24,"gateway":"10.8.0.1"
            }],
            "tunnel_address":"10.8.0.2",
            "prefix_len":24,
            "mtu":1400,
            "tunnel_gateway":"10.8.0.1",
            "routes":[{"cidr":"10.20.0.0/16","gateway":"10.8.0.1","metric":100}],
            "pushed_routes":["10.20.0.0/16"],
            "dns_servers":[{"address":"10.8.0.1","port":53}],
            "full_tunnel":false,
            "kill_switch":false,
            "allow_ipv4_leak":false,
            "allow_ipv6_leak":false,
            "max_streams":4,
            "adaptive":true,
            "data_plane":{
                "padding_enabled":true,"padding_min":8,"padding_max":64,
                "heartbeat_enabled":true,"heartbeat_interval_ms":15000,
                "shaping_enabled":true
            },
            "connection_log":["server push: mtu 1400 ACCEPTED"]
        }""".trimIndent().toByteArray()
        val event = TransportCoreEventCodec.decode(frame(payload))
        val plan = TransportCoreEventCodec.decodeNetworkPlan(event)

        assertEquals(9L, plan.generation)
        assertEquals("ipv4", plan.familyMode)
        assertEquals("10.8.0.2", plan.addresses.single().address)
        assertEquals("10.8.0.2", plan.tunnelAddress)
        assertEquals(24, plan.prefixLength)
        assertEquals(1400, plan.mtu)
        assertEquals("10.20.0.0/16", plan.routes.single().cidr)
        assertEquals(listOf("10.20.0.0/16"), plan.pushedRoutes)
        assertEquals("10.8.0.1", plan.dnsServers.single().address)
        assertEquals(false, plan.fullTunnel)
        assertEquals(4, plan.maxStreams)
        assertEquals(true, plan.adaptive)
        assertEquals(true, plan.dataPlane.paddingEnabled)
        assertEquals(15000L, plan.dataPlane.heartbeatIntervalMs)
        assertEquals(listOf("server push: mtu 1400 ACCEPTED"), plan.connectionLog)
    }

    @Test
    fun decodesDualStackAddressesWithoutCollapsingTheHostPrefixes() {
        val payload = """{
            "generation":9,
            "family_mode":"dual",
            "addresses":[
              {"family":"ipv4","address":"10.8.0.2","prefix_len":32,
               "on_link_prefix_len":24,"gateway":"10.8.0.1"},
              {"family":"ipv6","address":"fd71:e100::2","prefix_len":128,
               "on_link_prefix_len":64,"gateway":"fd71:e100::1"}
            ],
            "tunnel_address":"10.8.0.2","prefix_len":24,"mtu":1280,
            "tunnel_gateway":"10.8.0.1","routes":[],"pushed_routes":[],
            "dns_servers":[{"address":"fd71:e100::1","port":53}],
            "full_tunnel":true,"kill_switch":false,
            "allow_ipv4_leak":false,"allow_ipv6_leak":false
        }""".trimIndent().toByteArray()

        val plan = TransportCoreEventCodec.decodeNetworkPlan(
            TransportCoreEventCodec.decode(frame(payload))
        )

        assertEquals("dual", plan.familyMode)
        assertEquals(listOf("ipv4", "ipv6"), plan.addresses.map { it.family })
        assertEquals(32, plan.addresses[0].prefixLength)
        assertEquals(128, plan.addresses[1].prefixLength)
        assertEquals(64, plan.addresses[1].onLinkPrefixLength)
    }

    @Test
    fun rejectsNetworkPlanWithMismatchedGenerationOrInvalidDnsPort() {
        val mismatched = """{
            "generation":8,"tunnel_address":"10.8.0.2","prefix_len":24,"mtu":1400,
            "tunnel_gateway":"10.8.0.1","routes":[],"dns_servers":[],
            "full_tunnel":true,"kill_switch":false
        }""".trimIndent().toByteArray()
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decodeNetworkPlan(
                TransportCoreEventCodec.decode(frame(mismatched, planGeneration = 9))
            )
        }

        val invalidDns = """{
            "generation":9,"family_mode":"ipv4",
            "addresses":[{"family":"ipv4","address":"10.8.0.2","prefix_len":24,
              "on_link_prefix_len":24,"gateway":"10.8.0.1"}],
            "tunnel_address":"10.8.0.2","prefix_len":24,"mtu":1400,
            "tunnel_gateway":"10.8.0.1","routes":[],
            "dns_servers":[{"address":"1.1.1.1","port":0}],
            "full_tunnel":true,"kill_switch":false
        }""".trimIndent().toByteArray()
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decodeNetworkPlan(
                TransportCoreEventCodec.decode(frame(invalidDns))
            )
        }
    }

    @Test
    fun rejectsNetworkPlanFactsThatCannotBeAppliedByTheActiveFamily() {
        val canonical = """{
            "generation":9,"family_mode":"ipv4",
            "addresses":[{"family":"ipv4","address":"10.8.0.2","prefix_len":32,
              "on_link_prefix_len":24,"gateway":"10.8.0.1"}],
            "tunnel_address":"10.8.0.2","prefix_len":24,"mtu":1400,
            "tunnel_gateway":"10.8.0.1","carrier_address":"192.0.2.10",
            "routes":[{"cidr":"10.20.0.0/16","gateway":"10.8.0.1","metric":100}],
            "pushed_routes":["10.20.0.0/16"],
            "dns_servers":[{"address":"10.8.0.1","port":53}],
            "full_tunnel":false,"kill_switch":false
        }""".trimIndent()

        val invalidPlans = listOf(
            canonical.replace("\"on_link_prefix_len\":24", "\"on_link_prefix_len\":33"),
            canonical.replace("\"mtu\":1400", "\"mtu\":16639"),
            canonical.replace("\"tunnel_gateway\":\"10.8.0.1\"",
                "\"tunnel_gateway\":\"10.8.0.9\""),
            canonical.replace("\"cidr\":\"10.20.0.0/16\"",
                "\"cidr\":\"2001:db8:20::/48\"")
                .replace("\"gateway\":\"10.8.0.1\",\"metric\"",
                    "\"gateway\":\"2001:db8::1\",\"metric\""),
            canonical.replace("\"address\":\"10.8.0.1\",\"port\"",
                "\"address\":\"2001:db8::53\",\"port\""),
            canonical.replace("\"carrier_address\":\"192.0.2.10\"",
                "\"carrier_address\":\"not-an-ip\""),
        )
        invalidPlans.forEach { payload ->
            assertThrows(IllegalArgumentException::class.java) {
                TransportCoreEventCodec.decodeNetworkPlan(
                    TransportCoreEventCodec.decode(frame(payload.toByteArray()))
                )
            }
        }
    }

    @Test
    fun decodesCorrelatedAndroidBindPathCommand() {
        val payload = """{
            "generation":9,
            "candidate_id":77,
            "action":"bind_socket",
            "socket_fd":42,
            "path":{
              "generation":9,"update_id":3,"platform_path_id":"android:123",
              "reason":"network_changed","network_token":"123","interface_index":7,
              "local_addresses":["192.0.2.20"],
              "resolved_addresses":[{"address":"198.51.100.10","ttl_secs":0}],
              "flags":{"default_route_changed":true,"wake":false,
                       "same_network_nat_failure":false}
            }
        }""".trimIndent().toByteArray()
        val event = TransportCoreEventCodec.decode(
            frame(
                payload = payload,
                kind = TransportCoreEventCodec.KIND_PATH_COMMAND,
                sequence = 41,
                planGeneration = 9,
            )
        )

        assertEquals(
            TransportCorePathCommand(
                sequence = 41,
                generation = 9,
                candidateId = 77,
                action = "bind_socket",
                socketFd = 42,
                path = TransportCorePathRef("android:123", "123", 7),
            ),
            TransportCoreEventCodec.decodePathCommand(event),
        )
    }

    @Test
    fun rejectsPathCommandWithWrongGenerationOrFdPhase() {
        val canonical = """{
            "generation":9,"candidate_id":77,"action":"prepare_path","socket_fd":42,
            "path":{"generation":9,"platform_path_id":"android:123",
                    "network_token":"123"}
        }""".trimIndent()
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decodePathCommand(
                TransportCoreEventCodec.decode(
                    frame(
                        payload = canonical.toByteArray(),
                        kind = TransportCoreEventCodec.KIND_PATH_COMMAND,
                        planGeneration = 9,
                    )
                )
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decodePathCommand(
                TransportCoreEventCodec.decode(
                    frame(
                        payload = canonical
                            .replace("prepare_path", "bind_socket")
                            .replace("\"generation\":9", "\"generation\":8")
                            .toByteArray(),
                        kind = TransportCoreEventCodec.KIND_PATH_COMMAND,
                        planGeneration = 9,
                    )
                )
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            TransportCoreEventCodec.decodePathCommand(
                TransportCoreEventCodec.decode(
                    frame(
                        payload = canonical
                            .replace("\"socket_fd\":42", "\"socket_fd\":null")
                            .replace("\"network_token\":\"123\"", "\"network_token\":null")
                            .toByteArray(),
                        kind = TransportCoreEventCodec.KIND_PATH_COMMAND,
                        planGeneration = 9,
                    )
                )
            )
        }
    }

    @Test
    fun encodesGenerationScopedWakePathUpdate() {
        val payload = org.json.JSONObject(
            TransportCoreEventCodec.encodePathUpdate(
                generation = 12,
                updateId = 4,
                platformPathId = "android:456",
                reason = "wake",
                networkToken = "456",
                interfaceIndex = 9,
                localAddresses = listOf("192.0.2.30", "2001:db8::30"),
                resolvedAddresses = listOf("198.51.100.20", "2001:db8::20"),
            )
        )

        assertEquals(12L, payload.getLong("generation"))
        assertEquals(4L, payload.getLong("update_id"))
        assertEquals("456", payload.getString("network_token"))
        assertEquals(2, payload.getJSONArray("local_addresses").length())
        assertEquals(0, payload.getJSONArray("resolved_addresses")
            .getJSONObject(0).getInt("ttl_secs"))
        assertEquals(true, payload.getJSONObject("flags").getBoolean("wake"))
        assertEquals(false, payload.getJSONObject("flags")
            .getBoolean("default_route_changed"))
    }

}
