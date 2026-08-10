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
            "tunnel_address":"10.8.0.2",
            "prefix_len":24,
            "mtu":1400,
            "tunnel_gateway":"10.8.0.1",
            "routes":[{"cidr":"10.20.0.0/16","gateway":"10.8.0.1","metric":100}],
            "pushed_routes":["10.20.0.0/16"],
            "dns_servers":[{"address":"10.8.0.1","port":53}],
            "full_tunnel":false,
            "kill_switch":false,
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
            "generation":9,"tunnel_address":"10.8.0.2","prefix_len":24,"mtu":1400,
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
}
