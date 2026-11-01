package com.qeli

import java.io.IOException
import org.junit.Assert.*
import org.junit.Test

class IcmpEchoTest {
    private val nonce = ByteArray(IcmpEcho.NONCE_SIZE) { it.toByte() }
    private fun reply(request: ByteArray, ipv6: Boolean = false): ByteArray = request.copyOf().also {
        it[0] = (if (ipv6) 129 else 0).toByte(); it[2] = 0; it[3] = 0
        it[4] = 0x12; it[5] = 0x34 // Kernel ping sockets can rewrite the identifier.
        if (!ipv6) {val sum=IcmpEcho.checksum(it);it[2]=(sum ushr 8).toByte();it[3]=sum.toByte()}
    }
    @Test fun ipv4RequestHasValidHeaderChecksumAndRandomCorrelationPayload() {
        val request = IcmpEcho.request(false, 0x1234, nonce)
        assertEquals(24, request.size); assertEquals(8, request[0].toInt()); assertEquals(0, IcmpEcho.checksum(request))
        assertEquals(0x12, request[6].toInt()); assertEquals(0x34, request[7].toInt())
        assertArrayEquals(nonce, request.copyOfRange(8, request.size))
        assertTrue(IcmpEcho.matches(reply(request), request, false))
    }
    @Test fun ipv6UsesItsOwnEchoTypesAndKernelChecksum() {
        val request = IcmpEcho.request(true, 65535, nonce)
        assertEquals(128, request[0].toInt() and 255); assertEquals(0, request[2].toInt())
        assertTrue(IcmpEcho.matches(reply(request, true), request, true))
        assertFalse(IcmpEcho.matches(reply(request, true), request, false))
        assertFalse(IcmpEcho.matches(reply(request, true).also {it[8]=42},request,true))
    }
    @Test fun wrongNonceSequenceCodeTypeLengthOrChecksumCannotBecomeAnRtt() {
        val request = IcmpEcho.request(false, 1, nonce)
        for (index in listOf(0, 1, 2, 6, 7, 8, 23)) {
            val changed = reply(request).also { it[index] = (it[index].toInt() xor 1).toByte() }
            assertFalse("byte $index", IcmpEcho.matches(changed, request, false))
        }
        assertFalse(IcmpEcho.matches(reply(request).copyOf(23), request, false))
        assertFalse(IcmpEcho.matches(reply(request).copyOf(25), request, false))
        val oldRequest = IcmpEcho.request(false, 1, nonce.copyOf().also { it[0]=42 })
        assertFalse(IcmpEcho.matches(reply(oldRequest), request, false))
    }
    private class Socket(val answer: (Int) -> ByteArray?) : IcmpExchange.Socket {
        var closed = 0;var sent = 0;var maxWait = 0
        override fun send(packet: ByteArray) {sent++}
        override fun receive(timeoutMs: Int): ByteArray? {maxWait=maxOf(maxWait,timeoutMs);return answer(timeoutMs)}
        override fun close() {closed++}
    }
    @Test fun monotonicRttIgnoresUnrelatedResponsesAndClosesTheSocket() {
        val request = IcmpEcho.request(false, 10, nonce);var now=0L;var receives=0
        val socket=Socket { now+=20_000_000; if(receives++==0) ByteArray(24) else reply(request) }
        assertEquals(40, IcmpExchange.run(socket,request,false,{now},{false}))
        assertEquals(1,socket.sent);assertEquals(1,socket.closed);assertTrue(socket.maxWait<=250)
    }
    @Test fun overallDeadlineCannotBeExtendedByMalformedPackets() {
        val request=IcmpEcho.request(false,10,nonce);var now=0L
        val socket=Socket { now+=250_000_000;ByteArray(24) }
        assertEquals(-1,IcmpExchange.run(socket,request,false,{now},{false},500))
        assertEquals(500_000_000,now);assertEquals(1,socket.closed)
    }
    @Test fun replyAfterDeadlineDoesNotCreateASuccess() {
        val request=IcmpEcho.request(false,10,nonce);var now=0L
        val socket=Socket { now=3_000_000_000;reply(request) }
        assertEquals(-1,IcmpExchange.run(socket,request,false,{now},{false}))
        assertEquals(1,socket.closed)
    }
    @Test fun cancellationBeforeSendAndDuringReceiveClosesWithoutPublishingSuccess() {
        val request=IcmpEcho.request(false,10,nonce)
        val before=Socket {throw AssertionError("receive after cancellation")}
        assertEquals(-1,IcmpExchange.run(before,request,false,{0},{true}))
        assertEquals(0,before.sent);assertEquals(1,before.closed)
        var cancelled=false
        val during=Socket {cancelled=true;reply(request)}
        assertEquals(-1,IcmpExchange.run(during,request,false,{0},{cancelled}))
        assertEquals(1,during.closed)
    }
    @Test fun socketFailureStillClosesOwnership() {
        val request=IcmpEcho.request(false,10,nonce)
        val socket=Socket {throw IOException("mock OS denied echo")}
        assertThrows(IOException::class.java) {IcmpExchange.run(socket,request,false,{0},{false})}
        assertEquals(1,socket.closed)
    }
}
