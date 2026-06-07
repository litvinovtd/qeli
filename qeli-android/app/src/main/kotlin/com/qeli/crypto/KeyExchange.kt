package com.qeli.crypto

import android.util.Log
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

class KeyExchange {

    data class KeyPair(
        val privateKey: PrivateKey,
        val publicKey: PublicKey,
        val publicKeyBytes: ByteArray
    )

    fun generateKeyPair(): KeyPair {
        val kp = tryGenerateKeyPair()
        val pub = kp.public
        val encoded: ByteArray = pub.encoded

        val rawBytes: ByteArray = when {
            encoded.size == 44 -> encoded.copyOfRange(12, 44)
            encoded.size > 32  -> encoded.copyOfRange(encoded.size - 32, encoded.size)
            else -> throw IllegalStateException("Unexpected SPKI size: ${encoded.size}")
        }

        if (isWeakKey(rawBytes)) {
            throw IllegalStateException("Generated weak X25519 key (all zeros or order-8 point)")
        }
        return KeyPair(kp.private, pub, rawBytes)
    }

    fun computeSharedSecret(privateKey: PrivateKey, peerPublicKeyRaw: ByteArray): ByteArray {
        if (isWeakKey(peerPublicKeyRaw)) {
            throw IllegalArgumentException("Peer public key is weak (all zeros or order-8 point)")
        }

        val spki = buildX25519Spki(peerPublicKeyRaw)
        val kf = KeyFactory.getInstance("XDH")
        val peerPub: PublicKey = kf.generatePublic(X509EncodedKeySpec(spki))

        val ka = KeyAgreement.getInstance("XDH")
        ka.init(privateKey)
        ka.doPhase(peerPub, true)
        return ka.generateSecret()
    }

    private fun tryGenerateKeyPair(): java.security.KeyPair {
        runCatching {
            val kpg = KeyPairGenerator.getInstance("XDH")
            val spec = Class.forName("java.security.spec.NamedParameterSpec")
                .getConstructor(String::class.java)
                .newInstance("X25519") as java.security.spec.AlgorithmParameterSpec
            kpg.initialize(spec)
            return kpg.genKeyPair().also { Log.d("KeyExchange", "Method 1 (NamedParameterSpec) ok") }
        }

        runCatching {
            val kpg = KeyPairGenerator.getInstance("XDH")
            kpg.initialize(255)
            return kpg.genKeyPair().also { Log.d("KeyExchange", "Method 2 (size 255) ok") }
        }

        runCatching {
            val kpg = KeyPairGenerator.getInstance("X25519")
            return kpg.genKeyPair().also { Log.d("KeyExchange", "Method 3 (X25519 algo) ok") }
        }

        runCatching {
            val kpg = KeyPairGenerator.getInstance("XDH")
            return kpg.genKeyPair().also { Log.d("KeyExchange", "Method 4 (XDH no init) ok") }
        }

        throw RuntimeException("All X25519 key generation methods failed on API ${android.os.Build.VERSION.SDK_INT}")
    }

    private fun isWeakKey(rawKey: ByteArray): Boolean {
        if (rawKey.size != 32) return true
        val allZeros = rawKey.all { it == 0x00.toByte() }
        if (allZeros) return true
        val allOnes = rawKey.all { it == 0xFF.toByte() }
        if (allOnes) return true
        val order8Points = listOf(
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224edda094e000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "1d00000000000000000000000000000000000000000000000000000000000000",
            "5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a0002",
            "6f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224edda094e000",
            "0000000000000000000000000000000000000000000000000000000000000080"
        )
        val hex = rawKey.joinToString("") { "%02x".format(it) }
        return hex in order8Points
    }

    private fun buildX25519Spki(rawKey: ByteArray): ByteArray {
        require(rawKey.size == 32) { "X25519 raw key must be 32 bytes, got ${rawKey.size}" }
        return ByteArray(44).apply {
            this[0] = 0x30; this[1] = 42
            this[2] = 0x30; this[3] = 5
            this[4] = 0x06; this[5] = 3
            this[6] = 0x2b; this[7] = 0x65; this[8] = 0x6e
            this[9] = 0x03; this[10] = 33; this[11] = 0
            System.arraycopy(rawKey, 0, this, 12, 32)
        }
    }
}
