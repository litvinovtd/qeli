package com.qeli

/**
 * ML-KEM-768 (FIPS 203) key encapsulation via JNI
 * (`src/protocol/realtls/jni.rs` → `libqeli.so`). Android has no vetted managed
 * ML-KEM, so the post-quantum half of the qeli handshake calls the same Rust
 * `ml-kem` the server uses — byte-identical, no downgrade risk.
 *
 * The client generates a keypair, embeds [encapsulationKey] in its X25519MLKEM768
 * ClientHello key_share, then [decapsulate]s the server's ciphertext; the resulting
 * shared secret feeds `KeyDerivation.deriveKeysHybrid`. Mirrors the Windows/macOS
 * `MlKem` (P/Invoke) over the same `qeli_mlkem_*` C ABI.
 */
class MlKem private constructor(private var handle: Long, val encapsulationKey: ByteArray) {

    private val lock = Any()

    /** Decapsulate the server's ciphertext (1088 B) into the 32-byte shared secret. */
    fun decapsulate(ciphertext: ByteArray): ByteArray = synchronized(lock) {
        check(handle != 0L) { "MlKem already closed" }
        nativeDecapsulate(handle, ciphertext) ?: error("ML-KEM decapsulation failed")
    }

    /** Free the native decapsulation key. Idempotent. */
    fun close() = synchronized(lock) {
        if (handle != 0L) {
            nativeFree(handle)
            handle = 0L
        }
    }

    companion object {
        init {
            System.loadLibrary("qeli")
        }

        /** A fresh ML-KEM-768 keypair; the decapsulation key is retained natively. */
        fun generate(): MlKem {
            val h = nativeKeygen()
            check(h != 0L) { "ML-KEM keygen failed" }
            val ek = nativeEncapKey(h)
            if (ek == null) {
                nativeFree(h)
                error("ML-KEM encapsulation key unavailable")
            }
            return MlKem(h, ek)
        }

        @JvmStatic
        private external fun nativeKeygen(): Long
        @JvmStatic
        private external fun nativeEncapKey(handle: Long): ByteArray?
        @JvmStatic
        private external fun nativeDecapsulate(handle: Long, ct: ByteArray): ByteArray?
        @JvmStatic
        private external fun nativeFree(handle: Long)
    }
}
