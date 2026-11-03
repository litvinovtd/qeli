package com.qeli

import com.qeli.crypto.BackupCrypto
import java.io.OutputStream

/** Complete one explicit archive export. A null, failed or unclosed sink is never success. */
internal object BackupExporter {
    fun write(archive: String, passphrase: String, openSink: () -> OutputStream?) {
        val bytes = if (passphrase.isEmpty()) archive.toByteArray(Charsets.UTF_8)
            else BackupCrypto.encrypt(archive, passphrase)
        try {
            val limit = if (passphrase.isEmpty()) ProfileLimits.MAX_ARCHIVE_BYTES
                else ProfileLimits.MAX_BACKUP_BYTES
            require(bytes.size <= limit) { "backup exceeds the supported export limit" }
            val output = checkNotNull(openSink()) { "Cannot open backup destination" }
            output.use { it.write(bytes) }
        } finally {
            bytes.fill(0)
        }
    }
}
