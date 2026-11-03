package com.qeli

/** Limits shared by the Activity, encrypted store, service and portable backup container. */
internal object ProfileLimits {
    const val MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
    const val MAX_BACKUP_BYTES = 12 * 1024 * 1024
    const val MAX_PROFILES = 256
}
