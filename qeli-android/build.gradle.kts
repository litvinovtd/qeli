plugins {
    // AGP 9.0+ has built-in Kotlin support, so the org.jetbrains.kotlin.android
    // plugin is no longer applied (see https://kotl.in/gradle/agp-built-in-kotlin).
    id("com.android.application") version "9.3.0" apply false
}
