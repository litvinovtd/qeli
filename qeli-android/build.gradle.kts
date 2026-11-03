// AGP supports upgrading its built-in Kotlin by adding the newer KGP to this
// classpath. Security pins must also apply here, before plugin resolution.
buildscript {
    val securityVersions = java.util.Properties().apply {
        file("gradle/security-versions.properties").inputStream().use { load(it) }
    }
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:" +
            securityVersions.getProperty("org.jetbrains.kotlin/kotlin-gradle-plugin"))
    }
    configurations.classpath {
        resolutionStrategy.activateDependencyLocking()
        resolutionStrategy.eachDependency {
            securityVersions.getProperty("${requested.group}/${requested.name}")?.let {
                useVersion(it)
                because("Pinned security fixes for Android build dependencies")
            }
        }
    }
}

plugins {
    // AGP 9.0+ applies Kotlin itself; do not apply org.jetbrains.kotlin.android.
    id("com.android.application") version "9.2.1" apply false
}

val securityVersions = java.util.Properties().apply {
    file("gradle/security-versions.properties").inputStream().use { load(it) }
}

// Updating locks is an explicit maintenance operation, never a normal build.
allprojects {
    dependencyLocking {
        lockAllConfigurations()
        lockMode = LockMode.STRICT
    }
    configurations.configureEach {
        resolutionStrategy.eachDependency {
            securityVersions.getProperty("${requested.group}/${requested.name}")?.let {
                useVersion(it)
                because("Pinned security fixes for Android build dependencies")
            }
        }
    }
}
