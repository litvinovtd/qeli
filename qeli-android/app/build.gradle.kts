import java.io.FileInputStream
import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    // AGP 9.0+ applies Kotlin itself (built-in Kotlin support).
    id("com.android.application")
}

// Release signing is driven by an untracked keystore.properties at the project
// root (template: keystore.properties.example). When it is absent — CI, a fresh
// clone — release builds are simply left unsigned; debug builds and a bare
// `assembleRelease` still succeed.
val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) FileInputStream(keystorePropsFile).use { load(it) }
}

android {
    namespace = "com.qeli"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.qeli"
        minSdk = 28
        targetSdk = 37
        versionCode = 706
        versionName = "0.7.6"
    }

    signingConfigs {
        if (keystorePropsFile.exists()) {
            create("release") {
                storeFile = file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Sign the release only when a keystore is configured; otherwise the
            // APK is left unsigned (so CI / fresh clones still build).
            if (keystorePropsFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        viewBinding = true
    }
}

// Kotlin 2.x: jvmTarget moved from the (now removed) android.kotlinOptions DSL to
// the Kotlin plugin's compilerOptions DSL.
kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.19.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("com.google.android.material:material:1.14.0")
    implementation("androidx.constraintlayout:constraintlayout:2.2.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    // QR scanning for importing a qeli:// profile via camera.
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    // Encrypted-at-rest profile store (passwords/obfs_key) — master key in the
    // Android Keystore (TEE/StrongBox where available). See docs/RELEASE-FIXES.md E1.
    implementation("androidx.security:security-crypto:1.1.0")
    // Local (JVM) unit tests — e.g. the F3 WebSocket masking wire-vector test that
    // pins byte parity with the Rust/C# obfs framers (ObfsStreamTest).
    testImplementation("junit:junit:4.13.2")
}
