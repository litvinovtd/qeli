import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
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
    compileSdk = 35

    defaultConfig {
        applicationId = "com.qeli"
        minSdk = 28
        targetSdk = 35
        versionCode = 506
        versionName = "0.5.6"
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

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.14.0")
    implementation("androidx.constraintlayout:constraintlayout:2.2.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    // QR scanning for importing a qeli:// profile via camera.
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    // Encrypted-at-rest profile store (passwords/obfs_key) — master key in the
    // Android Keystore (TEE/StrongBox where available). See docs/RELEASE-FIXES.md E1.
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
}
