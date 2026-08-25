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
        versionCode = 720
        versionName = "0.8.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (keystorePropsFile.exists()) {
            create("release") {
                // rootProject.file, not file: this block lives in the :app module, so a bare
                // file() resolves a relative path against qeli-android/app/ — while
                // keystore.properties (and the keystore it names) sit at the project root, as
                // keystore.properties.example instructs. The documented layout could therefore
                // never build: "Keystore file '.../app/qeli-release.jks' not found".
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    // Android framework stubs in the unit-test classpath throw "not mocked" by default, so
    // ANY class touching android.util.Log is unconstructible in a JVM test. PacketCipher
    // logs its chosen algorithm at class-init, which made the wire codec — the most
    // safety-critical code in the app — untestable without a device. That is why Android had
    // no PacketCodec test at all, and why the M6 nonce fix could go missing here unnoticed.
    // Returning defaults instead of throwing lets the shared wire fixtures run on the JVM.
    testOptions {
        unitTests.isReturnDefaultValues = true
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
    implementation("androidx.appcompat:appcompat:1.8.0")
    implementation("com.google.android.material:material:1.14.0")
    implementation("androidx.constraintlayout:constraintlayout:2.2.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    // QR scanning for importing a qeli:// profile via camera.
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    // Read-only one-shot migration of the old security-crypto/Tink preference keysets.
    // New profile writes use AES-GCM + Android Keystore directly (ProfileStore).
    implementation("com.google.crypto.tink:tink-android:1.23.0")
    // Local (JVM) unit tests — e.g. the F3 WebSocket masking wire-vector test that
    // pins byte parity with the Rust/C# obfs framers (ObfsStreamTest).
    testImplementation("junit:junit:4.13.2")
    // A REAL org.json for JVM unit tests. The `org.json` in android.jar is a stub whose
    // every method throws "not mocked", so any test that touches JSON dies at runtime —
    // which is exactly what happened to the conformance test that reads
    // conformance/qeli-links.json. Test-only: the app itself uses the platform's real
    // implementation on-device.
    testImplementation("org.json:json:20260719")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}
