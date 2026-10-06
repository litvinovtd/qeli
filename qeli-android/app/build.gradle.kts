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

// Build the matching androidTest APK; debug tests cannot target an R8 release APK.
val qeliTestBuildType = providers.gradleProperty("qeliTestBuildType").getOrElse("debug")
require(qeliTestBuildType in listOf("debug", "release")) { "qeliTestBuildType must be debug or release" }
val qeliLabReleaseSigning = providers.gradleProperty("qeliLabReleaseSigning").getOrElse("false").toBooleanStrict()
require(!qeliLabReleaseSigning || qeliTestBuildType == "release") { "Lab release signing requires the release test variant" }

android {
    testBuildType = qeliTestBuildType
    // Fresh CI/development output replaces, rather than supplements, committed jniLibs.
    providers.environmentVariable("QELI_NATIVE_JNI_DIR").orNull?.let { nativeDir ->
        sourceSets.getByName("main").jniLibs.setSrcDirs(listOf(nativeDir))
    }
    namespace = "com.qeli"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.qeli"
        minSdk = 28
        targetSdk = 37
        versionCode = 722
        versionName = "0.8.2"
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

    // JVM policy/model tests can reach Android logging without executing framework APIs.
    // Return defaults for those stubs; actual framework behavior is tested on Android.
    // INI parsing still loads the production host ConfigCore JNI, configured below.
    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (qeliTestBuildType == "release") proguardFiles("instrumentation-abi.pro")
            // Sign the release only when a keystore is configured; otherwise the
            // APK is left unsigned (so CI / fresh clones still build).
            if (qeliLabReleaseSigning) {
                // Explicit disposable-lab fixture only; never a production signing fallback.
                signingConfig = signingConfigs.getByName("debug")
            } else if (keystorePropsFile.exists()) {
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
    implementation("androidx.core:core-ktx:1.19.1")
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
    // Local policy/model and shared configuration conformance tests.
    // Handshake, framing and payload codecs are owned by Rust, not duplicated here.
    testImplementation("junit:junit:4.13.2")
    // A REAL org.json for JVM unit tests. The `org.json` in android.jar is a stub whose
    // every method throws "not mocked", so any test that touches JSON dies at runtime —
    // which is exactly what happened to the conformance test that reads
    // conformance/qeli-links.json. Test-only: the app itself uses the platform's real
    // implementation on-device.
    testImplementation("org.json:json:20260814")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}

// Shared fixtures live outside this Gradle project. Declare them so edits to the
// cross-language contract cannot reuse an old successful JVM test result.
tasks.withType<org.gradle.api.tasks.testing.Test>().configureEach {
    inputs.dir(rootProject.layout.projectDirectory.dir("../conformance"))
        .withPropertyName("sharedConformanceFixtures")
        .withPathSensitivity(org.gradle.api.tasks.PathSensitivity.RELATIVE)
}

// JVM tests must execute the production Rust editor, never a second parser or a mock.
tasks.withType<org.gradle.api.tasks.testing.Test>().configureEach {
    val hostCore = providers.environmentVariable("QELI_CONFIG_NATIVE_LIBRARY")
    if (hostCore.isPresent) {
        inputs.file(hostCore).withPropertyName("hostConfigCore")
        systemProperty("qeli.config.nativeLibrary", hostCore.get())
    }
}


// Export resolved classpaths for the pre-R8 instrumentation ABI generator.
// Compile/assemble the matching releaseAndroidTest variant before using them.
tasks.register("printInstrumentationAbiClasspaths") {
    doLast {
        check(qeliTestBuildType == "release") { "Select -PqeliTestBuildType=release" }
        listOf("releaseRuntimeClasspath", "releaseAndroidTestRuntimeClasspath").forEach { name ->
            val paths = configurations.getByName(name).files.map { it.absolutePath }.sorted()
            println("Q29_CP $name " + groovy.json.JsonOutput.toJson(paths))
        }
    }
}
