import org.gradle.api.attributes.AttributeCompatibilityRule
import org.gradle.api.attributes.CompatibilityCheckDetails
import org.gradle.api.artifacts.type.ArtifactTypeDefinition
import java.security.MessageDigest
import java.nio.file.Files
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.MapProperty
import org.gradle.api.tasks.*
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
        versionCode = 724
        versionName = "0.8.4"
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
    implementation("com.google.crypto.tink:tink-android:1.24.0")
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

// Each APK keeps its own runtime notices, even when R8 removes Java resources.
// The reviewed inventory is a maintenance gate, not a guess based on coordinates.
abstract class GenerateLegalAssets : DefaultTask() {
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE)
    abstract val coreLicense: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE)
    abstract val clientLicense: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE)
    abstract val apacheLicense: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE)
    abstract val reviewedInventory: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE)
    abstract val cargoLock: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE)
    abstract val toolchainInventory: RegularFileProperty
    @get:InputDirectory @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val nativeLegalBundle: DirectoryProperty
    @get:InputFiles @get:PathSensitive(PathSensitivity.NAME_ONLY)
    abstract val runtimeArtifacts: ConfigurableFileCollection
    @get:Input abstract val artifactCoordinates: MapProperty<String, String>
    @get:Input abstract val runtimeCoordinates: ListProperty<String>
    @get:OutputDirectory abstract val outputDirectory: DirectoryProperty

    @TaskAction fun generate() {
        val inventory = reviewedInventory.get().asFile.readText(Charsets.UTF_8).replace("\r\n", "\n")
        val lines = inventory.trimEnd().lines()
        check(lines.first() == "coordinate\tlicense\treview") { "Invalid license inventory header" }
        val reviewed = lines.drop(1).map { line ->
            val fields = line.split('\t')
            check(fields.size == 3 && fields[1] == "Apache-2.0" && fields[2].startsWith("https://")) {
                "Review the upstream license/notice policy for $line"
            }
            check(fields[0].matches(Regex("[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9_.+-]+")))
            fields[0]
        }
        check(reviewed.size == reviewed.toSet().size) { "Duplicate license coordinates" }
        val actual = runtimeCoordinates.get().toSet()
        check(actual == reviewed.toSet()) {
            "Maven license inventory drift: unreviewed=${actual - reviewed.toSet()}, removed=${reviewed.toSet() - actual}"
        }
        val output = outputDirectory.get().asFile
        check(output.deleteRecursively() || !output.exists()) { "Cannot clear generated legal assets" }
        val legal = output.resolve("licenses").apply { mkdirs() }
        val records = mutableListOf<String>()
        fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
        fun save(path: String, bytes: ByteArray, origin: String) {
            check(bytes.isNotEmpty() && '\t' !in origin && '\n' !in origin && '\r' !in origin)
            val file = legal.resolve(path)
            check(!file.exists()) { "Duplicate legal asset: $path" }
            file.parentFile.mkdirs()
            file.writeBytes(bytes)
            records += "${sha(bytes)}\t$path\t$origin"
        }
        for ((name, source) in listOf("AGPL-3.0.txt" to coreLicense, "MPL-2.0.txt" to clientLicense,
            "Apache-2.0.txt" to apacheLicense)) {
            save(name, source.get().asFile.readText(Charsets.UTF_8).replace("\r\n", "\n").toByteArray(Charsets.UTF_8), name)
        }
        save("MAVEN.tsv", inventory.toByteArray(Charsets.UTF_8), "reviewed Maven runtime inventory")
        val native = nativeLegalBundle.get().asFile
        val lockSha = sha(cargoLock.get().asFile.readBytes().toString(Charsets.UTF_8)
            .replace("\r\n", "\n").toByteArray(Charsets.UTF_8))
        check(native.resolve("BINDING.properties").readText(Charsets.UTF_8) ==
            "cargo_lock_lf_sha256=$lockSha\nscope=full-cargo-lock\n") { "Native legal Cargo.lock binding drift" }
        val toolchainPolicy = toolchainInventory.get().asFile.readText(Charsets.UTF_8).replace("\r\n", "\n")
        check(native.resolve("toolchains/SOURCES.tsv").readText(Charsets.UTF_8) == toolchainPolicy) {
            "Native toolchain source inventory drift"
        }
        val nativeRows = native.resolve("INDEX.tsv").readText(Charsets.UTF_8).trimEnd().lines()
        check(nativeRows.first() == "sha256\tpath\torigin") { "Invalid native legal index" }
        val nativeSeen = mutableSetOf<String>()
        for (row in nativeRows.drop(1)) {
            val fields = row.split('\t')
            check(fields.size == 3 && fields[0].matches(Regex("[0-9a-f]{64}")))
            val path = fields[1]
            check(path.isNotEmpty() && path.split('/').none { it.isEmpty() || it == "." || it == ".." } &&
                '\\' !in path && ':' !in path && path.none { it.code < 32 || it.code == 127 } &&
                path != "INDEX.tsv" && nativeSeen.add(path)) { "Unsafe/duplicate native legal path" }
            val file = native.resolve(path)
            check(!Files.isSymbolicLink(file.toPath()) && file.isFile && file.length() <= 4 * 1024 * 1024)
            val bytes = file.readBytes()
            check(sha(bytes) == fields[0]) { "Native legal checksum mismatch: $path" }
        }
        val nativeFiles = native.walkTopDown().filter { it.isFile }.toList()
        check(nativeFiles.sumOf { it.length() } <= 32 * 1024 * 1024)
        check(nativeFiles.map { it.relativeTo(native).invariantSeparatorsPath }.toSet() == nativeSeen + "INDEX.tsv") {
            "Unindexed/missing native legal files"
        }
        check(native.resolve("Qeli-AGPL-3.0.txt").readBytes().contentEquals(legal.resolve("AGPL-3.0.txt").readBytes()))
        for (file in nativeFiles.sortedBy { it.relativeTo(native).invariantSeparatorsPath }) {
            check(!Files.isSymbolicLink(file.toPath()))
            val path = file.relativeTo(native).invariantSeparatorsPath
            save("native-rust/$path", file.readBytes(), "native-rust!$path")
        }
        val noticeName = Regex("(?i)(license|licence|notice|copying|copyright)([._-].*)?")
        fun notice(name: String) = noticeName.matches(name.substringAfterLast('/'))
        fun retain(coordinate: String, name: String, bytes: ByteArray) {
            check(bytes.size <= 4 * 1024 * 1024) { "Oversized legal notice: $name" }
            // Never extract archive paths: digest-based output preserves colliding names.
            save("maven/${coordinate.replace(':', '/')}/${sha(name.toByteArray(Charsets.UTF_8))}.txt",
                bytes, "$coordinate!$name")
        }
        val artifactRecords = mutableListOf<String>()
        for (file in runtimeArtifacts.files.sortedBy { it.name }) {
            val coordinate = artifactCoordinates.get().getValue(file.name)
            artifactRecords += "$coordinate\t${file.name}\t${sha(file.readBytes())}"
            ZipFile(file).use { archive ->
                check(archive.size() <= 100000) { "Oversized runtime archive" }
                for (entry in archive.entries().asSequence().filter { !it.isDirectory }.sortedBy { it.name }) {
                    if (notice(entry.name)) {
                        val bytes = archive.getInputStream(entry).use { it.readNBytes(4 * 1024 * 1024 + 1) }
                        retain(coordinate, entry.name, bytes)
                    } else if (file.extension == "aar" && (entry.name == "classes.jar" ||
                        entry.name.startsWith("libs/") && entry.name.endsWith(".jar"))) {
                        val bytes = archive.getInputStream(entry).use { it.readNBytes(64 * 1024 * 1024 + 1) }
                        check(bytes.size <= 64 * 1024 * 1024) { "Oversized nested jar: ${entry.name}" }
                        ZipInputStream(bytes.inputStream()).use { nested ->
                            var count = 0
                            while (true) {
                                val item = nested.nextEntry ?: break
                                check(++count <= 100000) { "Oversized nested runtime archive" }
                                if (!item.isDirectory && notice(item.name)) {
                                    retain(coordinate, "${entry.name}!${item.name}", nested.readNBytes(4 * 1024 * 1024 + 1))
                                }
                                nested.closeEntry()
                            }
                        }
                    }
                }
            }
        }
        save("ARTIFACTS.tsv", ("coordinate\tartifact\tsha256\n" + artifactRecords.sorted().joinToString("\n", postfix = "\n"))
            .toByteArray(Charsets.UTF_8), "original Maven runtime archive identities")
        legal.resolve("INDEX.tsv").writeText("sha256\tpath\torigin\n" + records.sorted().joinToString("\n", postfix = "\n"), Charsets.UTF_8)
    }
}

// A dedicated consumer attribute requests either original JAR or original AAR.
// This compatibility rule applies only to the legal-assets view.
abstract class LegalArchiveCompatibility : AttributeCompatibilityRule<String> {
    override fun execute(details: CompatibilityCheckDetails<String>) {
        if (details.consumerValue == "qeli-legal-original" && details.producerValue in listOf("jar", "aar")) {
            details.compatible()
        }
    }
}

dependencies.attributesSchema.attribute(ArtifactTypeDefinition.ARTIFACT_TYPE_ATTRIBUTE) {
    compatibilityRules.add(LegalArchiveCompatibility::class.java)
}

androidComponents.onVariants { variant ->
    val runtime = configurations.getByName("${variant.name}RuntimeClasspath")
    // Select original archives without AGP transforms stripping outer AAR notices.
    val artifacts = runtime.incoming.artifactView {
        attributes.attribute(ArtifactTypeDefinition.ARTIFACT_TYPE_ATTRIBUTE, "qeli-legal-original")
    }.artifacts.resolvedArtifacts
    val legal = tasks.register<GenerateLegalAssets>("generate${variant.name.replaceFirstChar { it.uppercaseChar() }}LegalAssets") {
        coreLicense.set(rootProject.layout.projectDirectory.file("../LICENSE"))
        clientLicense.set(rootProject.layout.projectDirectory.file("LICENSE"))
        apacheLicense.set(rootProject.layout.projectDirectory.file("gradle/licenses/Apache-2.0.txt"))
        reviewedInventory.set(rootProject.layout.projectDirectory.file("gradle/licenses/maven-runtime.tsv"))
        cargoLock.set(rootProject.layout.projectDirectory.file("../qeli/Cargo.lock"))
        toolchainInventory.set(rootProject.layout.projectDirectory.file("../qeli/third-party-notices/toolchain-sources.tsv"))
        nativeLegalBundle.set(rootProject.layout.projectDirectory.dir("../qeli/third-party-notices/rust"))
        runtimeArtifacts.from(artifacts.map { values -> values.map { it.file } })
        artifactCoordinates.set(artifacts.map { values ->
            // A module may be visited through multiple Gradle variants; keep one
            // record per identical component and original physical archive.
            val pairs = values.distinctBy { it.id.componentIdentifier to it.file.absolutePath }.map { value ->
                val id = value.id.componentIdentifier as? ModuleComponentIdentifier
                    ?: error("Review local runtime dependency licensing: ${value.id}")
                value.file.name to "${id.group}:${id.module}:${id.version}"
            }
            check(pairs.map { it.first }.toSet().size == pairs.size) { "Ambiguous runtime archive identity: ${pairs.groupBy { it.first }.filterValues { it.size > 1 }}" }
            pairs.toMap()
        })
        runtimeCoordinates.set(providers.provider {
            runtime.incoming.resolutionResult.allComponents.mapNotNull { component ->
                (component.id as? ModuleComponentIdentifier)?.let { "${it.group}:${it.module}:${it.version}" }
            }.sorted()
        })
    }
    variant.sources.assets?.addGeneratedSourceDirectory(legal, GenerateLegalAssets::outputDirectory)
}
