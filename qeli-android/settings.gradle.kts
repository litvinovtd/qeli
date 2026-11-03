pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "qeli"
include(":app")

// Deleting policy files must not silently switch a normal build back to an
// unverified/unlocked bootstrap. Only explicit maintenance flags can seed them.
check(gradle.startParameter.writeDependencyVerifications.isNotEmpty() ||
    file("gradle/verification-metadata.xml").isFile) {
    "Missing Gradle dependency verification metadata; restore the committed file."
}
check(gradle.startParameter.isWriteDependencyLocks ||
    file("buildscript-gradle.lockfile").isFile) {
    "Missing Gradle plugin dependency lock; restore the committed file."
}
