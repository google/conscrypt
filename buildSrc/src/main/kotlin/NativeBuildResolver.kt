import org.gradle.api.provider.Provider
import org.gradle.nativeplatform.platform.NativePlatform
import java.io.File
import org.gradle.api.file.Directory

/**
 * Gradle mostly uses Java os.arch names for architectures which feeds into default
 * targetPlatform names.  Notable exception Gradle 6.9.x reports MacOS/ARM as arm-v8.
 *
 * The Maven osdetector plugin (which we recommend to developers) uses different
 * arch names, so that's what we need for artifacts.
 *
 * This class encapsulates both naming schemes as well as other per-platform information
 * about native builds, more of which will migrate in here over time.
 */
enum class NativeBuildVariant(
    val os: String,
    val mavenArch: String, // osdetector / Maven architecture name
    val gradleArch: String, // Gradle architecture, used for things like NDK or toolchain selection
    val boringBuildDir: String = "build64", // Where to find prebuilt libcrypto
   ) {
    WINDOWS_X64("windows", "x86_64", "x86-64"),
    LINUX_X64("linux", "x86_64", "x86-64"),
    OSX_X64("osx", "x86_64", "x86-64", "build.x86"),
    OSX_ARM64("osx", "aarch_64", "aarch64", "build.arm");

    override fun toString(): String
            = "<os=$os target=$mavenArch gradle=$gradleArch boring=$boringBuildDir>"

    companion object {
        fun find(os: String, arch: String)
                = values().find { it.os == os && it.mavenArch == arch }
        fun findForGradle(os: String, arch: String)
                = values().find { it.os == os && it.gradleArch == arch }
        fun findAll(os: String) = values().filter { it.os == os }
    }
}

data class NativeBuildInfo(
    val buildDir: Provider<Directory>,
    private val variant: NativeBuildVariant
) {
    val mavenClassifier: String = "${variant.os}-${variant.mavenArch}"
    val targetPlatform: String = "${variant.os}_${variant.gradleArch}"

    val nativeResourcesDir: String
        get() = File(buildDir.get().asFile, "$mavenClassifier/native-resources").absolutePath

    val jarNativeResourcesDir: String
        get() = File(nativeResourcesDir, "META-INF/native").absolutePath

    val boringBuildDir
        get() = variant.boringBuildDir

    override fun toString(): String
            = "NativeBuildInfo<buildDir=${buildDir.get()} variant=$variant>"
}

class NativeBuildResolver(private val buildDir: Provider<Directory>) {
    private fun wrap(variant: NativeBuildVariant?) = variant?.let {
        NativeBuildInfo(buildDir, it)
    }

    fun find(os: String, arch: String) = wrap(NativeBuildVariant.find(os, arch))

    fun find(nativePlatform: NativePlatform) = wrap(NativeBuildVariant.findForGradle(
        nativePlatform.operatingSystem.name,
        nativePlatform.architecture.name))

    fun findAll(os: String): List<NativeBuildInfo> = NativeBuildVariant.findAll(os). map {
        NativeBuildInfo(buildDir, it)
    }
}
