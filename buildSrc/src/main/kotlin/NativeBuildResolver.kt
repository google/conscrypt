import org.gradle.api.file.Directory
import org.gradle.api.provider.Provider
import org.gradle.nativeplatform.platform.NativePlatform
import java.io.File

/**
 * Gradle mostly uses Java os.arch names for architectures which feeds into default
 * targetPlatform names.  Notable exception Gradle 6.9.x reports MacOS/ARM as arm-v8.
 *
 * The Maven osdetector plugin (which we recommend to developers) uses different
 * arch names, so that's what we need for artifacts.
 *
 * This class encapsulates both naming schemes as well as other per-platform information
 * about native builds.
 *
 * This information is project independent and should rarely change over time.
 */
enum class NativeBuildVariant(
    val os: String,
    val mavenArch: String,                  // osdetector / Maven architecture name
    val gradleArch: String,                 // Gradle name, used for NDK / toolchain etc
    val boringBuildDir: String = "build64", // Where to find prebuilt BoringSSL libcrypto
    val crossCompile: Boolean = false       // Whether we can cross-compile for this architecture
) {
    WINDOWS_X64("windows", "x86_64", "x86-64"),
    LINUX_X64("linux", "x86_64", "x86-64"),
    OSX_X64("osx", "x86_64", "x86-64", "build.x86", true),
    OSX_ARM64("osx", "aarch_64", "aarch64", "build.arm", true);

    override fun toString(): String =
        "<os=$os target=$mavenArch gradle=$gradleArch boring=$boringBuildDir>"

    companion object {
        /**
         * Finds the NativeBuildVariant for a particular Maven osdetector architecture.
         */
        fun find(os: String, arch: String) = values().find { it.os == os && it.mavenArch == arch }

        /**
         * Finds the NativeBuildVariant for a particular Gradle architecture.
         */
        fun findForGradle(os: String, arch: String) =
            values().find { it.os == os && it.gradleArch == arch }

        /**
         * Finds all the NativeBuildVariants which can be built on a particular
         * host OS.
         */
        fun findAll(os: String, arch: String) = values().filter {
            it.os == os && (it.mavenArch == arch || it.crossCompile)
        }
    }
}

/**
 * Encapsulates native information for the current project, i.e. a combination of the
 * NativeBuildVariant and information about the current project such as its build directory.
 */
data class NativeBuildInformation(
    val buildDir: Provider<Directory>,
    private val variant: NativeBuildVariant
) {
    /** Classifier used for jars etc */
    val mavenClassifier: String = "${variant.os}-${variant.mavenArch}"

    /** Target platform name as used for Gradle native builds */
    val targetPlatform: String = "${variant.os}_${variant.gradleArch}"

    /** Directory for native resources for this builds */
    val nativeResourcesDir: String
        get() = File(buildDir.get().asFile, "$mavenClassifier/native-resources").absolutePath

    /** Directory for jar resources for this builds */
    val jarNativeResourcesDir: String
        get() = File(nativeResourcesDir, "META-INF/native").absolutePath

    /** Name of the native library directory in $BORINGSSL_HOME */
    val boringBuildDir
        get() = variant.boringBuildDir

    override fun toString(): String =
        "NativeBuildInfo<buildDir=${buildDir.orNull} variant=$variant>"
}

/**
 * Replacement for the Groovy NativeBuildInfo enum using the above classes.
 *
 * Needs to be instantiated with the buildDir of the current build and then makes this
 * available where needed in NativeBuildInformation objects.
 */
class NativeBuildResolver(private val buildDir: Provider<Directory>) {
    // Wraps an immutable NativeBuildVariant with project information for this build */
    private fun wrap(variant: NativeBuildVariant?) = variant?.let {
        NativeBuildInformation(buildDir, it)
    } ?: error("Null build variant")


    /**
     * Returns a NativeBuildInformation for the provided Maven architecture in the current project.
     */
    fun find(os: String, arch: String) = wrap(NativeBuildVariant.find(os, arch))

    /**
     * Returns a NativeBuildInformation for the provided Gradle NativePlatform in the current project.
     */
    fun find(nativePlatform: NativePlatform) = wrap(
        NativeBuildVariant.findForGradle(
            nativePlatform.operatingSystem.name,
            nativePlatform.architecture.name
        )
    )

    /**
     * Returns a list of NativeBuildInformation for all the architectures buildable on a
     * particular host OS and Architecture.
     */
    fun findAll(os: String, arch: String): List<NativeBuildInformation> =
        NativeBuildVariant.findAll(os, arch).map {
            NativeBuildInformation(buildDir, it)
        }
}
