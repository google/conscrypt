import org.gradle.nativeplatform.platform.NativePlatform
import org.gradle.api.Project
import java.io.File

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
data class BuildVariant(
    val buildDir: File? = File("/UNKNOWN"),
    val os: String,
    val targetArch: String, // osdetector architecture name
    val gradleArch: String, // Gradle's architecture name for things like NDK or toolchain selection
    private val boringLib: String = "build64"
) {
    var mavenClassifier: String = "$os-$targetArch"
    var targetPlatform: String = "${os}_${gradleArch}"

    val nativeResourcesDir: String
            = File(buildDir, "$mavenClassifier/native-resources").absolutePath

    val jarNativeResourcesDir: String
            = File(nativeResourcesDir, "META-INF/native").absolutePath

    override fun toString(): String {
        return "BuildVariant<os=$os target=$targetArch gradle=$gradleArch boring=$boringLib>"
    }
}

class NativeBuildResolver(project: Project) {
    private val buildDir: File = project.layout.buildDirectory.asFile.get()

    companion object {
        private val ALL_VARIANTS: List<BuildVariant> = listOf(
            BuildVariant(os = "windows", targetArch = "x86_64", gradleArch = "x86-64"),
            BuildVariant(os = "linux", targetArch = "x86_64", gradleArch = "x86-64"),
            BuildVariant(os = "osx", targetArch = "x86_64", gradleArch = "x86-64",
                boringLib = "build.x86"),
            BuildVariant(os = "osx", targetArch = "aarch_64", gradleArch = "aarch64",
                boringLib = "build.arm")
        )

        // osdetector arch to Gradle
        private val GRADLE_ARCH_MAP: Map<String, String> = mapOf(
            "aarch_64" to "aarch64",
            "x86_64" to "x86-64"
        )

        fun gradleArchFromOsDetector(osDetectorArch: String): String
                = GRADLE_ARCH_MAP[osDetectorArch] ?: osDetectorArch
    }

    fun find(os: String, arch: String): BuildVariant? {
        return ALL_VARIANTS
            .find { it.os == os && it.targetArch == arch }
            ?.copy(buildDir = this@NativeBuildResolver.buildDir)
    }

    fun findAll(os: String): List<BuildVariant> {
        return ALL_VARIANTS
            .filter { it.os == os }
            .map { it.copy(buildDir = this@NativeBuildResolver.buildDir) }
    }

    fun find(nativePlatform: NativePlatform): BuildVariant? {
        return ALL_VARIANTS
            .find { it.os == nativePlatform.operatingSystem.name
                    && it.gradleArch == nativePlatform.architecture.name }
            ?.copy(buildDir = buildDir)
    }
}
