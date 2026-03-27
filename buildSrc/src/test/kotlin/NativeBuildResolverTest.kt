import org.gradle.nativeplatform.platform.internal.DefaultNativePlatform
import org.gradle.testfixtures.ProjectBuilder
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class NativeBuildResolverTest {
    // Verify lookup by Maven osdetector names (os + maven arch).
    @Test
    fun findByOsdetectorExact() {
        assertEquals(
            NativeBuildVariant.OSX_ARM64,
            NativeBuildVariant.find("osx", "aarch_64")
        )
        assertEquals(
            NativeBuildVariant.LINUX_X64,
            NativeBuildVariant.find("linux", "x86_64")
        )
    }

    // Verify lookup by Gradle native platform names (os + gradle arch).
    @Test
    fun findByGradleExact() {
        assertEquals(
            NativeBuildVariant.OSX_X64,
            NativeBuildVariant.findForGradle("osx", "x86-64")
        )
        assertEquals(
            NativeBuildVariant.OSX_ARM64,
            NativeBuildVariant.findForGradle("osx", "aarch64")
        )
    }

    // Unknown or unsupported platform/arch combinations return null.
    @Test
    fun findUnknownReturnsNull() {
        assertNull(NativeBuildVariant.find("linux", "armv7"))
        assertNull(NativeBuildVariant.findForGradle("windows", "aarch64"))
    }

    // macOS returns both x86_64 and aarch64 variants (cross-compile).
    @Test
    fun findAllByOs() {
        val osx = NativeBuildVariant.findAll("osx", "aarch_64").toSet()
        assertEquals(setOf(NativeBuildVariant.OSX_X64, NativeBuildVariant.OSX_ARM64), osx)
    }

    // Linux returns only the matching variant (no cross-compile (yet)).
    @Test
    fun findAllLinuxReturnsSingleVariant() {
        val linux = NativeBuildVariant.findAll("linux", "x86_64")
        assertEquals(listOf(NativeBuildVariant.LINUX_X64), linux)
    }

    // Unknown OS returns an empty list.
    @Test
    fun findAllUnknownReturnsEmpty() {
        assertTrue(NativeBuildVariant.findAll("solaris", "sparc").isEmpty())
    }

    // Windows x86_64 variant is resolvable.
    @Test
    fun findWindowsVariant() {
        assertEquals(
            NativeBuildVariant.WINDOWS_X64,
            NativeBuildVariant.find("windows", "x86_64")
        )
    }

    // Maven classifier, Gradle target, and BoringSSL dir strings are correct.
    @Test
    fun computedStringsAreStable() {
        assertEquals(
            "osx-aarch_64",
            NativeBuildVariant.OSX_ARM64.let { "${it.os}-${it.mavenArch}" })
        assertEquals(
            "osx_aarch64",
            NativeBuildVariant.OSX_ARM64.let { "${it.os}_${it.gradleArch}" })
        assertEquals("build.arm", NativeBuildVariant.OSX_ARM64.boringBuildDir)
        assertEquals("build64", NativeBuildVariant.LINUX_X64.boringBuildDir)
    }

    // NativeBuildInformation derives resource paths from project build dir.
    @Test
    fun directoriesAreDerivedCorrectlyFromBuilddir() {
        val tmp = Files.createTempDirectory("nativeBuildTest").toFile().apply { deleteOnExit() }
        val project = ProjectBuilder.builder().withProjectDir(tmp).build()
        val info = NativeBuildInformation(project.layout.buildDirectory, NativeBuildVariant.OSX_X64)

        assertTrue(
            info.nativeResourcesDir.replace('\\', '/')
                .endsWith("osx-x86_64/native-resources")
        )
        assertTrue(
            info.jarNativeResourcesDir.replace('\\', '/')
                .endsWith("osx-x86_64/native-resources/META-INF/native")
        )
        assertEquals("osx-x86_64", info.mavenClassifier)
        assertEquals("osx_x86-64", info.targetPlatform)
    }

    // NativeBuildResolver maps a Gradle NativePlatform to the correct variant.
    @Test
    fun resolverFindsByNativePlatform() {
        val project = ProjectBuilder.builder().build()
        val resolver = NativeBuildResolver(project.layout.buildDirectory)
        val platform = DefaultNativePlatform("osx_aarch64").apply {
            operatingSystem("osx")
            architecture("aarch64")
        }

        val info = resolver.find(platform)
        assertNotNull(info)
        assertEquals("osx-aarch_64", info.mavenClassifier)
        assertEquals("osx_aarch64", info.targetPlatform)
    }

    // NativeBuildResolver wraps variants with project build directory.
    @Test
    fun resolverWrapsVariants() {
        val project = ProjectBuilder.builder().build()
        val resolver = NativeBuildResolver(project.layout.buildDirectory)

        // There should only be a single Linux variant for now.
        val info = resolver.findAll("linux", "x86_64").single()
        assertEquals("linux-x86_64", info.mavenClassifier)
        assertEquals(project.layout.buildDirectory.get().asFile, info.buildDir.get().asFile)
    }
}
