import org.gradle.testfixtures.ProjectBuilder
import kotlin.test.*

class NativeBuildResolverTest {
    @Test
    fun findByOsdetectorExact() {
        assertEquals(NativeBuildVariant.OSX_ARM64,
            NativeBuildVariant.find("osx", "aarch_64"))
        assertEquals(NativeBuildVariant.LINUX_X64,
            NativeBuildVariant.find("linux", "x86_64"))
    }

    @Test
    fun findByGradleExact() {
        assertEquals(NativeBuildVariant.OSX_X64,
            NativeBuildVariant.findForGradle("osx", "x86-64"))
        assertEquals(NativeBuildVariant.OSX_ARM64,
            NativeBuildVariant.findForGradle("osx", "aarch64"))
    }

    @Test
    fun findUnknownReturnsNull() {
        assertNull(NativeBuildVariant.find("linux", "armv7"))
        assertNull(NativeBuildVariant.findForGradle("windows", "aarch64"))
    }

    @Test
    fun findAllByOs() {
        val osx = NativeBuildVariant.findAll("osx", "aarch_64").toSet()
        assertEquals(setOf(NativeBuildVariant.OSX_X64, NativeBuildVariant.OSX_ARM64), osx)
    }

    @Test
    fun computedStringsAreStable() {
        assertEquals("osx-aarch_64", NativeBuildVariant.OSX_ARM64.let { "${it.os}-${it.mavenArch}" })
        assertEquals("osx_aarch64",  NativeBuildVariant.OSX_ARM64.let { "${it.os}_${it.gradleArch}" })
        assertEquals("build.arm",    NativeBuildVariant.OSX_ARM64.boringBuildDir)
        assertEquals("build64",      NativeBuildVariant.LINUX_X64.boringBuildDir)
    }

    @Test
    fun directoriesAreDerivedCorrectlyFromBuilddir() {
        val tmp = createTempDir().apply { deleteOnExit() }
        val project = ProjectBuilder.builder().withProjectDir(tmp).build()
        val info = NativeBuildInfo(project.layout.buildDirectory, NativeBuildVariant.OSX_X64)

        assertTrue(info.nativeResourcesDir.replace('\\', '/')
            .endsWith("osx-x86_64/native-resources"))
        assertTrue(info.jarNativeResourcesDir.replace('\\', '/')
            .endsWith("osx-x86_64/native-resources/META-INF/native"))
        assertEquals("osx-x86_64", info.mavenClassifier)
        assertEquals("osx_x86-64", info.targetPlatform)
    }

    @Test fun resolverWrapsVariants() {
        val project = ProjectBuilder.builder().build()
        val resolver = NativeBuildResolver(project.layout.buildDirectory)

        // There should only be a single Linux variant for now.
        val info = resolver.findAll("linux", "x86_64").single()
        assertEquals("linux-x86_64", info.mavenClassifier)
        assertEquals(project.layout.buildDirectory.get().asFile, info.buildDir.get().asFile)
    }
}
