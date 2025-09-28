plugins {
    `kotlin-dsl`
    `java-gradle-plugin`
    id("groovy-gradle-plugin")
}

repositories {
    mavenCentral()
    google()
    gradlePluginPortal()
}

// Annoyingly, build-logic is pre-built before the rest of the subprojects and so cannot
// make use of the version catalogue in libs.versions.toml.
dependencies {
    // AGP
    implementation("com.android.tools.build:gradle:7.4.2")
    implementation("biz.aQute.bnd:biz.aQute.bnd.gradle:6.4.0")
    implementation("com.google.gradle:osdetector-gradle-plugin:1.7.3")
    implementation("net.ltgt.gradle:gradle-errorprone-plugin:4.3.0")
    implementation("org.ajoberstar.grgit:grgit-gradle:5.3.3")
    implementation("com.dorongold.plugins:task-tree:3.0.0")
    implementation(gradleApi())
}
