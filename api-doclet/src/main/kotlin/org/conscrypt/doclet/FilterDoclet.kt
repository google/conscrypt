/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.conscrypt.doclet

import com.sun.source.util.DocTrees
import jdk.javadoc.doclet.Doclet
import jdk.javadoc.doclet.DocletEnvironment
import jdk.javadoc.doclet.Reporter
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.Locale
import javax.lang.model.SourceVersion
import javax.lang.model.util.Elements
import javax.lang.model.util.Types

class FilterDoclet : Doclet {
    companion object {
        lateinit var docTrees: DocTrees
        lateinit var elementUtils: Elements
        lateinit var typeUtils: Types
        lateinit var outputPath: Path
        var baseUrl: String = "https://docs.oracle.com/javase/8/docs/api/"
        val CSS_FILENAME = "styles.css"
        var outputDir = "."
        var docTitle = "DTITLE"
        var windowTitle = "WTITLE"
        var noTimestamp: Boolean = false
        val classIndex = ClassIndex()
    }

    override fun init(locale: Locale?, reporter: Reporter?) = Unit // TODO
    override fun getName() = "FilterDoclet"
    override fun getSupportedSourceVersion() = SourceVersion.latest()

    override fun run(environment: DocletEnvironment): Boolean {
        docTrees = environment.docTrees
        elementUtils = environment.elementUtils
        typeUtils = environment.typeUtils
        outputPath = Paths.get(outputDir)
        Files.createDirectories(outputPath)

        classIndex.addVisible(environment.includedElements)

        try {
            generateClassFiles()
            generateIndex()
            return true
        } catch (e: Exception) {
            System.err.println("Error generating documentation: " + e.message)
            e.printStackTrace()
            return false
        }
    }

    private fun generateClassFiles() = classIndex.classes().forEach(::generateClassFile)

    private fun generateIndex() {
        val indexPath = outputPath.resolve("index.html")

        html {
            body(
                title = docTitle,
                stylesheet = relativePath(indexPath, CSS_FILENAME),
            ) {
                div("index-container") {
                    h1(docTitle, "index-title")
                    compose {
                        classIndex.generateHtml()
                    }
                }
            }
        }.let {
            Files.newBufferedWriter(indexPath).use { writer ->
                writer.write(it)
            }
        }
    }

    private fun generateClassFile(classInfo: ClassInfo) {
        val classFilePath = outputPath.resolve(classInfo.fileName)
        Files.createDirectories(classFilePath.parent)
        val simpleName = classInfo.simpleName

        html {
            body(
                title = "$simpleName - conscrypt-openjdk API",
                stylesheet = relativePath(classFilePath, CSS_FILENAME),
            ) {
                compose {
                    classInfo.generateHtml()
                }
            }
        }.let {
            Files.newBufferedWriter(classFilePath).use { writer ->
                writer.write(it)
            }
        }
    }

    private fun relativePath(from: Path, to: String): String {
        val fromDir = from.parent
        val toPath = Paths.get(outputDir).resolve(to)

        if (fromDir == null) {
            return to
        }

        val relativePath = fromDir.relativize(toPath)
        return relativePath.toString().replace('\\', '/')
    }

    override fun getSupportedOptions(): Set<Doclet.Option> {
        return setOf<Doclet.Option>(
            StringOption(
                "-d",
                "<directory>",
                "Destination directory for output files"
            ) { d: String -> outputDir = d },
            StringOption(
                "-doctitle",
                "<title>",
                "Document title"
            ) { t: String -> docTitle = t },
            StringOption(
                "-windowtitle",
                "<title>",
                "Window title"
            ) { w: String -> windowTitle = w },
            StringOption(
                "-link",
                "<link>",
                "Link"
            ) { l: String -> baseUrl = l },
            BooleanOption(
                "-notimestamp",
                "Something"
            ) { noTimestamp = true })
    }
}