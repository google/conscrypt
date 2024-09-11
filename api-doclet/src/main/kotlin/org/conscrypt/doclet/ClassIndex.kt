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

import javax.lang.model.element.Element
import javax.lang.model.element.TypeElement
import kotlin.streams.toList

class ClassIndex {
    private val index = mutableMapOf<String, ClassInfo>()

    private fun put(classInfo: ClassInfo) {
        index[classInfo.qualifiedName] = classInfo
    }

    fun put(element: Element) {
        put(ClassInfo(element as TypeElement))
    }

    fun get(qualifiedName: String) = index[qualifiedName]
    fun contains(qualifiedName: String) = index.containsKey(qualifiedName)
    fun find(name: String) = if (contains(name)) get(name) else findSimple(name)
    private fun findSimple(name: String) = classes().firstOrNull { it.simpleName == name } // XXX dups

    fun classes(): Collection<ClassInfo> = index.values

    fun addVisible(elements: Set<Element>) {
        elements
            .filterIsInstance<TypeElement>()
            .filter(Element::isVisibleType)
            .forEach(::put)
    }

    private fun packages(): List<String> = index.values.stream()
        .map { it.packageName }
        .distinct()
        .sorted()
        .toList()

    private fun classesForPackage(packageName: String) = index.values.stream()
        .filter { it.packageName == packageName }
        .sorted()
        .toList()

    fun generateHtml():String = html {
        packages().forEach { packageName ->
            div("package-section") {
                h2("Package $packageName", "package-name")
                ul("class-list") {
                    classesForPackage(packageName)
                        .forEach { c ->
                            li {
                                a(c.fileName, c.simpleName)
                            }
                        }

                }
            }
        }
    }
}

