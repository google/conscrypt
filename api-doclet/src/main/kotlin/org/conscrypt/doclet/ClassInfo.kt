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

import org.conscrypt.doclet.FilterDoclet.Companion.classIndex
import java.nio.file.Paths
import java.util.Locale
import javax.lang.model.element.Element
import javax.lang.model.element.ExecutableElement
import javax.lang.model.element.Modifier
import javax.lang.model.element.TypeElement
import javax.lang.model.type.TypeMirror


data class ClassInfo(val element: TypeElement) : Comparable<ClassInfo> {
    val simpleName = element.simpleName.toString()
    val qualifiedName = element.qualifiedName.toString()
    val packageName = FilterDoclet.elementUtils.getPackageOf(element).qualifiedName.toString()
    val fileName = element.baseFileName() + ".html"
    val isInnerClass = element.enclosingElement.isType()

    fun innerClasses() = element.enclosedElements
        .filterIsInstance<TypeElement>()
        .filter(TypeElement::isType)
        .map(classIndex::get)
        .sorted()


    private fun outerClass() = if (isInnerClass) {
        classIndex.get(element.enclosingElement as TypeElement)
    } else {
        null
    }

    fun innerName(): String = if (isInnerClass) {
        "${outerClass()?.innerName()}.$simpleName"
    } else {
        simpleName
    }

    private fun signature(): String {
        val visibleModifiers = element.modifiers
            .map(Modifier::toString)
            .toMutableSet()

        val kind = element.kind.toString().lowercase(Locale.getDefault())
        if (kind == "interface") {
            visibleModifiers.remove("abstract")
        }

        val modifierString = visibleModifiers.joinToString(" ")

        val superName = superDisplayName(element.superclass)

        val interfaces = element.interfaces
            .joinToString(", ")
            .prefixIfNotEmpty(" implements ")

        return "$modifierString $kind ${innerName()}$superName$interfaces"
    }

    private fun superDisplayName(mirror: TypeMirror): String {
        val name = mirror.toString()
        return when  {
            name == "none" || name == "java.lang.Object" -> ""
            name.startsWith("java.lang.Enum") -> ""
            else -> " extends $mirror "
        }
    }


    override fun compareTo(other: ClassInfo) = qualifiedName.compareTo(other.qualifiedName)

    private fun description() = html {
        div("class-description") {
            compose {
                element.commentsAndTagTrees()
            }
        }
    }

    private fun fields() = html {
        val fields = element.children(Element::isVisibleField)
        if (fields.isNotEmpty()) {
            h2("Fields")
            fields.forEach { field ->
                div("member") {
                    h4(field.simpleName.toString())
                    compose {
                        field.commentsAndTagTrees()
                    }
                }
            }
        }
    }

    private fun nestedClasses() = html {
        val nested = element.children(Element::isVisibleType)
        nested.takeIf { it.isNotEmpty() }?.let {
            h2("Nested Classes")
            nested.forEach { cls ->
                val typeElement = cls as TypeElement
                val info = classIndex.get(typeElement)
                val parent = classIndex.getParent(typeElement)
                div("member") {
                    h4 {
                        a(relativePath(parent.fileName, info.fileName), info.simpleName)
                    }
                    compose {
                        cls.commentsAndTagTrees()
                    }
                }
            }
        }
    }

    private fun method(method: ExecutableElement) = html {
        div("member") {
            h4(method.simpleName.toString())
            pre(method.methodSignature(), "method-signature")
            div("description") {
                compose {
                    method.commentTree()
                }
                val params = method.paramTags()
                val throwns = method.throwTags()
                val returns = if (method.isConstructor())
                    emptyList()
                else
                    method.returnTag(method.returnType)

                if(params.size + returns.size + throwns.size > 0) {
                    div("params") {
                        table("params-table") {
                            rowGroup(params, title = "Parameters", colspan = 2) {
                                td {text(it.first)}
                                td {text(it.second)}
                            }
                            rowGroup(returns, title = "Returns", colspan = 2) {
                                td {text(it.first)}
                                td {text(it.second)}
                            }
                            rowGroup(throwns, title = "Throws", colspan = 2) {
                                td {text(it.first)}
                                td {text(it.second)}
                            }
                        }
                    }
                }
            }
        }
    }

    private fun executables(title: String, filter: (Element) -> Boolean) = html {
        val methods = element.children(filter)
        if (methods.isNotEmpty()) {
            h2(title)
            methods.forEach {
                compose {
                    method(it as ExecutableElement)
                }
            }
        }
    }

    private fun constructors() = executables("Constructors", Element::isVisibleConstructor)
    private fun methods() = executables("Public Methods", Element::isVisibleMethod)

    fun generateHtml() = html {
        div("package-name") { text("Package: $packageName") }
        h1(simpleName)
        pre(signature(), "class-signature")

        compose {
            description() +
                    fields() +
                    constructors() +
                    methods() +
                    nestedClasses()
        }
    }

    private fun relativePath(from: String, to: String) =
        Paths.get(from).parent.relativize(Paths.get(to)).toString()
}

private fun String.prefixIfNotEmpty(prefix: String): String
        = if (isNotEmpty()) prefix + this else this
