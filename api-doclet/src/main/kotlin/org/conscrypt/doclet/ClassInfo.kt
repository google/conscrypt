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
import javax.lang.model.element.ExecutableElement
import javax.lang.model.element.TypeElement


data class ClassInfo(val element: TypeElement) : Comparable<ClassInfo> {
    val simpleName = element.simpleName.toString()
    val qualifiedName = element.qualifiedName.toString()
    val packageName = FilterDoclet.elementUtils.getPackageOf(element).qualifiedName.toString()
    val fileName = qualifiedName.replace('.', '/') + ".html"

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
                div("member") {
                    h4(cls.simpleName.toString())
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
        pre(element.signature(), "class-signature")

        compose {
            description() +
                    fields() +
                    constructors() +
                    methods() +
                    nestedClasses()
        }
    }
}

