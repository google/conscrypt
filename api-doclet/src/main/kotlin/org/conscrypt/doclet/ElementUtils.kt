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

import com.sun.source.doctree.UnknownBlockTagTree
import javax.lang.model.element.Element
import javax.lang.model.element.ElementKind
import javax.lang.model.element.ExecutableElement
import javax.lang.model.element.Modifier
import javax.lang.model.element.TypeElement
import javax.lang.model.element.VariableElement
import javax.lang.model.type.TypeMirror

fun Element.isType() = isClass() || isInterface() || isEnum()
fun Element.isClass() = this is TypeElement && kind == ElementKind.CLASS
fun Element.isEnum() = this is TypeElement && kind == ElementKind.ENUM
fun Element.isInterface() = this is TypeElement && kind == ElementKind.INTERFACE
fun Element.isExecutable() = this is ExecutableElement
fun Element.isField() = this is VariableElement

fun Element.isVisibleType() = isType() && isVisible()
fun Element.isVisibleMethod() = isExecutable() && isVisible() && kind == ElementKind.METHOD
fun Element.isVisibleConstructor() = isExecutable() && isVisible() && kind == ElementKind.CONSTRUCTOR
fun Element.isVisibleField() = isField() && isVisible()
fun Element.isPublic() = modifiers.contains(Modifier.PUBLIC)
fun Element.isPrivate() = !isPublic() // Ignore protected for now :)
fun Element.isVisible() = !isHidden()
fun Element.isHidden() = isPrivate() || isFiltered() || parentIsHidden()
fun Element.children(filterFunction: (Element) -> Boolean) = enclosedElements
    .filter(filterFunction)
    .toList()

fun Element.parentIsHidden(): Boolean
        = if (enclosingElement.isType()) enclosingElement.isHidden() else false

fun Element.hasAnnotation(annotationName: String): Boolean = annotationMirrors
    .map { it.annotationType.toString() }
    .any { it == annotationName }

fun Element.hasJavadocTag(tagName: String): Boolean {
    return docTree()?.blockTags?.any {
        tag -> tag is UnknownBlockTagTree && tag.tagName == tagName
    } ?: false
}

fun ExecutableElement.isConstructor() = kind == ElementKind.CONSTRUCTOR
fun ExecutableElement.name() = if (isConstructor()) parentName() else simpleName.toString()
fun ExecutableElement.parentName() = enclosingElement.simpleName.toString()

fun ExecutableElement.methodSignature(): String {
    val modifiers = modifiers.joinToString(" ")
    val returnType = if (isConstructor()) "" else "${formatType(returnType)} "

    val typeParams = typeParameters.takeIf { it.isNotEmpty() }
        ?.joinToString(separator = ", ", prefix = "<", postfix = ">") {
            it.asType().toString() } ?: ""

    val parameters = parameters.joinToString(", ") { param ->
        "${formatType(param.asType())} ${param.simpleName}"
    }

    val exceptions = thrownTypes
        .joinToString(", ")
        .prefixIfNotEmpty(" throws ")
    return "$modifiers $typeParams$returnType${name()}($parameters)$exceptions"
}

fun formatType(typeMirror: TypeMirror): String {
    return if (typeMirror.kind.isPrimitive) {
        typeMirror.toString()
    } else {
        typeMirror.toString()
            .split('.')
            .last()
    }
}

fun TypeElement.baseFileName(): String =
    if (enclosingElement.isType())
        (enclosingElement as TypeElement).baseFileName() + "." + simpleName
    else
        qualifiedName.toString().replace('.', '/')

private fun String.prefixIfNotEmpty(prefix: String): String
        = if (isNotEmpty()) prefix + this else this
