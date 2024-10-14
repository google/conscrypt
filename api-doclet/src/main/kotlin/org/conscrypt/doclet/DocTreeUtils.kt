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

import org.conscrypt.doclet.FilterDoclet.Companion.baseUrl
import com.sun.source.doctree.DocCommentTree
import com.sun.source.doctree.DocTree
import com.sun.source.doctree.EndElementTree
import com.sun.source.doctree.LinkTree
import com.sun.source.doctree.LiteralTree
import com.sun.source.doctree.ParamTree
import com.sun.source.doctree.ReturnTree
import com.sun.source.doctree.SeeTree
import com.sun.source.doctree.StartElementTree
import com.sun.source.doctree.TextTree
import com.sun.source.doctree.ThrowsTree
import org.conscrypt.doclet.FilterDoclet.Companion.classIndex
import org.conscrypt.doclet.FilterDoclet.Companion.docTrees
import javax.lang.model.element.Element
import javax.lang.model.type.TypeMirror

fun renderDocTreeList(treeList: List<DocTree>):String =
    treeList.joinToString("\n", transform = ::renderDocTree)

fun renderDocTree(docTree: DocTree): String = when (docTree) {
    is TextTree -> docTree.body
    is LinkTree -> {
        val reference = docTree.reference.toString()
        val label = if (docTree.label.isEmpty()) {
            reference
        } else {
            renderDocTreeList(docTree.label)
        }
        createLink(reference, label)
    }
    is StartElementTree, is EndElementTree -> docTree.toString()
    is LiteralTree -> "<code>${docTree.body}</code>"
    else -> error("[${docTree.javaClass} / ${docTree.kind} --- ${docTree}]")
}

fun createLink(reference: String, label: String) = html {
    val parts = reference.split('#')
    val className = parts[0]
    val anchor = if (parts.size > 1) "#${parts[1]}" else ""
    val classInfo = classIndex.find(className)
    val href = if (classInfo != null)
        "${classInfo.simpleName}.html$anchor"
    else
        "$baseUrl${className.replace('.', '/')}.html$anchor"

    a(href, label)
}

fun renderBlockTagList(tagList: List<DocTree>): String =
    tagList.joinToString("\n", transform = ::renderBlockTag)

fun renderBlockTag(tag: DocTree) = when (tag) {
    is ParamTree, is ReturnTree, is ThrowsTree -> error("Unexpected block tag: $tag")
    is SeeTree -> html {
        br()
        p {
            strong("See: ")
            text(renderDocTreeList(tag.reference))
        }
    }
    else -> tag.toString()
}

inline fun <reified T> Element.filterTags() =
    docTree()?.blockTags?.filterIsInstance<T>() ?: emptyList()

fun Element.paramTags() = filterTags<ParamTree>()
    .map { it.name.toString() to renderDocTreeList(it.description) }
    .toList()


fun Element.returnTag(returnType: TypeMirror): List<Pair<String, String>> {
    val list = mutableListOf<Pair<String, String>>()
    val descriptions  = filterTags<ReturnTree>()
        .map {  renderDocTreeList(it.description) }
        .singleOrNull()

    if (descriptions != null) {
        list.add(returnType.toString() to descriptions)
    }
    return list
}

fun Element.throwTags() = filterTags<ThrowsTree>()
    .map { it.exceptionName.toString() to renderDocTreeList(it.description) }
    .toList()

fun Element.docTree(): DocCommentTree? = docTrees.getDocCommentTree(this)
fun Element.commentTree() = docTree()?.let { renderDocTreeList(it.fullBody) } ?: ""
fun Element.tagTree() = docTree()?.let { renderBlockTagList(it.blockTags) } ?: ""
fun Element.commentsAndTagTrees() = commentTree() + tagTree()
