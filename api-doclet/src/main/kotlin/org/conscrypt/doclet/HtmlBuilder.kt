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

private typealias Block = HtmlBuilder.() -> Unit
private fun Block.render(): String = HtmlBuilder().apply(this).toString()

class HtmlBuilder {
    private val content = StringBuilder()
    override fun toString() = content.toString()

    fun text(fragment: () -> String): StringBuilder = text(fragment())
    fun text(text: String): StringBuilder = content.append(text)
    fun compose(fragment: () -> String) {
        content.append(fragment())
    }

    fun body(title: String, stylesheet: String, content: Block) {
        text("""
             <!DOCTYPE html>
             <html><head>
               <link rel="stylesheet" type="text/css" href="$stylesheet">
               <meta charset="UTF-8">
               <title>$title</title>
             </head>
             <body>""".trimIndent() +
             content.render() +
             "</body></html>")
    }

    private fun tagBlock(
        tag: String, cssClass: String? = null, colspan: Int? = null, id: String? = null, block: Block)
    {
        content.append("\n<$tag")
        cssClass?.let { content.append(""" class="$it"""") }
        colspan?.let { content.append(""" colspan="$it"""") }
        id?.let { content.append(""" id="$it"""") }
        content.append(">")
        content.append(block.render())
        content.append("</$tag>\n")
    }

    fun div(cssClass: String? = null, id: String? = null, block: Block) =
        tagBlock("div", cssClass = cssClass, colspan = null, id, block)
    fun ul(cssClass: String? = null, id: String? = null, block: Block) =
        tagBlock("ul", cssClass = cssClass, colspan = null, id, block)
    fun ol(cssClass: String? = null, id: String? = null, block: Block) =
        tagBlock("ol", cssClass = cssClass, colspan = null, id, block)
    fun table(cssClass: String? = null, id: String? = null, block: Block) =
        tagBlock("table", cssClass = cssClass, colspan = null, id, block)
    fun tr(cssClass: String? = null, id: String? = null, block: Block) =
        tagBlock("tr", cssClass = cssClass, colspan = null, id, block)
    fun th(cssClass: String? = null, colspan: Int? = null, id: String? = null, block: Block) =
        tagBlock("th", cssClass, colspan, id, block)
    fun td(cssClass: String? = null, colspan: Int? = null, id: String? = null, block: Block) =
        tagBlock("td", cssClass, colspan, id, block)

    private fun tagValue(tag: String, value: String, cssClass: String? = null) {
        val classText = cssClass?.let { """ class="$it"""" } ?: ""
        content.append("<$tag$classText>$value</$tag>\n")
    }

    fun h1(heading: String, cssClass: String? = null) = tagValue("h1", heading, cssClass)
    fun h1(cssClass: String? = null, block: Block) = h1(block.render(), cssClass)
    fun h2(heading: String, cssClass: String? = null) = tagValue("h2", heading, cssClass)
    fun h2(cssClass: String? = null, block: Block) = h2(block.render(), cssClass)
    fun h3(heading: String, cssClass: String? = null) = tagValue("h3", heading, cssClass)
    fun h3(cssClass: String? = null, block: Block) = h2(block.render(), cssClass)
    fun h4(heading: String, cssClass: String? = null) = tagValue("h4", heading, cssClass)
    fun h4(cssClass: String? = null, block: Block) = h2(block.render(), cssClass)
    fun h5(heading: String, cssClass: String? = null) = tagValue("h5", heading, cssClass)
    fun h5(cssClass: String? = null, block: Block) = h2(block.render(), cssClass)

    fun p(text: String, cssClass: String? = null) = tagValue("p", text, cssClass)
    fun p(cssClass: String? = null, block: Block) = p(block.render(), cssClass)
    fun b(text: String, cssClass: String? = null) = tagValue("b", text, cssClass)
    fun b(cssClass: String? = null, block: Block) = b(block.render(), cssClass)
    fun pre(text: String, cssClass: String? = null) = tagValue("pre", text, cssClass)
    fun pre(cssClass: String? = null, block: Block) = pre(block.render(), cssClass)
    fun code(text: String, cssClass: String? = null) = tagValue("code", text, cssClass)
    fun code(cssClass: String? = null, block: Block) = code(block.render(), cssClass)
    fun strong(text: String, cssClass: String? = null) = tagValue("strong", text, cssClass)
    fun strong(cssClass: String? = null, block: Block) = strong(block.render(), cssClass)

    fun br() = content.append("<br/>\n")
    fun a(href: String, label: String) {
        content.append("""<a href="$href">$label</a>""")
    }
    fun a(href: String, block: Block) = a(href, block.render())
    fun a(href: String) = a(href, href)

    fun li(text: String, cssClass: String? = null) = tagValue("li", text, cssClass)
    fun li(cssClass: String? = null, block: Block) = li(block.render(), cssClass)

    fun <T> items(collection: Iterable<T>, cssClass: String? = null,
                  transform: HtmlBuilder.(T) -> Unit = { text(it.toString()) }) {
        collection.forEach {
            li(cssClass = cssClass) { transform(it) }
        }
    }

    fun <T> row(item: T, rowClass: String? = null, cellClass: String? = null,
                span: Int? = null,
                transform: HtmlBuilder.(T) -> Unit = { td {it.toString() } }) {
        tr(cssClass = rowClass) {
            transform(item)
        }
    }
    fun <T> rowGroup(rows: Collection<T>, title: String? = null, rowClass: String? = null, cellClass: String? = null,
                 colspan: Int? = null,
                transform: HtmlBuilder.(T) -> Unit) {
        if(rows.isNotEmpty()) {
            title?.let {
                tr {
                    th(colspan = colspan) {
                        strong(it)
                    }
                }
            }
            rows.forEach {
                tr {
                    transform(it)
                }
            }
        }
    }
}

fun html(block: Block) = block.render()

fun exampleSubfunction() = html {
    h1("Headings from exampleSubfunction")
    listOf("one", "two", "three").forEach {
        h1(it)
    }
}

fun example() = html {
    val fruits = listOf("Apple", "Banana", "Cherry")
    body(
        stylesheet = "path/to/stylesheet.css",
        title = "Page Title"
    ) {
        div(cssClass = "example-class") {
            text {
                "This is a div"
            }
            h1 {
                text("Heading1a")
            }
            h2 {
                a("www.google.com", "Heading with a link")
            }
            h3("Heading with CSS class", "my-class")
            h2("h2", "my-class")
            p("Hello world")
            compose {
                exampleSubfunction()
            }
            br()
            a("www.google.com") {
                text("a link with ")
                b("bold")
                text(" text.")
            }

        }
        h1("Lists")

        h2("Unordered list:")
        ul {
            li("First item")
            li("Second item")
            li {
                text { "Complex item with " }
                b { text { "bold text" } }
            }
            ul {
                li("First nested item")
                li("Second nested item")
            }
        }

        h2("Ordered list:")
        ol {
            li("First item")
            li("Second item")
            li {
                text { "Item with a " }
                a(href = "https://example.com") { text { "link" } }
            }
        }
        h2("List item iteration")
        ul {
            // Default
            items(fruits)
            // Text transform
            items(fruits) {
                text("I like ${it}.")
            }
            // HTML transform with a CSS class
            items(fruits, "myclass") {
                a("www.google.com") {
                    b(it)
                }
            }
        }
        ol("ol-class") {
            items((1..5).asIterable()) {
                text("Item $it")
            }
        }
    }
    val data1 = listOf(1, 2)
    val data2 = "3" to "4"
    val data3 = listOf(
        "tag1" to "Some value",
        "tag2" to "Next Value",
        "tag3" to "Another value"
    )

    table("table-class") {
        tr {
            th {
                text("First column")
            }
            th {
                text("Second column")

            }
        }
        tr("tr-class") {
            td("td-class") {
                text("Data 1")
            }
            td(colspan = 2, id = "foo") {
                    text("Data 2")
            }
        }
        tr {
            td() {
                text("Data 3")
            }
        }
        row(data1, "c1") {
            a(href="www.google.com") { text("$it") }
        }
        row(data2) { p:Pair<String, String> ->
            td {
                text(p.first)
            }
            td {
                text(p.second)
            }

        }
        rowGroup(data3, title = "Row Group", colspan=2) { p: Pair<String, String> ->
            td {
                text(p.first)
            }
            td {
                text(p.second)
            }
        }
    }
}

fun main() {
    example().let(::println)
}
