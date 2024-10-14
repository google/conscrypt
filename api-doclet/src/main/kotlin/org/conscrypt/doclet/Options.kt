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

import jdk.javadoc.doclet.Doclet.Option
import java.util.function.Consumer

abstract class BaseOption(private val name: String) : Option {
    override  fun getKind() = Option.Kind.STANDARD
    override fun getNames(): List<String> = listOf(name)
}

class StringOption(name: String,
                   private val parameters: String,
                   private val description: String,
                   private val action: Consumer<String>
) : BaseOption(name) {
    override fun getArgumentCount() = 1
    override fun getDescription(): String = description
    override fun getParameters(): String = parameters

    override fun process(option: String, arguments: MutableList<String>): Boolean {
        action.accept(arguments[0])
        return true
    }
}

class BooleanOption(name: String,
                    private val description: String,
                    private val action: Runnable): BaseOption(name) {
    override fun getArgumentCount() = 0
    override fun getDescription(): String = description
    override fun getParameters(): String = ""

    override fun process(option: String, arguments: MutableList<String>): Boolean {
        action.run()
        return true
    }
}
