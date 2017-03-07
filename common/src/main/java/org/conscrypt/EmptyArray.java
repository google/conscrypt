/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Copied from libcore.util.EmptyArray

package org.conscrypt;

final class EmptyArray {
    private EmptyArray() {}

    static final boolean[] BOOLEAN = new boolean[0];
    static final byte[] BYTE = new byte[0];
    static final char[] CHAR = new char[0];
    static final double[] DOUBLE = new double[0];
    static final int[] INT = new int[0];

    static final Class<?>[] CLASS = new Class<?>[ 0 ];
    static final Object[] OBJECT = new Object[0];
    static final String[] STRING = new String[0];
    static final Throwable[] THROWABLE = new Throwable[0];
    static final StackTraceElement[] STACK_TRACE_ELEMENT = new StackTraceElement[0];
}
