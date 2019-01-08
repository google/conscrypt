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

package org.conscrypt.testing;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Locale;

/**
 * A PrintStream that throws away its output.
 */
public final class NullPrintStream extends PrintStream {
    public NullPrintStream() {
        // super class complains if argument is null
        super((OutputStream) new ByteArrayOutputStream());
    }

    @Override
    public boolean checkError() {
        return false;
    }

    @Override
    protected void clearError() {}

    @Override
    public void close() {}

    @Override
    public void flush() {}

    @Override
    public PrintStream format(String format, Object... args) {
        return this;
    }

    @Override
    public PrintStream format(Locale l, String format, Object... args) {
        return this;
    }

    @Override
    public PrintStream printf(String format, Object... args) {
        return this;
    }

    @Override
    public PrintStream printf(Locale l, String format, Object... args) {
        return this;
    }

    @Override
    public void print(char[] charArray) {}

    @Override
    public void print(char ch) {}

    @Override
    public void print(double dnum) {}

    @Override
    public void print(float fnum) {}

    @Override
    public void print(int inum) {}

    @Override
    public void print(long lnum) {}

    @Override
    public void print(Object obj) {}

    @Override
    public void print(String str) {}

    @Override
    public void print(boolean bool) {}

    @Override
    public void println() {}

    @Override
    public void println(char[] charArray) {}

    @Override
    public void println(char ch) {}

    @Override
    public void println(double dnum) {}

    @Override
    public void println(float fnum) {}

    @Override
    public void println(int inum) {}

    @Override
    public void println(long lnum) {}

    @Override
    public void println(Object obj) {}

    @Override
    public void println(String str) {}

    @Override
    public void println(boolean bool) {}

    @Override
    protected void setError() {}

    @Override
    public void write(byte[] buffer, int offset, int length) {}

    @Override
    public void write(int oneByte) {}

    @Override
    public PrintStream append(char c) {
        return this;
    }

    @Override
    public PrintStream append(CharSequence csq) {
        return this;
    }

    @Override
    public PrintStream append(CharSequence csq, int start, int end) {
        return this;
    }
}
