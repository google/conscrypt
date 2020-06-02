/*
 * Copyright (C) 2020 The Android Open Source Project
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

package org.conscrypt;

import javax.crypto.ShortBufferException;

/**
 * This class basically does the same thing the ShortBufferException class does
 * except not filling in stack trace in the exception to save CPU-time for it
 * in an environment where this can be thrown many times. e.g. OpenJDK 8.
 */
@Internal
final class ShortBufferWithoutStackTraceException extends ShortBufferException {
    private static final long serialVersionUID = 676150236007842683L;

    public ShortBufferWithoutStackTraceException() {
        super();
    }

    public ShortBufferWithoutStackTraceException(String msg) {
        super(msg);
    }

    @Override public Throwable fillInStackTrace() {
        return this;
    }
}
