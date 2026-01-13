/*
 * Copyright 2017 The Android Open Source Project
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

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Shim for Java 7-only google3 builds that does nothing.
 */
final class Java8PlatformUtil {
    static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        throw new AssertionError("Java 7 builds should never call this class.");
    }

    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        throw new AssertionError("Java 7 builds should never call this class.");
    }

    static void setSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        throw new AssertionError("Java 7 builds should never call this class.");
    }
    static void getSSLParameters(
            SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        throw new AssertionError("Java 7 builds should never call this class.");
    }

    static SSLEngine wrapEngine(ConscryptEngine engine) {
        throw new AssertionError("Java 7 builds should never call this class.");
    }

    static SSLEngine unwrapEngine(SSLEngine engine) {
        throw new AssertionError("Java 7 builds should never call this class.");
    }

    static SSLSocket unwrapSocket(SSLSocket socket) {
        throw new AssertionError("Java 7 builds should never call this class.");
    }

    static SSLSession wrapSSLSession(ConscryptSession sslSession) {
        throw new AssertionError("Java 7 builds should never call this class.");
    }

    private Java8PlatformUtil() {}
}
