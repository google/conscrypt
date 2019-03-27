/*
 * Copyright 2014 The Android Open Source Project
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import org.conscrypt.NativeLibraryLoader.LoadResult;

/**
 * Helper to initialize the JNI libraries. This version runs when compiled as part of a host OpenJDK
 * build.
 */
final class NativeCryptoJni {
    private static final String STATIC_LIB_NAME = "conscrypt";
    private static final String DYNAMIC_LIB_NAME_PREFIX = "conscrypt_openjdk_jni";

    /**
     * Attempts to load the shared JNI library. First try loading the platform-specific library
     * name (e.g. conscrypt_openjdk_jni-linux-x86_64). If that doesn't work, try to load the
     * library via just the prefix (e.g. conscrypt_openjdk_jni).  If not found, try the static
     * library name.
     *
     * The non-suffixed dynamic library name is used by the Android build system, which builds
     * the appropriate library for the system it's being run on under that name.
     *
     * The static library name is needed in order to support Java 8 static linking
     * (http://openjdk.java.net/jeps/178), where the library name is used to invoke a
     * library-specific load method (i.e. {@code JNI_OnLoad_conscrypt}).
     *
     * @throws UnsatisfiedLinkError if the library failed to load.
     */
    static void init() throws UnsatisfiedLinkError {
        List<LoadResult> results = new ArrayList<LoadResult>();
        if (!NativeLibraryLoader.loadFirstAvailable(classLoader(), results,
                platformLibName(), DYNAMIC_LIB_NAME_PREFIX, STATIC_LIB_NAME)) {
            logResults(results);
            throwBestError(results);
        }
    }

    private NativeCryptoJni() {}

    private static void logResults(List<LoadResult> results) {
        for (LoadResult result : results) {
            result.log();
        }
    }

    private static void throwBestError(List<LoadResult> results) {
        Collections.sort(results, ErrorComparator.INSTANCE);

        Throwable bestError = results.get(0).error;
        for (LoadResult result : results.subList(1, results.size())) {
            // Suppress all of the other errors, so that they're available to the caller if
            // desired.
            bestError.addSuppressed(result.error);
        }

        if (bestError instanceof Error) {
            throw (Error) bestError;
        }

        throw (Error) new UnsatisfiedLinkError(bestError.getMessage()).initCause(bestError);
    }

    private static ClassLoader classLoader() {
        return NativeCrypto.class.getClassLoader();
    }

    private static String platformLibName() {
        return DYNAMIC_LIB_NAME_PREFIX + "-" + osName() + '-' + archName();
    }

    private static String osName() {
        return HostProperties.OS.getFileComponent();
    }

    private static String archName() {
        return HostProperties.ARCH.getFileComponent();
    }

    /**
     * Sorts the errors in a list in descending order of value. After a list is sorted,
     * the first element is the most important error.
     */
    private static final class ErrorComparator implements Comparator<LoadResult> {
        static final ErrorComparator INSTANCE = new ErrorComparator();

        @Override
        public int compare(LoadResult o1, LoadResult o2) {
            Throwable e1 = o1.error;
            Throwable e2 = o2.error;

            // First, sort by error type.
            int value1 = e1 instanceof UnsatisfiedLinkError ? 1 : 0;
            int value2 = e2 instanceof UnsatisfiedLinkError ? 1 : 0;
            if (value1 != value2) {
                // Order so that the UnsatisfiedLinkError is first.
                return value2 - value1;
            }

            // Both are either link errors or not. Compare the message. Treat messages in
            // the form "no <libName> in java.library.path" as lower value, since there may be
            // a more interesting message for a library that was found.
            String m1 = e1.getMessage();
            String m2 = e2.getMessage();
            value1 = m1 != null && m1.contains("java.library.path") ? 0 : 1;
            value2 = m2 != null && m2.contains("java.library.path") ? 0 : 1;
            return value2 - value1;
        }
    }
}
